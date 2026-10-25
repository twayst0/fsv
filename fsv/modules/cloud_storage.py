"""
FSV Module — Cloud Storage Exposure & Orphaned Buckets
──────────────────────────────────────────────────────
Websites reference object-storage buckets for images, downloads, fonts and — too
often — JavaScript. Two failure modes, both routinely missed:

  1. PUBLIC LISTING   the bucket lets anyone list (and then fetch) every object.
  2. ORPHANED BUCKET  the page still references a bucket that no longer exists.
                      Bucket names are global; anyone can create it and serve
                      whatever they like to every visitor. If it is used as a
                      <script> source, that is full control of the page.

Detection only: one request per bucket, `max-keys=1` / `maxresults=1` — we ask
whether listing is allowed, we never enumerate or download objects, and we never
create anything. Contacts hosts other than the target (module is `external`).
"""

from __future__ import annotations
import re

from fsv.core import dnsutil
from fsv.core.content import find_bucket_refs, is_html, load_scripts, script_refs
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

MAX_BUCKETS = 25

_NAMES = {"s3": "Amazon S3", "gcs": "Google Cloud Storage", "azure": "Azure Blob Storage"}


class CloudStorageScanner(BaseScanner):
    name        = "cloud_storage"
    category    = "passive"
    scope       = "url"
    external    = True
    description = "Public listing and orphaned (non-existent, claimable) cloud-storage buckets referenced by pages and scripts"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._seen_scripts: set[str] = set()
        self._checked: set[tuple[str, str, str | None]] = set()

    async def scan(self, url: str) -> list[Finding]:
        r = await self.http.request(url)
        if not r.ok or r.status != 200 or not is_html(r.headers, r.body):
            return []

        # where does each bucket appear? script/style sources are the dangerous ones
        script_urls, inline = script_refs(r.body, url)
        refs: dict[tuple, str] = {}
        as_script = {k for u in script_urls for k in find_bucket_refs(u)}
        for k in find_bucket_refs(r.body):
            refs.setdefault(k, url)
        scripts, _ = await load_scripts(self.http, url, r.body, first_party_only=True,
                                        skip=self._seen_scripts)
        for sc in scripts:
            for k in find_bucket_refs(sc.body[:1_000_000]):
                refs.setdefault(k, sc.url)

        out: list[Finding] = []
        for key, where in list(refs.items())[:MAX_BUCKETS]:
            if key in self._checked:
                continue
            self._checked.add(key)
            f = await self._check(key, where, used_as_script=key in as_script)
            if f:
                out.append(f)
        return out

    # ── per-provider probes ──────────────────────────────────────────────

    async def _check(self, key, where: str, used_as_script: bool) -> Finding | None:
        provider, name, container = key
        if provider == "s3":
            r = await self.http.request(f"https://{name}.s3.amazonaws.com/?max-keys=1")
            return self._classify_s3_like(provider, name, r, where, used_as_script,
                                          listing="<ListBucketResult", missing="NoSuchBucket",
                                          pretty=f"s3://{name}")
        if provider == "gcs":
            r = await self.http.request(f"https://storage.googleapis.com/{name}?max-keys=1")
            return self._classify_s3_like(provider, name, r, where, used_as_script,
                                          listing="<ListBucketResult", missing="NoSuchBucket",
                                          pretty=f"gs://{name}")
        if provider == "azure":
            return await self._check_azure(name, container, where, used_as_script)
        return None

    def _classify_s3_like(self, provider, name, r, where, used_as_script, *, listing, missing, pretty):
        if not r.ok:
            return None
        if r.status == 200 and listing in r.body:
            return self._public(provider, name, pretty, where)
        if r.status == 404 and missing in r.body:
            return self._orphaned(provider, name, pretty, where, used_as_script)
        return None            # 403 AccessDenied = exists and private → fine

    async def _check_azure(self, account, container, where, used_as_script):
        host = f"{account}.blob.core.windows.net"
        d = await dnsutil.aresolve(host, "A", 3.0)
        if d.nxdomain:
            return self._orphaned("azure", account, f"{host}", where, used_as_script,
                                  how="storage account name does not resolve (NXDOMAIN)")
        if container:
            r = await self.http.request(
                f"https://{host}/{container}?restype=container&comp=list&maxresults=1")
            if r.ok and r.status == 200 and "<EnumerationResults" in r.body:
                return self._public("azure", account, f"{host}/{container}", where)
        return None

    # ── findings ─────────────────────────────────────────────────────────

    def _public(self, provider, name, pretty, where) -> Finding:
        return Finding(
            title=f"Publicly Listable Cloud Storage Bucket: {pretty}",
            severity=Severity.HIGH, confidence=Confidence.CERTAIN, url=where, module=self.name,
            description=(
                f"The {_NAMES[provider]} bucket `{name}`, referenced by the site, allows anyone to "
                "list its contents without credentials — and therefore to discover and download "
                "every object in it. Buckets holding uploads, backups, logs or exports are a "
                "frequent source of large data exposures."),
            evidence=f"Anonymous listing request returned a bucket listing for {pretty}\n(referenced from {where})",
            recommendation=(
                "Turn on the provider's account-level “block public access” setting, remove "
                "public-list ACLs/policies, and serve public assets through a CDN with an origin "
                "access control. Review what was exposed and for how long (access logs)."),
            references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
            cwe="CWE-200", extra={"provider": provider, "bucket": name, "kind": "public-listing"})

    def _orphaned(self, provider, name, pretty, where, used_as_script,
                  how="bucket does not exist (NoSuchBucket)") -> Finding:
        sev = Severity.CRITICAL if used_as_script else Severity.HIGH
        return Finding(
            title=f"Orphaned Cloud Storage Bucket Referenced: {pretty}",
            severity=sev, confidence=Confidence.CERTAIN, url=where, module=self.name,
            description=(
                f"The site still points at {_NAMES[provider]} `{name}`, but {how}. Bucket and "
                "account names are global, so anyone can now create it and serve their own files "
                "from the address your pages trust."
                + (" It is loaded as a <script>/<link> source: whoever claims the name controls "
                   "code running on your pages — a complete cross-site-scripting compromise "
                   "(and a supply-chain attack) for every visitor." if used_as_script else
                   " Images and downloads could be swapped for malicious ones.")),
            evidence=f"{pretty}: {how}\n(referenced from {where})",
            recommendation=(
                "Remove or replace every reference to the missing bucket. If you want to keep the "
                "URL, re-create the bucket in YOUR account immediately (private, with a deny-all "
                "policy), then fix the references. Add Subresource Integrity and a strict CSP "
                "`script-src` so that a third-party host can't inject code."),
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
            cwe="CWE-829",
            extra={"provider": provider, "bucket": name, "kind": "orphaned",
                   "used_as_script": used_as_script})
