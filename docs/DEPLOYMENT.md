# Deploying FSV safely

FSV on your laptop (`fsv web`, loopback) needs no configuration. **Running it as a shared service changes the threat model**: "scan this URL"
becomes a request other people can make from your network. These controls exist for that case.

| Risk | Control | Setting |
|---|---|---|
| Anyone who can reach the port can start scans | shared secret on every API / WebSocket call | `FSV_TOKEN` |
| A web page in a user's browser drives the local API (CSRF) | same-origin / JSON-only writes, WebSocket origin check | always on |
| DNS rebinding reads the API as "same origin" | `Host` allow-list | `FSV_ALLOWED_HOSTS` |
| Scanner used to reach internal services (SSRF), incl. via redirects & DNS | never connect to cloud-metadata / link-local; optionally block loopback + RFC 1918 | always on · `FSV_BLOCK_PRIVATE=1` |
| Scanner used against sites the requester doesn't own | payload-sending scans need proof of control; passive scans stay open | `FSV_REQUIRE_VERIFICATION=1` |
| Resource exhaustion | concurrent scan cap, per-scan time limit, response size cap | `FSV_MAX_SCANS`, `--max-time` |
| Credentials in reports | secrets masked at the source | always on |

The Docker image defaults to `FSV_BLOCK_PRIVATE=1` and `FSV_REQUIRE_VERIFICATION=1`, runs as an unprivileged user, and `docker-compose.yml` adds
`read_only`, `cap_drop: ALL` and `no-new-privileges`. Put it behind a TLS reverse proxy; do not publish port 7474 to the Internet.

## Proving ownership
```bash
fsv verify example.com              # prints the DNS record / well-known file to publish
fsv verify example.com --check      # looks for it and records the result (valid 90 days)
```
Or via the API: `POST /api/verify {"host": …}` then `POST /api/verify/check`. The token is an HMAC of the domain under a per-installation secret, so a token
issued by one installation is useless for another. A DNS proof covers the domain and its subdomains; an HTTP proof covers exactly that host and is
not accepted through a redirect.

## Behind a proxy
`fsv scan … --proxy http://proxy:3128` (or `--proxy env` for `HTTPS_PROXY`/`HTTP_PROXY`, honouring `NO_PROXY`;
`proxy = "env"` in `fsv.toml`) sends every HTTP request through the proxy. DNS-based modules still use the local
resolver, and the TLS analyzer connects directly. A proxy is **refused when `FSV_BLOCK_PRIVATE` is set**: the proxy
resolves the target itself, so FSV's private-address guard could no longer see where requests go.

## Network egress
FSV needs outbound HTTP(S) to targets and DNS. Optional features add third parties: `--ct-logs` (crt.sh) and the `cloud_storage` / `takeover` modules
(object-storage endpoints, public DNS). `--no-external` / `external = false` removes the latter two.
The dashboard itself loads nothing from third parties (fonts are the system's). A webhook (`FSV_WEBHOOK_URL`, `--notify`) is the one
destination *you* add: it receives a short summary (grade, counts, the worst titles and their URLs — never evidence) for scans with
findings at or above `FSV_WEBHOOK_MIN_SEVERITY` (default `high`). It is operator-configured, never settable through the web API.

## Backup & retention
Everything lives in one SQLite file (`FSV_DB`). `fsv prune --keep N` limits history. Scan data can contain sensitive evidence — protect the volume.
