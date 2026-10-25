#!/usr/bin/env python3
"""
A deliberately vulnerable demo site for trying FSV safely.

    python examples/demo_site.py            # serves http://127.0.0.1:8961  (loopback only)
    fsv scan http://127.0.0.1:8961 --authorize

It contains, on purpose: a reflected-XSS search page, a session cookie without HttpOnly/Secure, an old
`Server:` banner, a script bundle with a (fake) hard-coded key and a source map, jQuery 3.3.1 from a CDN
URL, an image from an object-storage bucket that does not exist, and an open Spring-Actuator-style
endpoint. Every "secret" is fake and assembled at runtime. Never expose this to a network.

Note: FSV's `cloud_storage` module asks Amazon S3 whether the referenced bucket exists, so that one
check makes a real (read-only) request to AWS.
"""
from __future__ import annotations
import argparse
import asyncio
import json

from aiohttp import web

# fake credential, built from pieces so no secret-shaped literal sits in the repository
FAKE_STRIPE = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
SOURCE_MAP = json.dumps({"version": 3, "sources": ["webpack:///src/app.js"],
                         "sourcesContent": ["const x = 1; // original, un-minified source"]})

HOME = """<html><body><h1>Demo Shop</h1>
<a href="/search?q=shoes">search</a>
<script src="/static/app.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
<img src="https://fsv-demo-orphan-0f3a9c1d.s3.amazonaws.com/logo.png">
</body></html>"""


async def handle(request: web.Request) -> web.Response:
    p = request.path
    if p == "/":
        return web.Response(text=HOME, content_type="text/html",
                            headers={"Server": "Apache/2.2.15", "Set-Cookie": "SESSIONID=demo123; Path=/"})
    if p == "/search":                                        # reflected, unescaped on purpose
        return web.Response(text=f"<html>results for {request.query.get('q', '')}</html>",
                            content_type="text/html")
    if p == "/static/app.js":
        return web.Response(
            text=f"var k='{FAKE_STRIPE}';var api='https://api-staging.demo-shop.test';\n"
                 "//# sourceMappingURL=app.js.map", content_type="application/javascript")
    if p == "/static/app.js.map":
        return web.Response(text=SOURCE_MAP, content_type="application/json")
    if p == "/actuator/env":
        return web.Response(
            text='{"activeProfiles":[],"propertySources":[{"properties":{"db.password":{"value":"not-a-real-password"}}}]}',
            content_type="application/json")
    return web.Response(status=404, text="not found")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1].strip())
    ap.add_argument("--port", type=int, default=8961)
    port = ap.parse_args().port
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    print(f"demo site on http://127.0.0.1:{port}  (loopback only — Ctrl-C to stop)")
    web.run_app(app, host="127.0.0.1", port=port, print=None)


if __name__ == "__main__":
    main()
