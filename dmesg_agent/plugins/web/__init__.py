"""Command plugin: local web UI for offline uploads and job reports.

`dmesg-agent web` starts a stdlib HTTP server; removing/disabling this package
(the module name is ``web``) only removes the command — the CLI is unaffected.
"""

from __future__ import annotations

import argparse
import secrets

from .. import register
from .server import serve


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmesg-agent web",
        description="local web UI for offline dmesg/package diagnosis")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default: loopback only)")
    p.add_argument("--port", type=int, default=8790, help="listen port (0 = auto)")
    p.add_argument("--token", default=None,
                   help="access token; auto-generated when binding a non-loopback address")
    p.add_argument("--job-root", default=None,
                   help="job directory (default: $XDG_DATA_HOME/dmesg-agent/web/jobs)")
    browser = p.add_mutually_exclusive_group()
    browser.add_argument("--open", dest="open_browser", action="store_true",
                         default=True, help="open a browser after starting (default)")
    browser.add_argument("--no-open", dest="open_browser", action="store_false",
                         help="do not open a browser")
    return p


@register("command", order=10,
          description="local web UI: upload logs/packages, run analysis jobs, view reports")
def web(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    token = args.token
    if token is None and args.host not in ("127.0.0.1", "localhost", "::1"):
        token = secrets.token_urlsafe(24)
        print(f"generated access token: {token}")
        print("note: the web UI has no user accounts; keep the token private")
    return serve(args.host, args.port, token, args.job_root,
                 open_browser=args.open_browser)
