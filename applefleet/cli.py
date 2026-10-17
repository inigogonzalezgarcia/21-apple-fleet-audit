"""Command line: `demo` builds everything from a fictional fleet, `export` reads your Jamf Pro (read-only),
`report` runs on your own export."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from . import report, simulate
from .checks import Config, load_vip, run_all
from .model import IOS, IPADOS, MAC, load, parse_ts


def run(export: Path, out: Path, title: str, c: Config, apns: str | None = None) -> dict:
    inv = load(export, apns)
    findings = run_all(inv, c)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(inv, findings, title, c), encoding="utf-8")
    report.write_findings(findings, out / "findings.csv")
    report.write_actions(inv, findings, out / "device_actions.csv")
    (out / "review.md").write_text(report.review_md(inv, findings, c), encoding="utf-8")
    return report.summary(inv, findings, c)


def _date(value: str) -> str:
    if not parse_ts(value):
        raise argparse.ArgumentTypeError(f"not a date (YYYY-MM-DD): {value}")
    return value


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="applefleet", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="generate a fictional fleet and build the outputs")
    d.add_argument("--out", type=Path, default=Path("output"))
    d.add_argument("--data", type=Path, default=Path("sample_data"))

    x = sub.add_parser("export", help="read-only export from the Jamf Pro API (secret in JAMF_CLIENT_SECRET)")
    x.add_argument("--url", required=True, help="https://yourorg.jamfcloud.com")
    x.add_argument("--client-id", default=os.environ.get("JAMF_CLIENT_ID"), help="API client ID (or JAMF_CLIENT_ID)")
    x.add_argument("--out", type=Path, default=Path("jamf_inventory.json"))
    x.add_argument("--apns-expires", type=_date, help="APNs push certificate expiry, YYYY-MM-DD (Jamf Pro shows it "
                                                      "in Settings > Global > Push certificates)")
    x.add_argument("--organisation", help="label for the report (default: the Jamf Pro host name)")
    x.add_argument("--page-size", type=int, default=100)

    r = sub.add_parser("report", help="build the outputs from your own export")
    r.add_argument("export", type=Path, help="JSON from `python -m applefleet export`")
    r.add_argument("--out", type=Path, default=Path("output"))
    r.add_argument("--title", default="Apple fleet audit")
    r.add_argument("--vip", type=Path, help="text file, one username per line: executives and board members")
    r.add_argument("--apns-expires", type=_date, help="APNs expiry, YYYY-MM-DD (overrides the export)")
    r.add_argument("--min-macos", default=Config().minimum[MAC])
    r.add_argument("--min-ios", default=Config().minimum[IOS])
    r.add_argument("--min-ipados", default=Config().minimum[IPADOS])
    r.add_argument("--oldest-macos", type=int, default=Config().oldest_major[MAC], help="oldest supported major")
    r.add_argument("--oldest-ios", type=int, default=Config().oldest_major[IOS])
    r.add_argument("--oldest-ipados", type=int, default=Config().oldest_major[IPADOS])
    r.add_argument("--token-warning-days", type=int, default=30)
    r.add_argument("--token-critical-days", type=int, default=14)
    r.add_argument("--stale-days", type=int, default=14)
    r.add_argument("--lost-days", type=int, default=45)
    a = p.parse_args(argv)

    if a.cmd == "export":
        from .jamf import JamfClient, export
        secret = os.environ.get("JAMF_CLIENT_SECRET")
        if not a.client_id or not secret:
            print("Set the API client ID (--client-id or JAMF_CLIENT_ID) and the secret in the JAMF_CLIENT_SECRET "
                  "environment variable.", file=sys.stderr)
            return 2
        org = a.organisation or urlparse(a.url).hostname or "jamf"
        print(f"Reading {a.url} (read-only) ...")
        data = export(JamfClient(a.url, a.client_id, secret, a.page_size), org, a.apns_expires)
        a.out.write_text(json.dumps(data, indent=1), encoding="utf-8")
        print(f"{len(data['devices'])} devices written to {a.out}"
              + ("" if a.apns_expires else ". APNs expiry not included: pass --apns-expires to `report`."))
        return 0

    if a.cmd == "demo":
        export_path, vip = simulate.write_demo(a.data)
        c = Config(vip=load_vip(vip))
        sm = run(export_path, a.out, "Apple fleet audit (demo data)", c)
    else:
        c = Config(token_warning_days=a.token_warning_days, token_critical_days=a.token_critical_days,
                   stale_days=a.stale_days, lost_days=a.lost_days,
                   minimum={MAC: a.min_macos, IOS: a.min_ios, IPADOS: a.min_ipados},
                   oldest_major={MAC: a.oldest_macos, IOS: a.oldest_ios, IPADOS: a.oldest_ipados},
                   vip=load_vip(a.vip) if a.vip else set())
        sm = run(a.export, a.out, a.title, c, a.apns_expires)
    apns = "APNs date not provided" if sm["apns_days"] is None else (
        f"APNs expired {-sm['apns_days']} days ago" if sm["apns_days"] < 0 else f"APNs in {sm['apns_days']} days")
    print(f"{sm['devices']} devices ({sm['macs']} Macs, {sm['iphones']} iPhones, {sm['ipads']} iPads) · "
          f"{sm['vip_devices']} VIP devices · {apns} · {sm['critical']} critical, {sm['warning']} warnings, "
          f"{sm['info']} clean-up. Outputs in {a.out}/")
    return 0
