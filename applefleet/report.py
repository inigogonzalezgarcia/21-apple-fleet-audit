"""Outputs: report.html, findings.csv, device_actions.csv (technician work list) and review.md (weekly review)."""
from __future__ import annotations

import csv
import html
from collections import Counter
from pathlib import Path

from .checks import (AREAS, CRITICAL, INFO, SEV_ORDER, WARNING, Config, Finding, area_status, device_actions,
                     os_status, token_calendar, token_status)
from .model import IOS, IPADOS, MAC, PLATFORMS, Inventory, version_tuple

e = html.escape


def write_findings(findings: list[Finding], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "area", "code", "device", "serial", "owner", "vip", "detail", "first_step"])
        for f in findings:
            w.writerow([f.severity, f.area, f.code, f.device, f.serial, f.owner, "yes" if f.vip else "",
                        f.detail, f.fix])


def write_actions(inv: Inventory, findings: list[Finding], path: Path) -> int:
    rows = device_actions(inv, findings)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["priority", "severity", "device", "serial", "platform", "model", "os_version", "owner", "vip",
                    "last_seen_days", "issues_count", "issues", "next_steps", "done"])
        for i, r in enumerate(rows, 1):
            w.writerow([i, r["severity"], r["device"], r["serial"], r["platform"], r["model"], r["os"], r["owner"],
                        "yes" if r["vip"] else "", r["last_seen_days"], r["count"], r["issues"], r["next_steps"], ""])
    return len(rows)


def summary(inv: Inventory, findings: list[Finding], c: Config) -> dict:
    sev = Counter(f.severity for f in findings)
    kinds = Counter(d.platform for d in inv.devices)
    apns = next((r for r in token_calendar(inv) if r["kind"] == "APNs"), None)
    return {"devices": len(inv.devices), "macs": kinds.get(MAC, 0), "iphones": kinds.get(IOS, 0),
            "ipads": kinds.get(IPADOS, 0), "vip_users": len(c.vip),
            "vip_devices": sum(1 for d in inv.devices if d.username.lower() in c.vip),
            "apns_days": apns["days"] if apns else None,
            "critical": sev.get(CRITICAL, 0), "warning": sev.get(WARNING, 0), "info": sev.get(INFO, 0)}


def version_distribution(inv: Inventory, c: Config) -> dict[str, list[tuple[str, int, str]]]:
    """Per platform: (version, devices, status), newest first. Unmanaged records are left out."""
    out = {}
    for p in PLATFORMS:
        cnt = Counter(d.os_version or "unknown" for d in inv.devices if d.platform == p and d.managed)
        out[p] = [(v, n, os_status(p, v if v != "unknown" else "", c))
                  for v, n in sorted(cnt.items(), key=lambda x: version_tuple(x[0]), reverse=True)]
    return out


def _days(days) -> str:
    if days is None:
        return "not provided"
    return f"expired {-days} d ago" if days < 0 else f"{days}"


def review_md(inv: Inventory, findings: list[Finding], c: Config) -> str:
    sm = summary(inv, findings, c)
    st = area_status(findings)
    lines = [f"# Apple fleet weekly review · {inv.organisation} · {inv.collected_at:%Y-%m-%d}", "",
             f"{sm['devices']} devices ({sm['macs']} Macs, {sm['iphones']} iPhones, {sm['ipads']} iPads) · "
             f"{sm['vip_devices']} VIP devices · {sm['critical']} critical, {sm['warning']} warnings, "
             f"{sm['info']} to tidy up.", "", "| Area | Status |", "|---|---|"]
    lines += [f"| {a} | {'OK' if st[a] == 'ok' else st[a].upper()} |" for a in AREAS]
    for sev, title in ((CRITICAL, "Act now"), (WARNING, "This week")):
        items = [f for f in findings if f.severity == sev]
        if items:
            lines += ["", f"## {title}", ""]
            lines += [f"- **{f.device}**{' · ' + f.owner if f.owner else ''}: {f.detail}  \n  Next step: {f.fix}"
                      for f in items]
    infos = [f for f in findings if f.severity == INFO]
    if infos:
        lines += ["", "## Clean-up", ""] + [f"- {f.device}: {f.detail}" for f in infos]
    lines += ["", "## Token calendar", "", "| Expires | Days left | Token | Name |", "|---|---|---|---|"]
    names = {"APNs": "APNs push certificate", "ADE": "ADE server token", "VPP": "Apps and Books (VPP) token"}
    for r in token_calendar(inv):
        when = f"{r['expires']:%Y-%m-%d}" if r["expires"] else "?"
        lines.append(f"| {when} | {_days(r['days'])} | {names.get(r['kind'], r['kind'])} | {r['name']} |")
    lines += ["", "Read-only export; nothing was changed in Jamf Pro. Device work list: `device_actions.csv`; "
              "full list: `findings.csv`.", ""]
    return "\n".join(lines)


CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;--bad:#f2685c;--info:#5aa9f0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:28px}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.area{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:10px 14px}
.area.critical{border-left-color:var(--bad)}.area.warning{border-left-color:var(--warn)}.area.info{border-left-color:var(--info)}
.area span{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}.cols h3{font-size:15px;margin:0 0 6px}
.cols h3 span{font-size:13px;font-weight:400}.cols .bar{min-width:40px}.cols td,.cols th{padding:6px 8px}.cols td:nth-child(3){width:35%}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--bad)}.warning{color:var(--warn)}.info{color:var(--info)}.ok{color:var(--ok)}
.area.critical,.area.warning,.area.info,.area.ok{color:inherit}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;min-width:120px}.bar i{display:block;height:100%;background:var(--ok)}
.bar i.warning{background:var(--warn)}.bar i.critical{background:var(--bad)}
.vip{font-size:11px;font-weight:700;letter-spacing:.04em;color:var(--info)}
td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);max-width:380px}footer{margin-top:40px;font-size:13px}
"""


def _pill(s: str) -> str:
    return f"<span class='pill {s}'>{'OK' if s == 'ok' else s.upper()}</span>"


def render_html(inv: Inventory, findings: list[Finding], title: str, c: Config) -> str:
    sm = summary(inv, findings, c)
    st = area_status(findings)
    tiles = "".join(f"<div class='tile'><span class='muted'>{label}</span><b{cls}>{val}</b></div>" for label, val, cls in (
        ("Devices", sm["devices"], ""), ("Macs", sm["macs"], ""), ("iPhones", sm["iphones"], ""),
        ("iPads", sm["ipads"], ""), ("Critical", sm["critical"], " class='critical'"),
        ("Warnings", sm["warning"], " class='warning'")))
    names = {"APNs": "APNs push certificate", "ADE": "ADE server token (ABM)", "VPP": "Apps and Books token (VPP)"}
    trows = ""
    for r in token_calendar(inv):
        s = token_status(r["days"], c)
        when = f"{r['expires']:%Y-%m-%d}" if r["expires"] else "?"
        label = "NOT PROVIDED" if r["days"] is None else ("EXPIRED" if r["days"] < 0 else None)
        pill = f"<span class='pill {s}'>{label}</span>" if label else _pill(s)
        trows += (f"<tr><td><b>{e(names.get(r['kind'], r['kind']))}</b></td><td>{e(r['name'])}</td><td>{when}</td>"
                  f"<td class='num'>{'' if r['days'] is None else r['days']}</td><td>{pill}</td></tr>")
    areas = "".join(f"<div class='area {st[a]}'><span>{e(a)}</span><b class='{st[a]}'>"
                    f"{'OK' if st[a] == 'ok' else st[a].capitalize()}</b></div>" for a in AREAS)
    dist = version_distribution(inv, c)
    cols = ""
    for p in PLATFORMS:
        rows = dist[p]
        total = sum(n for _, n, _ in rows) or 1
        body = "".join(f"<tr><td>{e(v)}</td><td class='num'>{n}</td><td><div class='bar'><i class='{s}' "
                       f"style='width:{100 * n / total:.0f}%'></i></div></td><td>{_pill(s)}</td></tr>"
                       for v, n, s in rows) or "<tr><td colspan=4>No devices.</td></tr>"
        cols += (f"<div><h3>{p} <span class='muted'>· minimum {e(c.minimum.get(p, '-'))} · unsupported below "
                 f"{c.oldest_major.get(p, '-')}</span></h3><table><thead><tr><th>Version</th><th class='num'>Devices"
                 f"</th><th></th><th>Status</th></tr></thead><tbody>{body}</tbody></table></div>")
    worst: dict[str, str] = {}
    per: Counter = Counter()
    for f in findings:
        if f.serial:
            per[f.serial] += 1
            if f.serial not in worst or SEV_ORDER[f.severity] < SEV_ORDER[worst[f.serial]]:
                worst[f.serial] = f.severity
    vip_rows = ""
    for d in sorted((d for d in inv.devices if d.username.lower() in c.vip),
                    key=lambda d: (SEV_ORDER.get(worst.get(d.serial, ""), 9), d.real_name, d.platform)):
        issues = "<br>".join(e(f.detail.replace(" (VIP)", "")) for f in findings if f.serial == d.serial) or \
            "<span class='muted'>Nothing to report.</span>"
        vip_rows += (f"<tr><td><b>{e(d.real_name or d.username)}</b><br><span class='muted'>{e(d.username)}</span></td>"
                     f"<td>{e(d.name)}<br><span class='muted'>{e(d.model)}</span></td><td>{e(d.os_version)}</td>"
                     f"<td>{issues}</td><td>{_pill(worst.get(d.serial, 'ok'))}</td></tr>")
    vip_block = ""
    if c.vip:
        empty = "<tr><td colspan=5>No device found for the VIP users.</td></tr>"
        vip_block = (f"<h2>VIP devices <span class='muted'>· {sm['vip_users']} users, findings raised one level"
                     f"</span></h2><div class='wrap'><table><thead><tr><th>User</th><th>Device</th><th>OS</th><th>Issues"
                     f"</th><th>Status</th></tr></thead><tbody>{vip_rows or empty}</tbody></table></div>")
    frows = "".join(
        f"<tr><td>{_pill(f.severity)}</td><td>{e(f.area)}</td><td><b>{e(f.device)}</b>"
        f"{' <span class=vip>VIP</span>' if f.vip else ''}<br>{e(f.detail.replace(' (VIP)', ''))}"
        f"{'<br><span class=muted>' + e(f.owner) + '</span>' if f.owner else ''}</td><td class='fix'>{e(f.fix)}</td></tr>"
        for f in findings)
    drows = ""
    for d in sorted(inv.devices, key=lambda d: (SEV_ORDER.get(worst.get(d.serial, ""), 9), d.platform, d.name.lower())):
        seen = "never" if d.last_seen is None else f"{(inv.collected_at - d.last_seen).days} d ago"
        free = "" if d.free_pct is None else f"{d.free_pct:.0f}%"
        s = worst.get(d.serial, "ok")
        vip = " <span class=vip>VIP</span>" if d.username.lower() in c.vip else ""
        drows += (f"<tr><td><b>{e(d.name)}</b>{vip}<br><span class='muted'>{e(d.serial)}</span></td>"
                  f"<td>{e(d.owner) or '<span class=muted>no user</span>'}</td><td>{e(d.model)}</td>"
                  f"<td>{e(d.os_version)}</td><td class='nw'>{seen}</td><td class='num'>{free}</td><td>{_pill(s)}</td></tr>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head><body><main>
<h1>{e(title)}</h1><p class="muted">{e(inv.organisation)} · {len(inv.ade_devices)} devices assigned in Apple Business Manager ·
collected {inv.collected_at:%Y-%m-%d %H:%M} UTC</p>
<div class="tiles">{tiles}</div>
<h2>Platform tokens</h2><div class="wrap"><table><thead><tr><th>Token</th><th>Name</th><th>Expires</th>
<th class="num">Days left</th><th>Status</th></tr></thead><tbody>{trows}</tbody></table></div>
<h2>Areas</h2><div class="areas">{areas}</div>
<h2>OS versions</h2><div class="cols">{cols}</div>
{vip_block}
<h2>Findings</h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Area</th><th>What</th><th>Next step</th></tr></thead>
<tbody>{frows or "<tr><td colspan=4>Nothing to report.</td></tr>"}</tbody></table></div>
<h2>Devices</h2><div class="wrap"><table><thead><tr><th>Device</th><th>Owner</th><th>Model</th><th>OS</th>
<th>Last seen</th><th class="num">Free</th><th>Status</th></tr></thead><tbody>{drows}</tbody></table></div>
<footer class="muted">Read-only check. What each finding means and the thresholds: README.md. Runbook: docs/weekly-review-runbook.md.</footer>
</main></body></html>"""
