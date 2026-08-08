"""report_html.py — fancy standalone HTML report for odd-scsi-probe (v1.2.0).

Pure stdlib (html, datetime). No external dependencies.
"""
import html
from datetime import datetime

TOOL_VERSION = "odd-scsi-probe v1.3.0"

_RESULT_COLORS = {
    "SUPPORTED": ("#052e16", "#4ade80"),      # green
    "NOT_SUPPORTED": ("#450a0a", "#f87171"),  # red
    "NEEDS_MEDIA": ("#422006", "#facc15"),    # yellow
    "SKIPPED": ("#1e293b", "#94a3b8"),        # gray
    "TIMEOUT": ("#431407", "#fb923c"),        # orange
    "OTHER": ("#2e1065", "#c4b5fd"),          # purple
}


def _esc(v):
    return html.escape(str(v if v is not None else ""))


def _badge(mode):
    if mode == "full-compat":
        return ('<span style="background:#ea580c;color:#fff;padding:4px 14px;'
                'border-radius:999px;font-size:13px;font-weight:700">FULL-COMPAT</span>')
    return ('<span style="background:#2563eb;color:#fff;padding:4px 14px;'
            'border-radius:999px;font-size:13px;font-weight:700">SAFE</span>')


def _stat_cards(summary):
    order = ["SUPPORTED", "NOT_SUPPORTED", "NEEDS_MEDIA", "SKIPPED"]
    accent = {"SUPPORTED": "#22c55e", "NOT_SUPPORTED": "#ef4444",
              "NEEDS_MEDIA": "#eab308", "SKIPPED": "#64748b"}
    icon = {"SUPPORTED": "✅", "NOT_SUPPORTED": "❌",
            "NEEDS_MEDIA": "💿", "SKIPPED": "🔒"}
    cards = []
    for k in order:
        n = summary.get(k, 0)
        cards.append(
            f'<div style="flex:1;min-width:140px;background:#1e293b;border-radius:14px;'
            f'padding:18px;border-left:4px solid {accent[k]};'
            f'box-shadow:0 4px 14px rgba(0,0,0,.35)">'
            f'<div style="color:#94a3b8;font-size:13px">{icon[k]} {k}</div>'
            f'<div style="font-size:30px;font-weight:800;color:{accent[k]};'
            f'margin-top:6px">{n}</div></div>')
    for k, n in summary.items():
        if k not in order:
            cards.append(
                f'<div style="flex:1;min-width:140px;background:#1e293b;border-radius:14px;'
                f'padding:18px;border-left:4px solid #a855f7;'
                f'box-shadow:0 4px 14px rgba(0,0,0,.35)">'
                f'<div style="color:#94a3b8;font-size:13px">🔹 {_esc(k)}</div>'
                f'<div style="font-size:30px;font-weight:800;color:#c084fc;'
                f'margin-top:6px">{n}</div></div>')
    return "".join(cards)


def _row_style(result):
    bg, fg = _RESULT_COLORS.get(result, _RESULT_COLORS["OTHER"])
    return f'style="background:{bg};color:{fg};font-weight:600"'


def _info_grid(r):
    pt = r.get("peripheral_type")
    pt_txt = f"0x{pt:02x} ({r.get('peripheral_type_name') or '?'})" if pt is not None else "?"
    prof = r.get("current_profile")
    prof_txt = (f"0x{prof:04x} ({r.get('current_profile_name') or '?'})"
                if prof is not None else "n/a")
    rows = [
        ("Vendor", r.get("vendor")),
        ("Product", r.get("product")),
        ("Revision", r.get("revision")),
        ("Peripheral Type", pt_txt),
        ("Serial Number", r.get("serial_number") or "n/a"),
        ("Current Profile", prof_txt),
        ("Media", r.get("media_type") or "n/a"),
        ("Block Size", r.get("media_block_size_name") or "n/a"),
    ]
    cells = []
    for label, val in rows:
        cells.append(
            f'<div style="background:#0f172a;border-radius:10px;padding:10px 14px">'
            f'<div style="color:#64748b;font-size:11px;letter-spacing:.5px">{label}</div>'
            f'<div style="color:#e2e8f0;font-size:14px;margin-top:4px">{_esc(val)}</div></div>')
    return "".join(cells)


def _matrix_table(rows, headers):
    thead = "".join(
        f"<th style='text-align:left;padding:10px 12px;color:#94a3b8;font-size:12px'>{h}</th>"
        for h in headers)
    trs = []
    for row in rows:
        tds = "".join(
            f"<td style='padding:8px 12px;border-top:1px solid #334155'>{c}</td>"
            for c in row["_cells"])
        trs.append(f"<tr {_row_style(row.get('result', 'OTHER'))}>{tds}</tr>")
    return (f'<table style="width:100%;border-collapse:collapse;background:#1e293b;'
            f'border-radius:14px;overflow:hidden">'
            f"<thead><tr>{thead}</tr></thead>{''.join(trs)}</table>")


def format_html(r):
    """Return a complete standalone HTML document for probe result dict r."""
    dev_name = f"{r.get('vendor') or '?'} {r.get('product') or r.get('device')}"
    title = f"{r.get('product') or r.get('device')} — SCSI Probe Report"
    cmds = []
    for c in r.get("commands", []):
        cmds.append({
            "_cells": [_esc(c.get("opcode")), _esc(c.get("name")),
                       _esc(c.get("category")), _esc(c.get("result")),
                       _esc(c.get("detail"))],
            "result": c.get("result", "OTHER"),
        })
    bts = []
    for b in r.get("block_type_matrix", []):
        bts.append({
            "_cells": ["0x" + _esc(b.get("code")), _esc(b.get("size")),
                       _esc(b.get("result")), _esc(b.get("detail"))],
            "result": b.get("result", "OTHER"),
        })
    rsoc_html = ""
    if r.get("rsoc_opcodes"):
        ops = ", ".join(
            f'<code style="background:#0f172a;color:#4ade80;padding:2px 8px;'
            f'border-radius:6px;font-size:13px">0x{op:02X}</code>'
            for op in r["rsoc_opcodes"])
        rsoc_html = (
            f'<div style="background:#1e293b;border-radius:14px;padding:20px;'
            f'margin-top:20px;box-shadow:0 4px 14px rgba(0,0,0,.35)">'
            f'<h2 style="color:#e2e8f0;font-size:17px;margin:0 0 12px">'
            f'🔎 Drive-Reported Opcodes (RSOC, SPC-3 SA=0x0C)</h2>'
            f'<p style="color:#94a3b8;margin:0 0 10px">{len(r["rsoc_opcodes"])} '
            f'opcodes the drive reports as supported:</p>'
            f'<div style="line-height:2">{ops}</div></div>')
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title></head>
<body style="margin:0;background:#0f172a;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;color:#e2e8f0">
<div style="max-width:1080px;margin:0 auto;padding:32px 20px 60px">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
    <div>
      <div style="color:#64748b;font-size:12px;letter-spacing:1px">ODD SCSI PROBE</div>
      <h1 style="margin:6px 0 0;font-size:26px;color:#f8fafc">{_esc(dev_name)}</h1>
    </div>
    {_badge(r.get("mode"))}
  </div>
  <div style="display:flex;gap:14px;margin-top:24px;flex-wrap:wrap">{_stat_cards(r.get("summary") or {})}</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:24px">{_info_grid(r)}</div>
  <div style="background:#1e293b;border-radius:14px;padding:20px;margin-top:20px;box-shadow:0 4px 14px rgba(0,0,0,.35)">
    <h2 style="color:#e2e8f0;font-size:17px;margin:0 0 12px">📋 SCSI Command Matrix</h2>
    {_matrix_table(cmds, ["Opcode", "Name", "Category", "Result", "Detail"])}
  </div>
  <div style="background:#1e293b;border-radius:14px;padding:20px;margin-top:20px;box-shadow:0 4px 14px rgba(0,0,0,.35)">
    <h2 style="color:#e2e8f0;font-size:17px;margin:0 0 12px">💿 Data Block Type Matrix (READ CD, MMC Table 600)</h2>
    {_matrix_table(bts, ["Type", "Size", "Result", "Detail"])}
  </div>
  {rsoc_html}
  <div style="margin-top:28px;color:#64748b;font-size:12px;text-align:center">
    Generated {_esc(ts)} · {_esc(TOOL_VERSION)}
  </div>
</div></body></html>"""


def write_html_report(r, path):
    """Write the HTML report to path; returns path."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(format_html(r))
    return path
