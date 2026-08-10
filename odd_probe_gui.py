#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
odd_probe_gui.py — Tkinter GUI for odd_probe.py (USB ODD SCSI support probe)

Reuses the CLI engine (odd_probe.py) for device discovery and probing; this
file only adds the desktop UI. Zero third-party dependencies.

Run:
  python3 odd_probe_gui.py           # Linux / WSLg
  pythonw odd_probe_gui.py           # Windows
  pyinstaller --onefile --windowed --name odd-probe odd_probe_gui.py

Safety: the --dangerous equivalent is off by default and asks for explicit
confirmation when enabled. In --dangerous mode every command is sent for
real: BLANK erases the disc, FORMAT UNIT formats media, CLOSE TRACK/SESSION
closes sessions, WRITE 10/12 writes data, LOAD/UNLOAD operates the tray.
Only WRITE BUFFER firmware modes (0x05/0x0F/0x0A) are never executed.
Use a sacrificial test disc!
"""

import json
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import odd_probe

APP_TITLE = "odd-scsi-probe — USB ODD 檢測工具"

RESULT_ORDER = ("SUPPORTED", "NOT_SUPPORTED", "NEEDS_MEDIA", "SKIPPED", "TIMEOUT", "OTHER")
RESULT_ICON = {"SUPPORTED": "✅", "NOT_SUPPORTED": "❌", "NEEDS_MEDIA": "💿",
               "SKIPPED": "🔒", "TIMEOUT": "⏱️", "OTHER": "⚠️"}
RESULT_TAG_COLORS = {"SUPPORTED": "#1b7a2e", "NOT_SUPPORTED": "#c62828",
                     "NEEDS_MEDIA": "#1565c0", "SKIPPED": "#9e9e9e",
                     "TIMEOUT": "#ef6c00", "OTHER": "#000000"}

INFO_FIELDS = (("device", "裝置"), ("vendor", "Vendor"), ("product", "Product"),
               ("revision", "Revision"), ("peripheral_type", "Peripheral Type"),
               ("serial", "Serial Number"), ("current_profile", "Current Profile"),
               ("media", "Media Detected"), ("block_size", "Media Block Size"))


# ---------------------------------------------------------------------------
# Pure display-model helpers (no Tk dependency — unit-testable headless)
# ---------------------------------------------------------------------------
def build_display_model(result):
    """Flatten a probe_device() dict into GUI-friendly rows (pure, testable)."""
    info = {
        "device": result.get("device", "?"),
        "vendor": result.get("vendor") or "?",
        "product": result.get("product") or "?",
        "revision": result.get("revision") or "?",
        "peripheral_type": "?",
        "serial": result.get("serial_number") or "n/a",
        "current_profile": "?",
        "media": result.get("media_type") or "unknown",
        "block_size": result.get("media_block_size_name") or "unknown",
    }
    pt = result.get("peripheral_type")
    if pt is not None:
        info["peripheral_type"] = f"0x{pt:02x} ({odd_probe.name_peripheral(pt)})"
    cp = result.get("current_profile")
    if cp is not None:
        info["current_profile"] = (f"0x{cp:04x} "
                                   f"({result.get('current_profile_name') or odd_probe.name_profile(cp)})")
    profiles = [{"code": p.get("code"), "name": odd_probe.name_profile(p.get("code", 0)),
                 "current": bool(p.get("current"))} for p in result.get("profiles", [])]
    features = [{"code": f.get("code"), "name": odd_probe.name_feature(f.get("code", 0)),
                 "current": bool(f.get("current"))} for f in result.get("features", [])]
    rows = [{"opcode": c.get("opcode", "?"), "name": c.get("name", "?"),
             "category": c.get("category", "?"), "result": c.get("result", "?"),
             "detail": c.get("detail", "")} for c in result.get("commands", [])]
    block_types = [
        {"code": b.get("code"), "size": b.get("size"),
         "name": b.get("name", ""), "mandatory": bool(b.get("mandatory")),
         "result": b.get("result", "?"), "detail": b.get("detail", "")}
        for b in result.get("block_type_matrix", [])
    ]
    summary = result.get("summary", {})
    stats = {k: int(summary.get(k, 0)) for k in RESULT_ORDER}
    return {"info": info, "profiles": profiles, "features": features,
            "rows": rows, "block_types": block_types,
            "stats": stats, "duration": result.get("duration_sec")}


def stats_line(stats):
    """One-line summary for the status bar / export, e.g. 'SUPPORTED 30 / ...'."""
    return " / ".join(f"{k} {stats.get(k, 0)}" for k in RESULT_ORDER)


# ---------------------------------------------------------------------------
# Tk application
# ---------------------------------------------------------------------------
class OddProbeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1020x700")
        self.minsize(860, 580)

        self.result = None
        self._running = False
        self._queue = queue.Queue()
        self._poll_job = None

        self.device_var = tk.StringVar()
        self.dangerous_var = tk.BooleanVar(value=False)
        self.timeout_var = tk.StringVar(value="5")
        self.status_var = tk.StringVar(value="就緒 — 請先「掃描裝置」並選擇目標")
        self.progress_var = tk.DoubleVar(value=0)

        self._build_toolbar()
        self._build_body()
        self._build_statusbar()
        self._set_running(False)

    # ---------------- UI construction ----------------
    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(side=tk.TOP, fill=tk.X)

        self.scan_btn = ttk.Button(bar, text="掃描裝置", command=self._on_scan)
        self.scan_btn.grid(row=0, column=0, padx=(0, 6))

        self.device_cb = ttk.Combobox(bar, textvariable=self.device_var,
                                      state="readonly", width=24)
        self.device_cb.grid(row=0, column=1, padx=(0, 10))
        self.device_cb.bind("<<ComboboxSelected>>", lambda e: self._on_device_selected())

        self.probe_btn = ttk.Button(bar, text="開始檢測", command=self._on_probe)
        self.probe_btn.grid(row=0, column=2, padx=(0, 14))

        self.dangerous_chk = ttk.Checkbutton(
            bar, text="--dangerous 寫入類存在性測試",
            variable=self.dangerous_var, command=self._on_dangerous_toggle)
        self.dangerous_chk.grid(row=0, column=3, padx=(0, 14))

        ttk.Label(bar, text="Timeout(秒):").grid(row=0, column=4, padx=(0, 4))
        self.timeout_spin = ttk.Spinbox(bar, from_=1, to=30, width=4,
                                        textvariable=self.timeout_var)
        self.timeout_spin.grid(row=0, column=5, padx=(0, 14))

        self.export_btn = ttk.Button(bar, text="匯出報告", command=self._on_export)
        self.export_btn.grid(row=0, column=6)
        self.html_btn = ttk.Button(bar, text="匯出 HTML 報告", command=self._on_export_html)
        self.html_btn.grid(row=0, column=7)

    def _build_body(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        self.nb.add(self._build_info_tab(self.nb), text="裝置資訊")
        self.nb.add(self._build_formats_tab(self.nb), text="支援格式")
        self.nb.add(self._build_matrix_tab(self.nb), text="指令矩陣")
        self.nb.add(self._build_stats_tab(self.nb), text="統計")

    def _build_statusbar(self):
        bar = ttk.Frame(self, padding=(8, 4))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.progress = ttk.Progressbar(bar, mode="determinate", length=220,
                                        maximum=odd_probe.TOTAL_PROBE_STEPS,
                                        variable=self.progress_var)
        self.progress.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(bar, textvariable=self.status_var).pack(side=tk.LEFT)

    def _build_info_tab(self, parent):
        frame = ttk.Frame(parent, padding=12)
        self._info_labels = {}
        for row, (key, text) in enumerate(INFO_FIELDS):
            ttk.Label(frame, text=text, font=("", 10, "bold")).grid(
                row=row, column=0, sticky="w", pady=3, padx=(0, 14))
            lbl = ttk.Label(frame, text="—", wraplength=640, justify="left")
            lbl.grid(row=row, column=1, sticky="w", pady=3)
            self._info_labels[key] = lbl
        return frame

    def _build_formats_tab(self, parent):
        frame = ttk.Frame(parent, padding=8)
        frame.columnconfigure(0, weight=1, uniform="f")
        frame.columnconfigure(1, weight=1, uniform="f")
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)
        ttk.Label(frame, text="支援的 Profile（[*] = current）").grid(
            row=0, column=0, sticky="w", pady=(0, 4))
        ttk.Label(frame, text="Feature List").grid(row=0, column=1, sticky="w", pady=(0, 4))
        prof_frame, self.profile_txt = self._make_text_area(frame)
        prof_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 4))
        feat_frame, self.feature_txt = self._make_text_area(frame)
        feat_frame.grid(row=1, column=1, sticky="nsew", padx=(4, 0))
        ttk.Label(frame, text="CD Data Block Type 支援矩陣（READ CD, MMC Table 600）").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(8, 4))
        bt_frame, self.blocktype_txt = self._make_text_area(frame)
        bt_frame.grid(row=3, column=0, columnspan=2, sticky="nsew")
        return frame

    def _build_matrix_tab(self, parent):
        frame = ttk.Frame(parent, padding=8)
        cols = ("opcode", "name", "category", "result", "detail")
        self.matrix = ttk.Treeview(frame, columns=cols, show="headings")
        headings = {"opcode": ("指令碼", 70, "center"), "name": ("名稱", 200, "w"),
                    "category": ("類別", 110, "center"), "result": ("結果", 160, "w"),
                    "detail": ("詳細", 500, "w")}
        for col in cols:
            text, width, anchor = headings[col]
            self.matrix.heading(col, text=text)
            self.matrix.column(col, width=width, anchor=anchor, stretch=(col == "detail"))
        for result, color in RESULT_TAG_COLORS.items():
            self.matrix.tag_configure(result, foreground=color)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.matrix.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.matrix.xview)
        self.matrix.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.matrix.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return frame

    def _build_stats_tab(self, parent):
        frame = ttk.Frame(parent, padding=12)
        self._stat_labels = {}
        for row, result in enumerate(RESULT_ORDER):
            ttk.Label(frame, text=f"{RESULT_ICON[result]} {result}",
                      font=("", 10, "bold")).grid(row=row, column=0, sticky="w", pady=2)
            lbl = ttk.Label(frame, text="0", font=("", 10, "bold"))
            lbl.grid(row=row, column=1, sticky="w", padx=(18, 0), pady=2)
            self._stat_labels[result] = lbl
        ttk.Separator(frame).grid(row=len(RESULT_ORDER), column=0, columnspan=2,
                                  sticky="ew", pady=8)
        self.stats_summary_txt = tk.Text(frame, height=9, width=72, wrap=tk.NONE,
                                         state=tk.DISABLED, font=("Courier", 9))
        self.stats_summary_txt.grid(row=len(RESULT_ORDER) + 1, column=0,
                                    columnspan=2, sticky="nsew")
        frame.rowconfigure(len(RESULT_ORDER) + 1, weight=1)
        return frame

    def _make_text_area(self, parent):
        """Composite widget: (frame, text) — scrollbars packed inside the frame so
        the caller can grid the frame without mixing geometry managers."""
        frame = ttk.Frame(parent)
        txt = tk.Text(frame, height=10, wrap=tk.NONE, state=tk.DISABLED,
                      font=("Courier", 9))
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=txt.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=txt.xview)
        txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        return frame, txt

    # ---------------- actions ----------------
    def _on_scan(self):
        devs = odd_probe.discover_devices()
        if os.name == "nt":  # GUI targets optical drives; skip raw Scsi ports
            devs = [d for d in devs if "CdRom" in d]
        if not devs:
            messagebox.showinfo(
                "掃描結果",
                "未找到任何候選裝置。\n\n"
                "Linux：請確認 /dev/sg* 或 /dev/sr* 存在，且目前使用者有讀寫權限。\n"
                "Windows：請確認有光碟機（\\\\.\\CdRom*）。",
                parent=self)
            self.device_cb["values"] = ()
            self.device_var.set("")
            self._on_device_selected()
            return
        # 對每個裝置做快速 INQUIRY，只保留 ODD 裝置（peripheral type 0x05）
        self.status_var.set("正在識別 ODD 裝置...")
        odd_devs = []
        for dev in devs:
            try:
                info, ok, err = odd_probe.inquiry(dev, 2)  # 2s timeout per device
                if ok and info and info.get("peripheral_type") == 0x05:
                    odd_devs.append(dev)
            except Exception:
                pass
        if not odd_devs:
            # 沒有 ODD 裝置時，顯示所有可存取的裝置（含非 ODD）
            messagebox.showinfo(
                "掃描結果",
                "未找到 USB ODD 裝置（peripheral type 0x05 CD/DVD）。\n\n"
                "請確認：\n"
                "1. USB ODD 已正確連接\n"
                "2. 驅動程式已正確安裝\n"
                "3. 以系統管理員權限執行（Windows）",
                parent=self)
            # 仍顯示所有找到的裝置供手動選擇
            self.device_cb["values"] = devs
            self.device_var.set(devs[0] if devs else "")
            self.status_var.set(f"找到 {len(devs)} 個候選裝置（無 ODD 類型）")
            self._on_device_selected()
            return
        self.device_cb["values"] = odd_devs
        self.device_var.set(odd_devs[0])
        self.status_var.set(f"找到 {len(odd_devs)} 個 ODD 裝置：{odd_devs[0]} ...")
        self._on_device_selected()

    def _on_device_selected(self):
        ready = bool(self.device_var.get()) and not self._running
        self.probe_btn.config(state=tk.NORMAL if ready else tk.DISABLED)

    def _on_dangerous_toggle(self):
        if not self.dangerous_var.get():
            return
        ok = messagebox.askyesno(
            "確認",
            "⚠️ 此模式會真實執行所有指令！\n\n"
            "BLANK 抹除整片光碟、FORMAT UNIT 格式化媒體、\n"
            "CLOSE TRACK/SESSION 關閉 session、WRITE 10/12 寫入資料、\n"
            "LOAD/UNLOAD 操作托盤。\n\n"
            "請使用可犧牲的測試片！",
            parent=self)
        if not ok:
            self.dangerous_var.set(False)

    def _on_probe(self):
        dev = self.device_var.get().strip()
        if not dev:
            return
        try:
            timeout = min(30, max(1, int(self.timeout_var.get() or "5")))
        except ValueError:
            timeout = 5
        dangerous = bool(self.dangerous_var.get())

        self._set_running(True)
        self.result = None
        self._clear_results()
        self.progress["mode"] = "determinate"
        self.progress["maximum"] = odd_probe.TOTAL_PROBE_STEPS
        self.progress["value"] = 0
        self.status_var.set("檢測中（取得裝置資訊）...")
        self._queue = queue.Queue()
        threading.Thread(target=self._probe_worker,
                         args=(dev, timeout, dangerous), daemon=True).start()
        self._poll_job = self.after(100, self._poll)

    def _probe_worker(self, dev, timeout, dangerous):
        try:
            def progress_cb(done, total):
                self._queue.put(("progress", done, total))
            res = odd_probe.probe_device(dev, timeout, dangerous,
                                         progress_cb=progress_cb)
            self._queue.put(("done", res))
        except OSError as e:
            self._queue.put(("error", f"無法開啟裝置 {dev}：{e}"))
        except Exception as e:  # noqa: BLE001 — GUI must surface any failure
            self._queue.put(("error", f"檢測失敗：{e!r}"))

    def _poll(self):
        self._poll_job = None
        try:
            while True:
                kind, *payload = self._queue.get_nowait()
                if kind == "progress":
                    done, total = payload
                    self.progress["value"] = done
                    self.status_var.set(f"檢測中 {done}/{total}...")
                elif kind == "done":
                    self._show_result(payload[0])
                    self._set_running(False)
                    return
                elif kind == "error":
                    self.status_var.set("檢測失敗")
                    self._set_running(False)
                    messagebox.showerror("檢測失敗", payload[0], parent=self)
                    return
        except queue.Empty:
            pass
        self._poll_job = self.after(100, self._poll)

    def _show_result(self, result):
        self.result = result
        model = build_display_model(result)
        self._fill_info(model["info"])
        self._fill_formats(model["profiles"], model["features"])
        self._fill_block_types(model["block_types"])
        self._fill_matrix(model["rows"])
        self._fill_stats(model)
        self.status_var.set(f"檢測完成（{model['duration'] or 0:.1f}s）：{stats_line(model['stats'])}")

    def _on_export_html(self):
        if self.result is None:
            messagebox.showinfo("匯出 HTML 報告", "尚無檢測結果可匯出。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="匯出 HTML 報告", defaultextension=".html",
            filetypes=[("HTML 報告", "*.html")])
        if not path:
            return
        try:
            import report_html
            saved = report_html.write_html_report(self.result, path)
            messagebox.showinfo("匯出 HTML 報告", f"已存檔：\n{saved}", parent=self)
        except Exception as e:
            messagebox.showerror("匯出 HTML 報告", f"匯出失敗：{e}", parent=self)

    def _on_export(self):
        if self.result is None:
            messagebox.showinfo("匯出報告", "尚無檢測結果可匯出。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="匯出報告", defaultextension=".json",
            filetypes=[("JSON 報告", "*.json"), ("文字報告", "*.txt")])
        if not path:
            return
        try:
            if path.lower().endswith(".txt"):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(odd_probe.format_human(self.result))
            else:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.result, f, indent=2, ensure_ascii=False)
        except OSError as e:
            messagebox.showerror("匯出失敗", f"無法寫入檔案：{e}", parent=self)
            return
        self.status_var.set(f"報告已匯出：{path}")

    # ---------------- fill helpers ----------------
    def _clear_results(self):
        for lbl in self._info_labels.values():
            lbl.config(text="—")
        self._set_text(self.profile_txt, "（尚未檢測）")
        self._set_text(self.feature_txt, "（尚未檢測）")
        self._set_text(self.blocktype_txt, "（尚未檢測）")
        self.matrix.delete(*self.matrix.get_children())
        for lbl in self._stat_labels.values():
            lbl.config(text="0")
        self._set_text(self.stats_summary_txt, "（尚未檢測）")

    def _fill_info(self, info):
        for key, lbl in self._info_labels.items():
            lbl.config(text=info.get(key, "—"))

    def _fill_formats(self, profiles, features):
        prof_lines = [f"{'[*]' if p['current'] else '[ ]'} 0x{p['code']:04x} {p['name']}"
                      for p in profiles] or ["（無 profile 資料）"]
        feat_lines = [f"0x{f['code']:04x} {f['name']}{' *' if f['current'] else ''}"
                      for f in features] or ["（無 feature 資料）"]
        self._set_text(self.profile_txt, "\n".join(prof_lines))
        self._set_text(self.feature_txt, "\n".join(feat_lines))

    def _fill_block_types(self, block_types):
        if not block_types:
            self._set_text(self.blocktype_txt, "（無資料）")
            return
        lines = ["Code   Size   Result         Mandatory  Name"]
        for b in block_types:
            icon = RESULT_ICON.get(b["result"], "?")
            mand = "(M)" if b["mandatory"] else "(O)"
            lines.append(f"{b['code']:<6}{b['size']:<7}{icon + ' ' + b['result']:<15}{mand:<11}{b['name']}")
        self._set_text(self.blocktype_txt, "\n".join(lines))

    def _fill_matrix(self, rows):
        self.matrix.delete(*self.matrix.get_children())
        for r in rows:
            icon = RESULT_ICON.get(r["result"], "?")
            self.matrix.insert("", tk.END,
                               values=(r["opcode"], r["name"], r["category"],
                                       f"{icon} {r['result']}", r["detail"]),
                               tags=(r["result"],))

    def _fill_stats(self, model):
        stats = model["stats"]
        for result, lbl in self._stat_labels.items():
            lbl.config(text=str(stats.get(result, 0)))
        info = model["info"]
        lines = [f"裝置           : {info['device']}",
                 f"Vendor/Product : {info['vendor']} / {info['product']}",
                 f"Serial         : {info['serial']}",
                 f"Media          : {info['media']}",
                 f"Block Size     : {info['block_size']}",
                 f"檢測耗時       : {model['duration'] or 0:.1f}s",
                 f"指令總數       : {sum(stats.values())}",
                 "", stats_line(stats)]
        self._set_text(self.stats_summary_txt, "\n".join(lines))

    @staticmethod
    def _set_text(widget, text):
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        widget.config(state=tk.DISABLED)

    def _set_running(self, running):
        self._running = running
        state = tk.DISABLED if running else tk.NORMAL
        self.scan_btn.config(state=state)
        self.timeout_spin.config(state=state)
        self.dangerous_chk.config(state=state)
        self.device_cb.config(state=tk.DISABLED if running else "readonly")
        self._on_device_selected()
        self.export_btn.config(state=tk.NORMAL if (not running and self.result) else tk.DISABLED)


def main():
    app = OddProbeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
