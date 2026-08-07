#!/usr/bin/env python3
# GUI smoke test — needs a display (run under xvfb on headless hosts):
#   xvfb-run -a python3 tests/gui_smoke.py
# Drives the REAL Tk app with a mocked probe through the threading+queue
# pipeline (progress ticks -> result tabs -> status bar) and the error path.
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import odd_probe
import odd_probe_gui as gui

FAKE_RESULT = {
    "device": "/dev/sg0",
    "vendor": "HL-DT-ST", "product": "BD-RE WH16NS60", "revision": "1.02",
    "peripheral_type": 5, "peripheral_type_name": "CD/DVD device",
    "serial_number": "K9AB1234567",
    "current_profile": 0x41, "current_profile_name": "BD-R Sequential",
    "profiles": [{"code": 0x08, "current": True}, {"code": 0x41, "current": True}],
    "features": [{"code": 0x0000, "current": True, "persistent": True},
                 {"code": 0x0040, "current": True, "persistent": False}],
    "media_type": "BD-R (disc type 0x0d)",
    "media_block_size": 2352, "media_block_size_name": "2352 (CD raw)",
    "cd_block_types": [
        {"code": 0, "block_size": 2352, "name": "Raw data", "mandatory": False,
         "result": "SUPPORTED", "detail": "GOOD"},
        {"code": 8, "block_size": 2048, "name": "Mode 1 ISO/IEC 10149", "mandatory": True,
         "result": "SUPPORTED", "detail": "GOOD"},
    ],
    "commands": [{"opcode": "0x28", "name": "READ 10", "category": "SPC",
                  "result": "SUPPORTED", "detail": "GOOD"},
                 {"opcode": "0xA1", "name": "BLANK", "category": "DANGEROUS",
                  "result": "SKIPPED", "detail": "🔒 unsafe to test (erases entire disc)"}],
    "summary": {"SUPPORTED": 30, "NOT_SUPPORTED": 1, "NEEDS_MEDIA": 0,
                "SKIPPED": 15, "TIMEOUT": 0, "OTHER": 0},
    "duration_sec": 0.42,
}


def pump(app, rounds=150):
    """Drive the Tk event loop until the probe pipeline settles; sleep so
    after() timers actually become due (update() alone is too fast)."""
    for _ in range(rounds):
        app.update()
        if not app._running and app._poll_job is None:
            return True
        time.sleep(0.01)
    return False


def main():
    # avoid modal dialogs blocking the automated run
    gui.messagebox.showinfo = lambda *a, **k: None
    gui.messagebox.askyesno = lambda *a, **k: True
    gui.messagebox.showerror = lambda *a, **k: None

    # --- scan path ---
    odd_probe.discover_devices = lambda: ["/dev/sg0", "/dev/sr0", "/dev/sg1"]
    app = gui.OddProbeApp()
    app.update()
    app._on_scan()
    assert tuple(app.device_cb["values"]) == ("/dev/sg0", "/dev/sr0", "/dev/sg1"), app.device_cb["values"]
    assert app.device_var.get() == "/dev/sg0"
    assert str(app.probe_btn["state"]) == "normal", "probe button should enable after selection"
    assert str(app.export_btn["state"]) == "disabled", "export disabled before any result"
    print("  ✅ scan populates dropdown + enables 開始檢測")

    # --- no-device scan path ---
    odd_probe.discover_devices = lambda: []
    app._on_scan()
    assert app.device_var.get() == ""
    assert str(app.probe_btn["state"]) == "disabled"
    print("  ✅ empty scan disables 開始檢測")

    # --- success path through worker thread + queue ---
    def fake_probe(dev, timeout_s, dangerous, progress_cb=None):
        for i in range(1, 5):
            progress_cb(i, len(odd_probe.CMDS))
        return FAKE_RESULT
    odd_probe.probe_device = fake_probe
    odd_probe.discover_devices = lambda: ["/dev/sg0"]
    app._on_scan()
    app._on_probe()
    assert app._running is True
    pump(app)
    assert app.result is not None, "result should be set after done"
    assert app._stat_labels["SUPPORTED"]["text"] == "30"
    assert app._stat_labels["SKIPPED"]["text"] == "15"
    assert app._info_labels["vendor"]["text"] == "HL-DT-ST"
    assert app._info_labels["current_profile"]["text"] == "0x0041 (BD-R Sequential)"
    assert app._info_labels["media"]["text"] == "BD-R (disc type 0x0d)"
    assert app._info_labels["block_size"]["text"] == "2352 (CD raw)"
    assert "Mode 1 ISO/IEC 10149" in app.blocktype_txt.get("1.0", "end")
    assert len(app.matrix.get_children()) == 2
    assert "檢測完成" in app.status_var.get()
    assert str(app.export_btn["state"]) == "normal", "export enabled after result"
    assert str(app.probe_btn["state"]) == "disabled" or app._running is False
    print("  ✅ mocked probe -> info/formats/matrix/stats tabs + status + export enabled")

    # --- dangerous checkbox default off, confirm flow works ---
    assert app.dangerous_var.get() is False
    app.dangerous_var.set(True)
    app._on_dangerous_toggle()
    assert app.dangerous_var.get() is True, "askyesno mocked True -> stays checked"
    print("  ✅ dangerous confirm flow (askyesno=True keeps it checked)")

    # --- error path: device open failure surfaces as messagebox, no crash ---
    def bad_probe(dev, timeout_s, dangerous, progress_cb=None):
        raise PermissionError(13, "Permission denied")
    odd_probe.probe_device = bad_probe
    app._on_probe()
    pump(app)
    assert app._running is False
    assert "檢測失敗" in app.status_var.get()
    print("  ✅ OSError from probe -> status 檢測失敗, UI not stuck")

    app.destroy()
    print("GUI smoke PASS")


if __name__ == "__main__":
    main()
