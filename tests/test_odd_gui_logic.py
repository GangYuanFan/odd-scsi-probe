#!/usr/bin/env python3
# GUI logic tests for odd_probe_gui.py — pure display-model / stats helpers.
# No display needed (tkinter is imported but no Tk() is created).
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import odd_probe_gui as gui

passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name} {extra}")

FAKE_RESULT = {
    "device": "/dev/sg2",
    "vendor": "HL-DT-ST", "product": "BD-RE WH16NS60", "revision": "1.02",
    "peripheral_type": 5, "peripheral_type_name": "CD/DVD device",
    "serial_number": "K9AB1234567",
    "current_profile": 0x41, "current_profile_name": "BD-R Sequential",
    "profiles": [
        {"code": 0x08, "current": True},
        {"code": 0x40, "current": False},
        {"code": 0x41, "current": True},
    ],
    "features": [
        {"code": 0x0000, "current": True, "persistent": True},
        {"code": 0x0040, "current": True, "persistent": False},
        {"code": 0x001E, "current": False, "persistent": False},
    ],
    "media_type": "BD-R (disc type 0x0d)",
    "commands": [
        {"opcode": "0x28", "name": "READ 10", "category": "SPC", "result": "SUPPORTED", "detail": "GOOD"},
        {"opcode": "0x51", "name": "READ DISC INFORMATION", "category": "MMC", "result": "SUPPORTED", "detail": "GOOD"},
        {"opcode": "0x2B", "name": "SEEK 10", "category": "SPC", "result": "NOT_SUPPORTED", "detail": "ILLEGAL REQUEST"},
        {"opcode": "0x42", "name": "READ SUBCHANNEL", "category": "MMC", "result": "NEEDS_MEDIA", "detail": "MEDIUM NOT PRESENT"},
        {"opcode": "0xA1", "name": "BLANK", "category": "DANGEROUS", "result": "SKIPPED", "detail": "unsafe"},
        {"opcode": "0x00", "name": "TEST UNIT READY", "category": "SPC", "result": "TIMEOUT", "detail": "ioctl error"},
        {"opcode": "0x45", "name": "PLAY AUDIO 10", "category": "MMC", "result": "OTHER", "detail": "status=0x08"},
    ],
    "summary": {"SUPPORTED": 2, "NOT_SUPPORTED": 1, "NEEDS_MEDIA": 1,
                "SKIPPED": 1, "TIMEOUT": 1, "OTHER": 1},
    "duration_sec": 1.25,
}

print("== build_display_model(): full result ==")
m = gui.build_display_model(FAKE_RESULT)
check("info.device", m["info"]["device"] == "/dev/sg2")
check("info.vendor/product/rev", (m["info"]["vendor"], m["info"]["product"], m["info"]["revision"]) ==
      ("HL-DT-ST", "BD-RE WH16NS60", "1.02"))
check("info.peripheral_type formatted", m["info"]["peripheral_type"] == "0x05 (CD/DVD device)")
check("info.serial", m["info"]["serial"] == "K9AB1234567")
check("info.current_profile formatted", m["info"]["current_profile"] == "0x0041 (BD-R Sequential)")
check("info.media", m["info"]["media"] == "BD-R (disc type 0x0d)")
check("3 profiles with names", [p["name"] for p in m["profiles"]] ==
      ["CD-ROM", "BD-ROM", "BD-R Sequential"])
check("profile current flags", [p["current"] for p in m["profiles"]] == [True, False, True])
check("3 features with names", [f["name"] for f in m["features"]] ==
      ["Profile List", "BD Read", "CD Read"])
check("7 matrix rows preserved", len(m["rows"]) == 7 and m["rows"][0]["opcode"] == "0x28")
check("stats counted from summary", m["stats"] == {"SUPPORTED": 2, "NOT_SUPPORTED": 1,
      "NEEDS_MEDIA": 1, "SKIPPED": 1, "TIMEOUT": 1, "OTHER": 1})
check("duration carried", m["duration"] == 1.25)

print("== build_display_model(): sparse/empty result (robustness) ==")
m2 = gui.build_display_model({})
check("missing keys -> safe defaults", m2["info"]["vendor"] == "?"
      and m2["info"]["peripheral_type"] == "?" and m2["info"]["serial"] == "n/a")
check("empty lists -> []", m2["profiles"] == [] and m2["features"] == [] and m2["rows"] == [])
check("empty summary -> zeros", m2["stats"] == dict.fromkeys(gui.RESULT_ORDER, 0))
check("duration None tolerated", m2["duration"] is None)

print("== stats_line() ==")
line = gui.stats_line(FAKE_RESULT["summary"])
check("order + counts", line == "SUPPORTED 2 / NOT_SUPPORTED 1 / NEEDS_MEDIA 1 / SKIPPED 1 / TIMEOUT 1 / OTHER 1", line)
check("missing keys -> 0", gui.stats_line({}) == "SUPPORTED 0 / NOT_SUPPORTED 0 / NEEDS_MEDIA 0 / SKIPPED 0 / TIMEOUT 0 / OTHER 0")

print("== result taxonomy consistency ==")
check("RESULT_ORDER covers 6 classes", len(gui.RESULT_ORDER) == 6)
check("icons cover all results", set(gui.RESULT_ICON) == set(gui.RESULT_ORDER))
check("tag colors cover all results", set(gui.RESULT_TAG_COLORS) == set(gui.RESULT_ORDER))
check("INFO_FIELDS non-empty", len(gui.INFO_FIELDS) == 8)

print(f"\nRESULT: {passed} passed / {failed} failed")
sys.exit(1 if failed else 0)
