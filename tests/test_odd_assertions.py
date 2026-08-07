#!/usr/bin/env python3
# Logic assertion tests for odd_probe.py (Phase 4) — run on Linux, no device needed.
# Covers: sense classification, parsers (incl. MMC-3 spec-layout Disc Type),
# command matrix safety flags, READ 10 CDB regression, CLI guards (B3/B4),
# Windows ctypes layout (B5), doc counts (B6), progress callback.
import argparse
import ctypes
import io
import os
import sys
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import odd_probe as op

passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name} {extra}")

print("== classify() ==")
check("GOOD -> SUPPORTED", op.classify(0x00, b"", "") == ("SUPPORTED", "GOOD"))
check("ILLEGAL_REQ 0x20/0x00 -> NOT_SUPPORTED",
      op.classify(0x02, bytes([0x70,0,5,0,0,0,0,0,0,0,0,0,0x20,0x00]), "")[0] == "NOT_SUPPORTED")
check("ILLEGAL_REQ 0x24 -> SUPPORTED (param rejected)",
      op.classify(0x02, bytes([0x70,0,5,0,0,0,0,0,0,0,0,0,0x24,0x00]), "")[0] == "SUPPORTED")
check("ILLEGAL_REQ 0x25 -> SUPPORTED",
      op.classify(0x02, bytes([0x70,0,5,0,0,0,0,0,0,0,0,0,0x25,0x00]), "")[0] == "SUPPORTED")
check("NOT_READY 0x3A -> NEEDS_MEDIA",
      op.classify(0x02, bytes([0x70,0,2,0,0,0,0,0,0,0,0,0,0x3A,0x00]), "")[0] == "NEEDS_MEDIA")
check("NOT_READY 0x04 -> NEEDS_MEDIA",
      op.classify(0x02, bytes([0x70,0,2,0,0,0,0,0,0,0,0,0,0x04,0x00]), "")[0] == "NEEDS_MEDIA")
check("UNIT_ATTENTION -> SUPPORTED",
      op.classify(0x02, bytes([0x70,0,6,0,0,0,0,0,0,0,0,0,0x28,0x00]), "")[0] == "SUPPORTED")
check("WRITE_PROTECTED 0x27 -> SUPPORTED",
      op.classify(0x02, bytes([0x70,0,7,0,0,0,0,0,0,0,0,0,0x27,0x00]), "")[0] == "SUPPORTED")
check("MEDIUM_ERROR -> OTHER w/ sense hex",
      op.classify(0x02, bytes([0x70,0,3,0,0,0,0,0,0,0,0,0,0x11,0x00]), "")[0] == "OTHER")
check("status=0x08 -> OTHER",
      op.classify(0x08, b"", "")[0] == "OTHER")
check("EIO errno=5 -> TIMEOUT",
      op.classify(0, b"", "ioctl error errno=5") == ("TIMEOUT", "ioctl error (ioctl error errno=5)"))
check("EINVAL errno=22 -> OTHER",
      op.classify(0, b"", "ioctl error errno=22")[0] == "OTHER")
check("empty sense + CHECK CONDITION -> OTHER",
      op.classify(0x02, b"\x00"*8, "")[0] == "OTHER")
check("classify has exactly 11 return branches (matches docs)",
      sum(1 for _ in __import__("inspect").getsourcelines(op.classify)[0]
          if _.strip().startswith("return ")) == 11)

print("== parse_inquiry() ==")
inq = bytearray(36)
inq[0] = 0x05
inq[4] = 0x20
inq[8:16] = b"HL-DT-ST"
inq[16:32] = b"BD-RE WH16NS60"
inq[32:36] = b"1.02"
r = op.parse_inquiry(bytes(inq))
check("peripheral type 0x05", r["peripheral_type"] == 0x05)
check("vendor", r["vendor"] == "HL-DT-ST")
check("product", r["product"] == "BD-RE WH16NS60")
check("revision", r["revision"] == "1.02")

print("== parse_get_configuration() ==")
gc = bytearray(8)
gc[0:2] = (0x1C).to_bytes(2, "big")
gc[6:8] = (0x41).to_bytes(2, "big")  # current profile BD-R Sequential
gc += (0x0000).to_bytes(2, "big") + bytes([0x03, 12])          # Profile List feature, current+persistent, add_len=12
gc += (0x0008).to_bytes(2, "big") + bytes([0x01, 0x00])        # CD-ROM, current
gc += (0x0040).to_bytes(2, "big") + bytes([0x00, 0x00])        # BD-ROM, not current
gc += (0x0041).to_bytes(2, "big") + bytes([0x01, 0x00])        # BD-R, current
gc += (0x001E).to_bytes(2, "big") + bytes([0x01, 0x00])        # CD Read feature
cur, profs, feats = op.parse_get_configuration(bytes(gc))
check("current profile 0x41", cur == 0x41)
check("3 profiles parsed", len(profs) == 3)
check("profile CD-ROM current", profs[0] == {"code": 0x08, "current": True})
check("profile BD-ROM not current", profs[1] == {"code": 0x40, "current": False})
check("profile BD-R current", profs[2] == {"code": 0x41, "current": True})
check("2 features parsed", len(feats) == 2)
check("feature Profile List current", feats[0] == {"code": 0x0000, "current": True, "persistent": True})
check("feature CD Read current", feats[1] == {"code": 0x001E, "current": True, "persistent": False})
check("name_profile 0x41", op.name_profile(0x41) == "BD-R Sequential")
check("name_profile unknown", op.name_profile(0x77) == "unknown")
check("name_feature 0x0040", op.name_feature(0x0040) == "BD Read")
check("name_feature unknown", op.name_feature(0x1234) == "unknown")

print("== parse_disc_info() — MMC-3 r10g spec layout (Disc Type = byte 8, B1) ==")
# byte0-1 = Disc Information Length (0x0034 = 52), byte 8 = Disc Type
check("BD-R (byte8=0x0D)", op.parse_disc_info(bytes([0x00,0x34,0,1,1,1,1,0,0x0D,0])) == 0x0D)
check("CD-R (byte8=0x02)", op.parse_disc_info(bytes([0x00,0x34,0,1,1,1,1,0,0x02,0])) == 0x02)
check("high nibble of byte8 masked (0x1D -> 0x0D)",
      op.parse_disc_info(bytes([0x00,0x34,0,1,1,1,1,0,0x1D,0])) == 0x0D)
check("len<=8 -> None (short data)", op.parse_disc_info(b"\x00") is None)
check("old byte1 layout no longer misread (regression guard)",
      op.parse_disc_info(bytes([0, 0x0D])) is None)
check("name_disc_type 0x0D", op.name_disc_type(0x0D) == "BD-R")
check("name_disc_type 0x10", op.name_disc_type(0x10) == "HD DVD-ROM")

print("== READ 10 CDB regression (B2) ==")
read10 = next(c for c in op.CMDS if c["op"] == 0x28)
check("transfer len bytes 7-8 == 0x0001 (1 block)",
      read10["cdb"][7:9] == bytes([0x00, 0x01]), read10["cdb"].hex())
check("alloc == 512 (matches 1 block)", read10["alloc"] == 512)
check("LBA bytes 2-5 == 0", read10["cdb"][2:6] == bytes(4))

print("== command matrix counts / safety flags ==")
check("total 46 opcodes", len(op.CMDS) == 46, str(len(op.CMDS)))
check("15 SPC / 18 MMC / 13 DANGEROUS",
      [sum(1 for c in op.CMDS if c["cat"] == k) for k in ("SPC", "MMC", "DANGEROUS")] == [15, 18, 13])
for opc in (0xA1, 0x5B, 0x56):
    c = next(c for c in op.CMDS if c["op"] == opc)
    check(f"0x{opc:02X} has unsafe flag", bool(c.get("unsafe")), str(c))
for opc in (0x47, 0x48):
    c = next(c for c in op.CMDS if c["op"] == opc)
    check(f"0x{opc:02X} play-audio has unsafe flag", bool(c.get("unsafe")), str(c))
danger = [c for c in op.CMDS if c.get("dangerous")]
unsafe = [c for c in op.CMDS if c.get("unsafe")]
check("10 dangerous-inert entries (3 unsafe never-sent excluded)", len(danger) == 10, str(len(danger)))
check("5 unsafe-never-sent entries (BLANK/CLOSE x3 + PLAY AUDIO x2)", len(unsafe) == 5, str(len(unsafe)))

print("== --timeout validation (B4) ==")
check("_positive_int('5') == 5", op._positive_int("5") == 5)
for bad in ("0", "-3", "abc"):
    try:
        op._positive_int(bad)
        check(f"_positive_int({bad!r}) rejected", False)
    except argparse.ArgumentTypeError:
        check(f"_positive_int({bad!r}) rejected", True)

print("== list mode OSError guard (B3) ==")
orig_exec = op.scsi_execute
def boom(path, cdb, alloc, timeout_s):
    raise PermissionError(13, "Permission denied")
op.scsi_execute = boom
buf = io.StringIO()
try:
    with contextlib.redirect_stdout(buf):
        rc = op.main(["list"])
finally:
    op.scsi_execute = orig_exec
out = buf.getvalue()
check("exit code 0", rc == 0, str(rc))
check("prints (unavailable: ...)", "(unavailable: " in out)
check("no traceback leaked", "Traceback" not in out)

print("== Windows SCSI_PASS_THROUGH layout vs ntddscsi.h pshpack4 (B5) ==")
expected = {"Length": 0, "ScsiStatus": 2, "PathId": 3, "TargetId": 4, "Lun": 5,
            "CdbLength": 6, "SenseInfoLength": 7, "DataIn": 8,
            "DataTransferLength": 12, "TimeOutValue": 16, "DataBufferOffset": 20,
            "SenseInfoOffset": 24, "Cdb": 28, "SenseBuf": 44}
all_ok = True
for name, off in expected.items():
    if getattr(op.ScsiPassThrough, name).offset != off:
        all_ok = False
check("field offsets match pshpack4 layout", all_ok)
check("sizeof == 76", ctypes.sizeof(op.ScsiPassThrough) == 76,
      str(ctypes.sizeof(op.ScsiPassThrough)))
s = op.ScsiPassThrough()
s.Length = 76
s.DataIn = 1
s.CdbLength = 10
for i, b in enumerate(bytes([0x28,0,0,0,0,0,0,0x00,0x01,0])):
    s.Cdb[i] = b
raw = ctypes.string_at(ctypes.byref(s), 76)
check("CDB lands at offset 28 (round-trip)", raw[28:38] == bytes([0x28,0,0,0,0,0,0,0x00,0x01,0]))
check("Length/DataIn little-endian", raw[0:2] == (76).to_bytes(2, "little") and raw[8] == 1)

import ctypes.wintypes as wt
class FakeFunc:
    def __init__(self, name): self.name, self.restype, self.argtypes = name, None, None
class FakeKernel32:
    def __init__(self):
        self.CreateFileW = FakeFunc("CreateFileW")
        self.DeviceIoControl = FakeFunc("DeviceIoControl")
fake = FakeKernel32()
op._configure_windows_ctypes(fake)
check("CreateFileW restype = HANDLE", fake.CreateFileW.restype is wt.HANDLE)
check("DeviceIoControl restype = BOOL", fake.DeviceIoControl.restype is wt.BOOL)
check("CreateFileW argtypes complete", fake.CreateFileW.argtypes ==
      [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE])
check("DeviceIoControl argtypes complete (8 args)", len(fake.DeviceIoControl.argtypes) == 8)

print("== doc/feature counts (B6) ==")
check("FEATURE_NAMES == 49 (README claim)", len(op.FEATURE_NAMES) == 49, str(len(op.FEATURE_NAMES)))

print("== probe_device progress callback (GUI support) ==")
op.scsi_execute = lambda path, cdb, alloc, timeout_s: (0x00, b"", b"\x00" * max(alloc, 1), "")
try:
    calls = []
    res = op.probe_device("/dev/fake", 1, False, progress_cb=lambda d, t: calls.append((d, t)))
    check("46 monotonic calls (incl. SKIPPED)", len(calls) == 46 and calls[0] == (1, 46)
          and calls[-1] == (46, 46) and [c[0] for c in calls] == list(range(1, 47)), str(len(calls)))
    check("summary counts add up to 46",
          sum(res["summary"].values()) == 46, str(res["summary"]))
finally:
    op.scsi_execute = orig_exec

print(f"\nRESULT: {passed} passed / {failed} failed")
sys.exit(1 if failed else 0)
