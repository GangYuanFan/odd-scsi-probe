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
check("total 45 opcodes (READ CD moved to block-type matrix)", len(op.CMDS) == 45, str(len(op.CMDS)))
check("15 SPC / 17 MMC / 13 DANGEROUS",
      [sum(1 for c in op.CMDS if c["cat"] == k) for k in ("SPC", "MMC", "DANGEROUS")] == [15, 17, 13])
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

print("== probe_device: 0x12 cache respects INQUIRY failure (Windows finding) ==")
op.scsi_execute = lambda path, cdb, alloc, timeout_s: (0, b"", b"", "CreateFileW failed (2)")
try:
    r = op.probe_device("/dev/fake", 1, False)
    e12 = next(c for c in r["commands"] if c["opcode"] == "0x12")
    check("0x12 NOT reported SUPPORTED when INQUIRY fails",
          e12["result"] == "OTHER" and "CreateFileW" in e12["detail"], str(e12))
finally:
    pass

print("== doc/feature counts (B6) ==")
check("FEATURE_NAMES == 49 (README claim)", len(op.FEATURE_NAMES) == 49, str(len(op.FEATURE_NAMES)))

print("== probe_device progress callback (GUI support) ==")
op.scsi_execute = lambda path, cdb, alloc, timeout_s: (0x00, b"", b"\x00" * max(alloc, 1), "")
try:
    calls = []
    res = op.probe_device("/dev/fake", 1, False, progress_cb=lambda d, t: calls.append((d, t)))
    check("55 monotonic calls (45 opcodes + 10 block types)", len(calls) == 55 and calls[0] == (1, 55)
          and calls[-1] == (55, 55) and [c[0] for c in calls] == list(range(1, 56)), str(len(calls)))
    check("summary counts add up to 55 (block types merged)",
          sum(res["summary"].values()) == 55, str(res["summary"]))
finally:
    op.scsi_execute = orig_exec

print("== READ CD / MMC Table 600 (PM requirement) ==")
check("10 valid block type codes", tuple(op.CD_BLOCK_TYPES) == (0, 1, 2, 3, 8, 9, 10, 11, 12, 13))
check("CD_BLOCK_TYPE_CODES matches table", set(op.CD_BLOCK_TYPE_CODES) == set(op.CD_BLOCK_TYPES))
check("sizes per MMC Table 600", [op.CD_BLOCK_TYPES[c]["size"] for c in (0, 1, 2, 3, 8, 9, 10, 11, 12, 13)] ==
      [2352, 2368, 2448, 2448, 2048, 2336, 2048, 2056, 2324, 2332])
check("mandatory flags (8/10/13 mandatory)", [op.CD_BLOCK_TYPES[c]["mandatory"] for c in (8, 10, 13)] == [True, True, True]
      and op.CD_BLOCK_TYPES[0]["mandatory"] is False)
cdb0 = op._read_cd_cdb(0)
check("READ CD code 0 CDB (byte1=0, byte6=0)", cdb0 == bytes([0xBE, 0, 0, 0, 0, 0, 0x00, 0, 1, 0, 0, 0]), cdb0.hex())
check("READ CD code 8 CDB (byte1=0x20, user data bit)",
      op._read_cd_cdb(8)[1] == 0x20 and op._read_cd_cdb(8)[6] == 0x10)
check("READ CD code 13 CDB (byte1=0x34)", op._read_cd_cdb(13)[1] == 0x34)
bt24 = bytes([0x70, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24, 0x00])
check("block type 0x24 -> type NOT_SUPPORTED",
      op.classify_cd_block_type(0x02, bt24, "")[0] == "NOT_SUPPORTED")
check("block type 0x25 -> type NOT_SUPPORTED",
      op.classify_cd_block_type(0x02, bytes([0x70, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25, 0x00]), "")[0] == "NOT_SUPPORTED")
check("block type 0x20 -> NOT_SUPPORTED (no such command)",
      op.classify_cd_block_type(0x02, bytes([0x70, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x00]), "")[0] == "NOT_SUPPORTED")
check("block type NEEDS_MEDIA kept",
      op.classify_cd_block_type(0x02, bytes([0x70, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3A, 0x00]), "")[0] == "NEEDS_MEDIA")
check("block type GOOD -> SUPPORTED", op.classify_cd_block_type(0x00, b"", "")[0] == "SUPPORTED")

print("== sector size / READ 10 dynamic allocation (PM requirement) ==")
check("name_block_size(None) == unknown", op.name_block_size(None) == "unknown")
check("name_block_size(2352) == '2352 (CD raw)'", op.name_block_size(2352) == "2352 (CD raw)")
check("name_block_size(2048) == '2048'", op.name_block_size(2048) == "2048")
check("READ 10 static alloc >= 512 (min sector)", read10["alloc"] >= 512)
check("TOTAL_PROBE_STEPS == 55 (45 + 10)", op.TOTAL_PROBE_STEPS == 55, str(op.TOTAL_PROBE_STEPS))
check("0xBE not in CMDS (block-type matrix owns READ CD)",
      all(c["op"] != 0xBE for c in op.CMDS))
# CDB/alloc consistency: sector-transfer READ commands must allocate at
# least one full sector; fixed-structure responses (sense, capacities,
# keys) legitimately use small buffers and are not sector-based.
for opc, min_alloc in ((0x28, 512), (0xAD, 2048)):
    cmd = next(c for c in op.CMDS if c["op"] == opc)
    check(f"0x{opc:02X} alloc >= {min_alloc} (sector-sized)", cmd["alloc"] >= min_alloc, str(cmd["alloc"]))
check("READ 10 CDB transfer len = 1 block (bytes 7-8)", read10["cdb"][7:9] == bytes([0x00, 0x01]))
# dynamic alloc: READ CAPACITY block size feeds READ 10 alloc
orig_exec = op.scsi_execute

def make_exec(rc_block_size=None):
    calls = []
    def exec_(path, cdb, alloc, timeout_s):
        calls.append((bytes(cdb), alloc))
        if cdb[0] == 0x25:
            if rc_block_size is None:
                return (0x02, bytes([0x70, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x00]), b"", "")
            return (0x00, b"", (0).to_bytes(4, "big") + rc_block_size.to_bytes(4, "big"), "")
        return (0x00, b"", b"\x00" * max(alloc, 1), "")
    return exec_, calls

try:
    for bs, want, name in ((2352, 2352, "CD raw"), (2048, 2048, "DVD/BD"), (4096, 4096, "odd sector")):
        exec_, calls = make_exec(bs)
        op.scsi_execute = exec_
        r = op.probe_device("/dev/fake", 1, False)
        alloc = next(c for c in calls if c[0][0] == 0x28)[1]
        check(f"READ 10 alloc == block size {bs} ({name})", alloc == want, str(alloc))
        check(f"media_block_size reported ({name})", r["media_block_size"] == bs)
    exec_, calls = make_exec(None)
    op.scsi_execute = exec_
    r = op.probe_device("/dev/fake", 1, False)
    alloc = next(c for c in calls if c[0][0] == 0x28)[1]
    check("READ CAPACITY fail -> READ 10 alloc fallback 2352", alloc == 2352, str(alloc))
    check("no media -> media_block_size unknown", r["media_block_size"] is None
          and r["media_block_size_name"] == "unknown")
    exec_, calls = make_exec(2048)
    op.scsi_execute = exec_
    r = op.probe_device("/dev/fake", 1, False)
    be_calls = [c for c in calls if c[0][0] == 0xBE]
    check("READ CD probed once per valid block type (10)", len(be_calls) == 10, str(len(be_calls)))
    check("per-type alloc matches Table 600 sizes",
          [c[1] for c in be_calls] == [op.CD_BLOCK_TYPES[code]["size"] for code in op.CD_BLOCK_TYPE_CODES])
    check("block_type_matrix reported (10 entries)", len(r["block_type_matrix"]) == 10)
    by_code = {bt["code"]: bt for bt in r["block_type_matrix"]}
    check("block type 0 mandatory=False / 8 mandatory=True",
          by_code[0]["mandatory"] is False and by_code[8]["mandatory"] is True)
    check("per-code CDB byte1 == code<<2 (bits 7-2)",
          all(c[0][1] == (code << 2) & 0xFF
              for c, code in zip(be_calls, op.CD_BLOCK_TYPE_CODES)),
          [hex(c[0][1]) for c in be_calls])
    check("per-code user-data flag: byte6=0x10 for codes >= 8",
          all((c[0][6] == 0x10) == (code >= 8)
              for c, code in zip(be_calls, op.CD_BLOCK_TYPE_CODES)))
    check("block_type_matrix entries carry sense_hex + size",
          all("sense_hex" in bt and bt["size"] == op.CD_BLOCK_TYPES[bt["code"]]["size"]
              for bt in r["block_type_matrix"]))
    check("no 0xBE row in opcode matrix (replaced by block-type loop)",
          all(c["opcode"] != "0xBE" for c in r["commands"]))
finally:
    op.scsi_execute = orig_exec

print(f"\nRESULT: {passed} passed / {failed} failed")
sys.exit(1 if failed else 0)
