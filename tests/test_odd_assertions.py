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
gc[0:2] = (0x14).to_bytes(2, "big")  # Data Length 20 -> total 8+20=28 (matches payload)
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

print("== parse_get_configuration: Data Length truncation (P0-4 belt-and-suspenders) ==")
# Simulate a real Linux response: 28 valid bytes + 64 KB zero padding.
# The Data Length field (bytes 0-1, total = 8 + data_length = 28) must cut
# the padding so no fake 0x0000 features are parsed (the P0-4 pollution bug).
gc_pad = bytes(gc) + b"\x00" * 65500
cur2, profs2, feats2 = op.parse_get_configuration(gc_pad)
check("zero padding dropped (still 3 profiles / 2 features)",
      len(profs2) == 3 and len(feats2) == 2, f"{len(profs2)}/{len(feats2)}")
check("no fake 0x0000 feature rows from padding",
      all(f["code"] != 0 or i == 0 for i, f in enumerate(feats2)) and feats2[0]["code"] == 0x0000,
      str([f["code"] for f in feats2]))
# A truncated response (shorter than Data Length claims) is left untouched.
gc_short = bytes(gc)[:20]
cur3, profs3, feats3 = op.parse_get_configuration(gc_short)
check("short response tolerated (no crash, partial parse)",
      cur3 is not None and isinstance(feats3, list))

print("== scsi_execute resid truncation (P0-4, Linux sg) ==")
real_open, real_close, real_ioctl = op.os.open, op.os.close, op._libc.ioctl
op.os.open = lambda path, flags, *a: 42
op.os.close = lambda fd: None
try:
    for resid, expect in ((4, 16), (0, 20), (-4, 20), (20, 0)):
        holder = {"resid": resid}
        def fake_ioctl(fd, req, arg, _h=holder):
            hdr = ctypes.cast(arg, ctypes.POINTER(op.SgIoHdr)).contents
            if hdr.dxferp:
                ptr = ctypes.cast(hdr.dxferp, ctypes.POINTER(ctypes.c_ubyte))
                for i in range(hdr.dxfer_len):
                    ptr[i] = i & 0xFF
            hdr.status = 0x00
            hdr.resid = _h["resid"]
            hdr.sb_len_wr = 0
            return 0
        op._libc.ioctl = fake_ioctl
        st, se, data, err = op.scsi_execute(
            "/dev/fake", bytes([0x46, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0]), 20, 1)
        check(f"resid={resid} -> {expect} bytes returned (no zero padding)",
              len(data) == expect and err == "", f"got {len(data)} err={err}")
        if expect >= 2:
            check(f"resid={resid} leading bytes preserved",
                  data[0] == 0x00 and data[1] == 0x01, data[:4].hex())
finally:
    op.os.open, op.os.close = real_open, real_close
    op._libc.ioctl = real_ioctl

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
check("alloc == 0 static (runtime override to media block size)", read10["alloc"] == 0)
check("LBA bytes 2-5 == 0", read10["cdb"][2:6] == bytes(4))

print("== command matrix counts / safety flags (v1.2.0 MMC-6 + RSOC) ==")
check("total 69 opcodes (READ CD moved to block-type matrix)", len(op.CMDS) == 69, str(len(op.CMDS)))
check("21 SPC / 24 MMC / 24 DANGEROUS",
      [sum(1 for c in op.CMDS if c["cat"] == k) for k in ("SPC", "MMC", "DANGEROUS")] == [21, 24, 24],
      str([sum(1 for c in op.CMDS if c["cat"] == k) for k in ("SPC", "MMC", "DANGEROUS")]))
check("RSOC entry present (MAINTENANCE IN SA=0x0C)", any(c.get("rsoc") for c in op.CMDS), "missing")
rsoc = next((c for c in op.CMDS if c.get("rsoc")), None)
check("RSOC CDB is 12-byte MAINTENANCE IN 0xA3/0x0C with alloc at bytes 6-7 = 0x1000",
      rsoc is not None and rsoc["cdb"] == bytes([0xA3, 0x0C, 0, 0, 0, 0, 0x10, 0x00, 0, 0, 0, 0])
      and rsoc["cdb"][6:8] == (0x1000).to_bytes(2, "big")
      and rsoc["cdb"][8:10] == bytes(2) and rsoc["alloc"] == 4096,
      str(rsoc))
check("0x35 name covers MMC-2 FLUSH CACHE (ATAPI variant)",
      any("FLUSH CACHE" in c["name"] for c in op.CMDS if c["op"] == 0x35), "0x35 rename missing")
check("full MMC-6 Table 226/227 coverage (48 opcodes, 0xBE via block-type matrix)",
      not (op.MMC6_OPCODES - {c["op"] for c in op.CMDS} - {0xBE}))
check("every command has a legal dir (in/out/none)",
      all(c.get("dir") in ("in", "out", "none") for c in op.CMDS))
check("all 'out' commands carry alloc > 0 or runtime override",
      all(c["alloc"] > 0 or c["op"] in (0x15, 0x2A, 0x2E, 0x55, 0xAA, 0x4D) for c in op.CMDS if c.get("dir") == "out"),
      str([hex(c["op"]) for c in op.CMDS if c.get("dir") == "out" and c["alloc"] == 0]))
check("0xA0 is REPORT LUNS (was wrongly REPORT KEY)",
      next(c for c in op.CMDS if c["op"] == 0xA0)["name"] == "REPORT LUNS")
rl = next(c for c in op.CMDS if c["op"] == 0xA0)
check("0xA0 REPORT LUNS 12-byte CDB with alloc at bytes 6-7 = 0x0010",
      rl["cdb"] == bytes([0xA0, 0, 0, 0, 0, 0, 0x00, 0x10, 0, 0, 0, 0])
      and len(rl["cdb"]) == 12 and rl["cdb"][6:8] == (0x0010).to_bytes(2, "big") and rl["alloc"] == 16,
      rl["cdb"].hex())
check("0xA2 is SECURITY PROTOCOL IN (was wrongly SEND KEY)",
      next(c for c in op.CMDS if c["op"] == 0xA2)["name"] == "SECURITY PROTOCOL IN")
check("0xA3 is MAINTENANCE IN (RSOC, SPC-3 SA=0x0C, 12-byte CDB)",
      next(c for c in op.CMDS if c["op"] == 0xA3)["name"] == "MAINTENANCE IN (RSOC)"
      and next(c for c in op.CMDS if c["op"] == 0xA3)["rsoc"] is True
      and len(next(c for c in op.CMDS if c["op"] == 0xA3)["cdb"]) == 12,
      str(next(c for c in op.CMDS if c["op"] == 0xA3)))
check("12-byte CDBs (A8/AA/AB/BD) have len==12",
      all(len(next(c for c in op.CMDS if c["op"] == opc)["cdb"]) == 12 for opc in (0xA8, 0xAA, 0xAB, 0xBD)))
check("16-byte CDBs (A2/A3/B5/A4) have len==16",
      all(len(next(c for c in op.CMDS if c["op"] == opc)["cdb"]) == 16 for opc in (0xA2, 0xA4, 0xB5)))
for opc in (0xA1, 0x5B, 0x56, 0x04, 0xA6, 0x47, 0x48):
    c = next(c for c in op.CMDS if c["op"] == opc)
    check(f"0x{opc:02X} flagged dangerous (sent for real in --dangerous)", bool(c.get("dangerous")), str(c))
danger = [c for c in op.CMDS if c.get("dangerous")]
check("27 dangerous entries (incl. PLAY AUDIO x3 — full compat per product owner)",
      len(danger) == 27, str(len(danger)))
check("no 'unsafe' flag remains (owner removed never-send policy)",
      all(not c.get("unsafe") for c in op.CMDS))
wb = next(c for c in op.CMDS if c["op"] == 0x3B)
check("WRITE BUFFER uses mode 0x00 (never firmware mode)", wb["cdb"][1] == 0x00)

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
def boom(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
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
op.scsi_execute = lambda path, cdb, alloc, timeout_s, direction="in", out_data=b"": (0, b"", b"", "CreateFileW failed (2)")
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
op.scsi_execute = lambda path, cdb, alloc, timeout_s, direction="in", out_data=b"": (0x00, b"", b"\x00" * max(alloc, 1), "")
try:
    calls = []
    res = op.probe_device("/dev/fake", 1, False, progress_cb=lambda d, t: calls.append((d, t)))
    check("79 monotonic calls (69 opcodes + 10 block types)", len(calls) == 79 and calls[0] == (1, 79)
          and calls[-1] == (79, 79) and [c[0] for c in calls] == list(range(1, 80)), str(len(calls)))
    check("summary counts add up to 79 (block types merged)",
          sum(res["summary"].values()) == 79, str(res["summary"]))
    check("RSOC probe populates rsoc_opcodes from SUPPORTED 0xA3",
          isinstance(res.get("rsoc_opcodes"), list), str(type(res.get("rsoc_opcodes"))))
finally:
    op.scsi_execute = orig_exec

print("== parse_rsoc (SPC-3 REPORT SUPPORTED OPERATION CODES) ==")
fake = b"\x00\x10\x00\x00" + bytes([0x12]) + b"\x00" * 7 + bytes([0xA3]) + b"\x00" * 7 + bytes([0x25]) + b"\x00" * 7
check("parse_rsoc extracts 0x12/0x25/0xA3 descriptors",
      op.parse_rsoc(fake) == [0x12, 0x25, 0xA3], str(op.parse_rsoc(fake)))
check("parse_rsoc tolerates short data", op.parse_rsoc(b"\x00\x00") == [], str(op.parse_rsoc(b"\x00\x00")))

print("== READ CD / MMC-6 Table 352 (PM requirement) ==")
check("10 matrix rows keyed 1..10", tuple(op.CD_BLOCK_TYPES) == (1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
check("CD_BLOCK_TYPE_CODES matches table", set(op.CD_BLOCK_TYPE_CODES) == set(op.CD_BLOCK_TYPES))
check("sizes per Table 352 rows", [op.CD_BLOCK_TYPES[c]["size"] for c in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)] ==
      [2352, 2368, 2448, 2448, 2048, 2336, 2048, 2056, 2324, 2332])
check("mandatory EST set per Table 352 (rows 1/5/7/9)",
      [op.CD_BLOCK_TYPES[c]["mandatory"] for c in (1, 5, 7, 9)] == [True, True, True, True]
      and [op.CD_BLOCK_TYPES[c]["mandatory"] for c in (2, 3, 4, 6, 8, 10)] == [False] * 6)
# Byte-exact golden vectors: [0xBE, EST<<2, LBA(4), TL(3)=0x000001, flags, subch, ctrl]
CD_GOLDEN = {
    1: bytes([0xBE, 0x00, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0xF8, 0x00, 0]),
    2: bytes([0xBE, 0x00, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0xF8, 0x01, 0]),
    3: bytes([0xBE, 0x00, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0xF8, 0x02, 0]),
    4: bytes([0xBE, 0x00, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0xF8, 0x03, 0]),
    5: bytes([0xBE, 0x08, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x10, 0x00, 0]),
    6: bytes([0xBE, 0x0C, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x10, 0x00, 0]),
    7: bytes([0xBE, 0x10, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x10, 0x00, 0]),
    8: bytes([0xBE, 0x10, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x50, 0x00, 0]),
    9: bytes([0xBE, 0x14, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x10, 0x00, 0]),
    10: bytes([0xBE, 0x14, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x50, 0x00, 0]),
}
check("all 10 READ CD CDBs byte-exact (golden vectors)",
      all(op._read_cd_cdb(code) == want for code, want in CD_GOLDEN.items()),
      "mismatch: " + str([hex(op._read_cd_cdb(c)[1]) for c in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)]))
check("row 5 (Mode 1) CDB (byte1=0x08, byte9=0x10 user data)",
      op._read_cd_cdb(5)[1] == 0x08 and op._read_cd_cdb(5)[9] == 0x10)
check("row 10 (form 2 + sub-header) CDB (byte1=0x14, byte9=0x50)",
      op._read_cd_cdb(10)[1] == 0x14 and op._read_cd_cdb(10)[9] == 0x50)
check("row 3 (P-W pack) CDB (byte9=0xF8, byte10=0x02)",
      op._read_cd_cdb(3)[9] == 0xF8 and op._read_cd_cdb(3)[10] == 0x02)
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
check("READ 10 static alloc is 0 (runtime override)", read10["alloc"] == 0)
check("TOTAL_PROBE_STEPS == 79 (69 + 10)", op.TOTAL_PROBE_STEPS == 79, str(op.TOTAL_PROBE_STEPS))
check("0xBE not in CMDS (block-type matrix owns READ CD)",
      all(c["op"] != 0xBE for c in op.CMDS))
# CDB/alloc consistency: sector-transfer READ commands must allocate at
# least one full sector; fixed-structure responses (sense, capacities,
# keys) legitimately use small buffers and are not sector-based.
for opc, min_alloc in ((0xAD, 2048),):
    cmd = next(c for c in op.CMDS if c["op"] == opc)
    check(f"0x{opc:02X} alloc >= {min_alloc} (sector-sized)", cmd["alloc"] >= min_alloc, str(cmd["alloc"]))
check("READ 10 CDB transfer len = 1 block (bytes 7-8)", read10["cdb"][7:9] == bytes([0x00, 0x01]))
# dynamic alloc: READ CAPACITY block size feeds READ 10 alloc
orig_exec = op.scsi_execute

def make_exec(rc_block_size=None):
    calls = []
    def exec_(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        calls.append((bytes(cdb), alloc, direction))
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
    check("row 1 (raw) mandatory=True / row 2 (P&Q) mandatory=False",
          by_code[1]["mandatory"] is True and by_code[2]["mandatory"] is False)
    check("per-code CDB byte1 == EST<<2 (Table 352)",
          all(c[0][1] == (op.CD_BLOCK_TYPES[code]["est"] << 2) & 0xFF
              for c, code in zip(be_calls, op.CD_BLOCK_TYPE_CODES)),
          [hex(c[0][1]) for c in be_calls])
    check("per-code CDB byte9/byte10 == flags/subch (kernel cdrom_read_block layout)",
          all(c[0][9] == op.CD_BLOCK_TYPES[code]["flags"] and c[0][10] == op.CD_BLOCK_TYPES[code]["subch"]
              for c, code in zip(be_calls, op.CD_BLOCK_TYPE_CODES)))
    check("per-code CDB transfer length bytes 6-8 == 0x000001 (1 block)",
          all(c[0][6:9] == bytes([0x00, 0x00, 0x01]) for c, _ in zip(be_calls, op.CD_BLOCK_TYPE_CODES)))
    check("block_type_matrix entries carry sense_hex + size",
          all("sense_hex" in bt and bt["size"] == op.CD_BLOCK_TYPES[bt["code"]]["size"]
              for bt in r["block_type_matrix"]))
    check("no 0xBE row in opcode matrix (replaced by block-type loop)",
          all(c["opcode"] != "0xBE" for c in r["commands"]))
finally:
    op.scsi_execute = orig_exec

print("== full-compat mode (--dangerous, product-owner requirement) ==")
blank = next(c for c in op.CMDS if c["op"] == 0xA1)
check("BLANK CDB real params (byte1 Immed=1 + blank type 000b == 0x10)", blank["cdb"][1] == 0x10,
      blank["cdb"].hex())
funit = next(c for c in op.CMDS if c["op"] == 0x04)
check("FORMAT UNIT CDB FMTDATA=1 (byte1 == 0x11)", funit["cdb"][1] == 0x11, funit["cdb"].hex())
check("FORMAT UNIT out-data 12 bytes + dir out", funit["dir"] == "out" and funit["alloc"] == 12)
loadu = next(c for c in op.CMDS if c["op"] == 0xA6)
check("LOAD/UNLOAD CDB real params (Immed=1, LoUnlo=1 -> bytes 1,4 == 0x01,0x02)",
      loadu["cdb"][1] == 0x01 and loadu["cdb"][4] == 0x02, loadu["cdb"].hex())
close = next(c for c in op.CMDS if c["op"] == 0x5B)
check("CLOSE TRACK/SESSION CDB (Immed=1, close session 010b)",
      close["cdb"][1] == 0x01 and close["cdb"][2] == 0x02, close["cdb"].hex())

# safe mode: destructive commands SKIPPED; full-compat: sent for real
orig_exec = op.scsi_execute
def fc_exec(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
    if cdb[0] == 0x25:
        return (0x00, b"", (0).to_bytes(4, "big") + (2048).to_bytes(4, "big"), "")
    return (0x00, b"", b"\x00" * max(alloc, 1), "")
try:
    op.scsi_execute = fc_exec
    rs = op.probe_device("/dev/fake", 1, False)
    check("safe mode: BLANK SKIPPED with hint",
          next(c for c in rs["commands"] if c["opcode"] == "0xA1")["result"] == "SKIPPED")
    check("safe mode: mode == 'safe'", rs["mode"] == "safe")
    rf = op.probe_device("/dev/fake", 1, True)
    check("full-compat: BLANK sent (result != SKIPPED)",
          next(c for c in rf["commands"] if c["opcode"] == "0xA1")["result"] != "SKIPPED")
    check("full-compat: FORMAT UNIT sent",
          next(c for c in rf["commands"] if c["opcode"] == "0x04")["result"] != "SKIPPED")
    check("full-compat: LOAD/UNLOAD sent",
          next(c for c in rf["commands"] if c["opcode"] == "0xA6")["result"] != "SKIPPED")
    check("full-compat: mode == 'full-compat'", rf["mode"] == "full-compat")
    check("full-compat: BLANK detail carries danger_note",
          "erases entire disc" in next(c for c in rf["commands"] if c["opcode"] == "0xA1")["detail"])
    check("safe mode summary: SKIPPED >= 19 (dangerous set)",
          rs["summary"]["SKIPPED"] >= 19, str(rs["summary"]["SKIPPED"]))
finally:
    op.scsi_execute = orig_exec

print(f"\nRESULT: {passed} passed / {failed} failed")
sys.exit(1 if failed else 0)
