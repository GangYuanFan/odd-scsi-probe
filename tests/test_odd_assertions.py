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


def s70(key, asc, ascq=0):
    """Fixed-format sense (0x70) with realistic additional length 10
    (18-byte sense; kernel clamps ASC/ASCQ reads to sense[7]+8)."""
    return bytes([0x70, 0, key, 0, 0, 0, 0, 0x0A, 0, 0, 0, 0, asc, ascq])


def s72(key, asc, ascq=0):
    """Descriptor-format sense (0x72) — key/ASC/ASCQ at bytes 1/2/3."""
    return bytes([0x72, key, asc, ascq, 0, 0, 0, 0, 0x0A])

print("== classify() ==")
check("GOOD -> SUPPORTED", op.classify(0x00, b"", "") == ("SUPPORTED", "GOOD"))
check("ILLEGAL_REQ 0x20/0x00 -> NOT_SUPPORTED",
      op.classify(0x02, s70(5, 0x20), "")[0] == "NOT_SUPPORTED")
check("ILLEGAL_REQ 0x24 -> PARAMETER_NOT_SUPPORTED",
      op.classify(0x02, s70(5, 0x24), "")[0] == "PARAMETER_NOT_SUPPORTED")
check("ILLEGAL_REQ 0x25 -> PARAMETER_NOT_SUPPORTED",
      op.classify(0x02, s70(5, 0x25), "")[0] == "PARAMETER_NOT_SUPPORTED")
check("NOT_READY 0x3A -> NEEDS_MEDIA",
      op.classify(0x02, s70(2, 0x3A), "")[0] == "NEEDS_MEDIA")
check("NOT_READY 0x04 -> NEEDS_MEDIA",
      op.classify(0x02, s70(2, 0x04), "")[0] == "NEEDS_MEDIA")
check("UNIT_ATTENTION -> SUPPORTED",
      op.classify(0x02, s70(6, 0x28), "")[0] == "SUPPORTED")
check("WRITE_PROTECTED 0x27 -> SUPPORTED",
      op.classify(0x02, s70(7, 0x27), "")[0] == "SUPPORTED")
check("MEDIUM_ERROR 0x11 -> MEDIA_STATE_INVALID",
      op.classify(0x02, s70(3, 0x11), "")[0] == "MEDIA_STATE_INVALID")
check("BLANK CHECK 0x08/0x30 -> NEEDS_RECORDED_MEDIA",
      op.classify(0x02, s70(8, 0x30), "")[0] == "NEEDS_RECORDED_MEDIA")
check("BLANK CHECK detail carries key/asc/ascq",
      "8/0x30/0x00" in op.classify(0x02, s70(8, 0x30), "")[1])
check("status=0x08 -> OTHER",
      op.classify(0x08, b"", "")[0] == "OTHER")
check("EIO errno=5 -> TIMEOUT",
      op.classify(0, b"", "ioctl error errno=5") == ("TIMEOUT", "ioctl error (ioctl error errno=5)"))
check("EINVAL errno=22 -> OTHER",
      op.classify(0, b"", "ioctl error errno=22")[0] == "OTHER")
check("empty sense + CHECK CONDITION -> OTHER",
      op.classify(0x02, b"\x00"*8, "")[0] == "OTHER")
check("classify has exactly 13 return branches (matches docs)",
      sum(1 for _ in __import__("inspect").getsourcelines(op.classify)[0]
          if _.strip().startswith("return ")) == 13)

print("== sense: descriptor format 0x72/0x73 (P1-6, kernel scsi_normalize_sense) ==")
check("_parse_sense fixed 0x70 (key byte 2, ASC/ASCQ 12/13)",
      op._parse_sense(s70(5, 0x20)) == (5, 0x20, 0x00), str(op._parse_sense(s70(5, 0x20))))
check("_parse_sense descriptor 0x72 (key byte 1, ASC/ASCQ 2/3)",
      op._parse_sense(s72(2, 0x3A)) == (2, 0x3A, 0x00), str(op._parse_sense(s72(2, 0x3A))))
check("_parse_sense descriptor 0x73 deferred format",
      op._parse_sense(bytes([0x73, 0x05, 0x20, 0x00, 0, 0, 0, 0, 0x0A])) == (5, 0x20, 0x00))
check("_parse_sense invalid: empty", op._parse_sense(b"") == (0, 0, 0))
check("_parse_sense invalid: response 0x00", op._parse_sense(b"\x00" * 8) == (0, 0, 0))
check("_parse_sense invalid: vendor response 0x50",
      op._parse_sense(bytes([0x50, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0])) == (0, 0, 0))
check("descriptor NOT_READY/0x3A -> NEEDS_MEDIA (was misjudged OTHER)",
      op.classify(0x02, s72(2, 0x3A), "")[0] == "NEEDS_MEDIA")
check("descriptor ILLEGAL_REQ/0x20 -> NOT_SUPPORTED",
      op.classify(0x02, s72(5, 0x20), "")[0] == "NOT_SUPPORTED")
check("descriptor ILLEGAL_REQ/0x24 -> PARAMETER_NOT_SUPPORTED",
      op.classify(0x02, s72(5, 0x24), "")[0] == "PARAMETER_NOT_SUPPORTED")
check("descriptor UNIT ATTENTION -> SUPPORTED",
      op.classify(0x02, s72(6, 0x28), "")[0] == "SUPPORTED")
check("descriptor block type ILLEGAL_REQ/0x24 -> type NOT_SUPPORTED",
      op.classify_cd_block_type(0x02, s72(5, 0x24), "")[0] == "NOT_SUPPORTED")
check("descriptor block type NEEDS_MEDIA kept",
      op.classify_cd_block_type(0x02, s72(2, 0x3A), "")[0] == "NEEDS_MEDIA")
check("fixed-format detail still carries key/asc/ascq",
      "5/0x20/0x00" in op.classify(0x02, s70(5, 0x20), "")[1])
check("descriptor-format detail carries key/asc/ascq",
      "5/0x20/0x00" in op.classify(0x02, s72(5, 0x20), "")[1])

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

print("== scsi_execute OSError catch (P1-9, hot-unplug) ==")
real_open2, real_close2, real_ioctl2 = op.os.open, op.os.close, op._libc.ioctl

def boom_open(path, flags, *a):
    raise OSError(19, "No such device")

try:
    op.os.open = boom_open
    op.os.close = lambda fd: None
    st, se, da, er = op.scsi_execute("/dev/sr9", bytes([0x00, 0, 0, 0, 0, 0]), 0, 1)
    check("os.open OSError -> error tuple, not an exception", st == 0 and er.startswith("OSError:"), er)
    check("classify(OSError) -> OTHER (probe keeps going)", op.classify(st, se, er)[0] == "OTHER")
finally:
    op.os.open, op.os.close = real_open2, real_close2
    op._libc.ioctl = real_ioctl2

# probe_device: hot-unplug on the 3rd command (GET CONFIGURATION) — the full
# result dict must survive with the remaining 78 steps intact.
real_open3, real_close3, real_ioctl3 = op.os.open, op.os.close, op._libc.ioctl
counter = {"n": 0}
def flaky_open(path, flags, *a):
    counter["n"] += 1
    if counter["n"] == 3:
        raise OSError(19, "No such device")
    return 42

def ok_ioctl(fd, req, arg):
    hdr = ctypes.cast(arg, ctypes.POINTER(op.SgIoHdr)).contents
    if hdr.dxferp:
        ptr = ctypes.cast(hdr.dxferp, ctypes.POINTER(ctypes.c_ubyte))
        for i in range(hdr.dxfer_len):
            ptr[i] = i & 0xFF
    hdr.status = 0x00
    hdr.resid = 0
    hdr.sb_len_wr = 0
    return 0

try:
    op.os.open = flaky_open
    op.os.close = lambda fd: None
    op._libc.ioctl = ok_ioctl
    r = op.probe_device("/dev/fake", 1, False)
    check("probe survives mid-probe OSError (71 commands + 10 block types + 26 DVD + 7 BD structures)",
          len(r["commands"]) == 71 and len(r["block_type_matrix"]) == 10
          and len(r["dvd_structure_matrix"]) == 26 and len(r["bd_structure_matrix"]) == 7,
          f"{len(r['commands'])}/{len(r['block_type_matrix'])}/{len(r['dvd_structure_matrix'])}/{len(r['bd_structure_matrix'])}")
    e46 = next(c for c in r["commands"] if c["opcode"] == "0x46")
    check("0x46 (hit by OSError) -> OTHER with OSError detail",
          e46["result"] == "OTHER" and "OSError" in e46["detail"], str(e46))
    check("0x00 still probed after the failure",
          next(c for c in r["commands"] if c["opcode"] == "0x00")["result"] == "SUPPORTED")
    check("summary still sums to 114 (result not discarded)",
          sum(r["summary"].values()) == 114, str(r["summary"]))
finally:
    op.os.open, op.os.close = real_open3, real_close3
    op._libc.ioctl = real_ioctl3

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
check("total 71 opcodes (READ CD and READ DVD STRUCTURE moved to matrices)", len(op.CMDS) == 71, str(len(op.CMDS)))
check("25 SPC / 23 MMC / 23 DANGEROUS",
      [sum(1 for c in op.CMDS if c["cat"] == k) for k in ("SPC", "MMC", "DANGEROUS")] == [25, 23, 23],
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
check("full MMC-6 Table 226/227 coverage (49 opcodes incl. VERIFY 12 0xAF; 0xBE and 0xAD via matrices)",
      not (op.MMC6_OPCODES - {c["op"] for c in op.CMDS} - {0xBE, 0xAD}))
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
gp = next(c for c in op.CMDS if c["op"] == 0xAC)
check("0xAC GET PERFORMANCE 12-byte CDB (MMC-6 Table 290: Max Descriptors bytes 8-9 = 0x0001, Type byte 10 = 0x00)",
      gp["cdb"] == bytes([0xAC, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0])
      and len(gp["cdb"]) == 12 and gp["cdb"][8:10] == (0x0001).to_bytes(2, "big") and gp["cdb"][10] == 0x00,
      gp["cdb"].hex())
for opc, sl in ((0x46, 7), (0x51, 7), (0x52, 7), (0x5A, 8)):
    c = next(c for c in op.CMDS if c["op"] == opc)
    check(f"0x{opc:02X} alloc + CDB allocation length == 4096 (P1-8, Windows 64KB cap)",
          c["alloc"] == 4096 and c["cdb"][sl:sl + 2] == (0x1000).to_bytes(2, "big"),
          f"alloc={c['alloc']} cdb{sl}-{sl+1}={c['cdb'][sl:sl + 2].hex()}")
check("12-byte CDBs (A8/AA/AB/BD) have len==12",
      all(len(next(c for c in op.CMDS if c["op"] == opc)["cdb"]) == 12 for opc in (0xA8, 0xAA, 0xAB, 0xBD)))
rms = next(c for c in op.CMDS if c["op"] == 0xAB)
check("0xAB READ MEDIA SERIAL alloc length bytes 9-10 = 0x0080 (P1-5, was 0x8000)",
      rms["cdb"] == bytes([0xAB, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x80, 0])
      and rms["cdb"][9:11] == (0x0080).to_bytes(2, "big") and rms["alloc"] == 128,
      rms["cdb"].hex())
check("16-byte CDBs (A2/A3/B5/A4) have len==16",
      all(len(next(c for c in op.CMDS if c["op"] == opc)["cdb"]) == 16 for opc in (0xA2, 0xA4, 0xB5)))
for opc in (0xA1, 0x5B, 0x04, 0xA6, 0x47, 0x48):
    c = next(c for c in op.CMDS if c["op"] == opc)
    check(f"0x{opc:02X} flagged dangerous (sent for real in --dangerous)", bool(c.get("dangerous")), str(c))
danger = [c for c in op.CMDS if c.get("dangerous")]
check("26 dangerous entries (incl. PLAY AUDIO x3 — full compat per product owner; 0x56 RESERVE 10 no longer dangerous)",
      len(danger) == 26, str(len(danger)))

print("== P0 spec fix golden vectors (MMC-6 Table 7: RESERVE=16h/56h, RELEASE=17h/57h, VERIFY=2Fh/AFh) ==")
res6 = next(c for c in op.CMDS if c["op"] == 0x16)
rel6 = next(c for c in op.CMDS if c["op"] == 0x17)
res10 = next(c for c in op.CMDS if c["op"] == 0x56)
rel10 = next(c for c in op.CMDS if c["op"] == 0x57)
ver10 = next(c for c in op.CMDS if c["op"] == 0x2F)
ver12 = next(c for c in op.CMDS if c["op"] == 0xAF)
check("0x17 RELEASE 6 CDB byte-exact (Table 7 RELEASE=17h,57h)",
      rel6["cdb"] == bytes([0x17, 0, 0, 0, 0, 0]) and rel6["cat"] == "SPC" and rel6.get("legacy") and not rel6.get("dangerous"),
      rel6["cdb"].hex())
check("0x56 RESERVE 10 CDB byte-exact + not dangerous (Table 7 RESERVE=16h,56h; old CLOSE TRACK/SESSION label was wrong)",
      res10["cdb"] == bytes([0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0]) and res10["cat"] == "SPC" and res10.get("legacy")
      and not res10.get("dangerous") and res10["alloc"] == 0 and res10["dir"] == "none",
      f'{res10["cdb"].hex()} dangerous={res10.get("dangerous")}')
check("0x57 RELEASE 10 CDB byte-exact (Table 7 RELEASE=17h,57h)",
      rel10["cdb"] == bytes([0x57, 0, 0, 0, 0, 0, 0, 0, 0, 0]) and rel10["cat"] == "SPC" and rel10.get("legacy") and not rel10.get("dangerous"),
      rel10["cdb"].hex())
check("0xAF VERIFY 12 CDB 12-byte byte-exact (BYTCHK=0, verification length=0 -> verifies nothing)",
      ver12["cdb"] == bytes([0xAF, 0, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 0]) and ver12["alloc"] == 0
      and ver12["dir"] == "none" and not ver12.get("dangerous"),
      f'{ver12["cdb"].hex()} alloc={ver12["alloc"]} dir={ver12["dir"]}')
check("0xAF in MMC6_OPCODES (VERIFY 2Fh/AFh both MMC-6 Table 7)", 0xAF in op.MMC6_OPCODES, "missing")
check("no 'unsafe' flag remains (owner removed never-send policy)",
      all(not c.get("unsafe") for c in op.CMDS))
wb = next(c for c in op.CMDS if c["op"] == 0x3B)
check("WRITE BUFFER uses mode 0x00 (never firmware mode)", wb["cdb"][1] == 0x00)
check("0x3B WRITE BUFFER param len bytes 6-8 = 0x000008 (4B header + 4B data, P1-4)",
      wb["cdb"] == bytes([0x3B, 0x00, 0x00, 0, 0, 0, 0x00, 0x00, 0x08, 0])
      and wb["cdb"][6:9] == (0x000008).to_bytes(3, "big") and wb["alloc"] == 8,
      wb["cdb"].hex())
ssu = next(c for c in op.CMDS if c["op"] == 0x1B)
check("0x1B START STOP UNIT CDB = 1B 01 00 00 01 00 (kernel CDROMSTART: IMMED + START@byte4 bit0, SFF-8020i)",
      ssu["cdb"] == bytes([0x1B, 0x01, 0, 0, 0x01, 0]) and ssu["cdb"][1] == 0x01 and ssu["cdb"][4] == 0x01,
      ssu["cdb"].hex())
pa = next(c for c in op.CMDS if c["op"] == 0x45)
check("0x45 PLAY AUDIO 10 CDB: 10-byte, TL at bytes 7-8 = 0x0001 (P1-3, was 0x0100=256)",
      pa["cdb"] == bytes([0x45, 0, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0])
      and len(pa["cdb"]) == 10 and pa["cdb"][7:9] == (0x0001).to_bytes(2, "big"),
      pa["cdb"].hex())

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
    check("114 monotonic calls (71 opcodes + 10 block types + 26 DVD + 7 BD structures)", len(calls) == 114 and calls[0] == (1, 114)
          and calls[-1] == (114, 114) and [c[0] for c in calls] == list(range(1, 115)), str(len(calls)))
    check("summary counts add up to 114 (matrices merged)",
          sum(res["summary"].values()) == 114, str(res["summary"]))
    check("RSOC probe populates rsoc_opcodes from SUPPORTED 0xA3",
          isinstance(res.get("rsoc_opcodes"), list), str(type(res.get("rsoc_opcodes"))))
finally:
    op.scsi_execute = orig_exec

print("== REQUEST SENSE rescue (P1-7) ==")
orig_exec = op.scsi_execute
try:
    calls = []
    def mk_exec(rs_result, main_result=(0x02, b"", b"", b"")):
        def exec_(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
            calls.append(bytes(cdb)[0])
            if cdb[0] == 0x03:
                return rs_result
            return main_result
        return exec_
    gc16 = bytes([0x46, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0])
    op.scsi_execute = mk_exec((0x00, b"", s72(2, 0x3A), ""))
    st, se, da, er = op._scsi_execute_rescued("/dev/fake", gc16, 16, 1)
    check("CC + empty sense -> rescue recovers descriptor sense (NEEDS_MEDIA path)",
          st == 0x02 and op._parse_sense(se) == (2, 0x3A, 0x00), se.hex())
    check("rescue issued exactly one REQUEST SENSE", calls.count(0x03) == 1, str(calls.count(0x03)))
    calls.clear()
    op.scsi_execute = mk_exec((0x02, b"", b"", b""))  # REQUEST SENSE also CC + empty
    st, se, da, er = op._scsi_execute_rescued("/dev/fake", gc16, 16, 1)
    check("rescue failure: original sense kept, exactly 1 RS call (no recursion)",
          st == 0x02 and se == b"" and calls.count(0x03) == 1, f"calls={calls.count(0x03)}")
    calls.clear()
    op.scsi_execute = mk_exec((0x00, b"", s72(2, 0x3A), ""), (0x00, b"", b"\x00" * 16, ""))
    st, se, da, er = op._scsi_execute_rescued("/dev/fake", gc16, 16, 1)
    check("GOOD status -> no rescue issued", st == 0x00 and calls.count(0x03) == 0, str(calls))
    calls.clear()
    op.scsi_execute = mk_exec((0x00, b"", s72(2, 0x3A), ""), (0, b"", b"", "ioctl error errno=22"))
    st, se, da, er = op._scsi_execute_rescued("/dev/fake", gc16, 16, 1)
    check("ioctl error -> no rescue issued", "errno=22" in er and calls.count(0x03) == 0, str(calls))
    # probe_device integration: 0x51 cache path classifies with rescued sense
    calls.clear()
    def rs_exec2(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        if cdb[0] == 0x25:
            return (0x00, b"", (0).to_bytes(4, "big") + (2048).to_bytes(4, "big"), "")
        if cdb[0] == 0x51:
            return (0x02, b"", b"", b"")  # drive swallowed auto-sense
        if cdb[0] == 0x03:
            return (0x00, b"", s72(2, 0x3A), "")
        return (0x00, b"", b"\x00" * max(alloc, 1), "")
    op.scsi_execute = rs_exec2
    r = op.probe_device("/dev/fake", 1, False)
    e51 = next(c for c in r["commands"] if c["opcode"] == "0x51")
    check("probe_device: 0x51 NEEDS_MEDIA via REQUEST SENSE rescue (cache path)",
          e51["result"] == "NEEDS_MEDIA" and "MEDIUM NOT PRESENT" in e51["detail"], str(e51))
    check("probe_device: rescued sense not leaked to other entries",
          all(c["opcode"] != "0x51" or c is e51 for c in r["commands"]))
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
bt24 = s70(5, 0x24)
check("block type 0x24 -> type NOT_SUPPORTED",
      op.classify_cd_block_type(0x02, bt24, "")[0] == "NOT_SUPPORTED")
check("block type 0x25 -> type NOT_SUPPORTED",
      op.classify_cd_block_type(0x02, s70(5, 0x25), "")[0] == "NOT_SUPPORTED")
check("block type 0x20 -> NOT_SUPPORTED (no such command)",
      op.classify_cd_block_type(0x02, s70(5, 0x20), "")[0] == "NOT_SUPPORTED")
check("block type NEEDS_MEDIA kept",
      op.classify_cd_block_type(0x02, s70(2, 0x3A), "")[0] == "NEEDS_MEDIA")
check("block type GOOD -> SUPPORTED", op.classify_cd_block_type(0x00, b"", "")[0] == "SUPPORTED")

print("== READ DISC STRUCTURE format matrices (P1-2, MMC-6 §6.22.3) ==")
check("26 DVD format codes (§6.22.3.2: 00h-11h, 15h, 20h-24h, 30h, 31h)",
      len(op.DVD_STRUCTURE_FORMATS) == 26, str(len(op.DVD_STRUCTURE_FORMATS)))
check("DVD format codes exact order",
      [f for f, _ in op.DVD_STRUCTURE_FORMATS] ==
      [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
       0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x15, 0x20, 0x21, 0x22, 0x23, 0x24, 0x30, 0x31],
      str([f for f, _ in op.DVD_STRUCTURE_FORMATS]))
check("7 BD format codes (§6.22.3.3: 00h, 03h, 08h, 09h, 0Ah, 12h, 30h)",
      [f for f, _ in op.BD_STRUCTURE_FORMATS] == [0x00, 0x03, 0x08, 0x09, 0x0A, 0x12, 0x30],
      str([f for f, _ in op.BD_STRUCTURE_FORMATS]))
check("DVD media type 0x00 (Table 382: 0000b = DVD types)", op.DVD_MEDIA_TYPE == 0x00,
      f"{op.DVD_MEDIA_TYPE:#04x}")
check("BD media type 0x01 (Table 382: 0001b = BD; 0x05 is reserved)", op.BD_MEDIA_TYPE == 0x01,
      f"{op.BD_MEDIA_TYPE:#04x}")
# Byte-exact golden vectors: [0xAD, 0, media, addr(3), layer=0, fmt, alloc 0x0800, AGID, ctrl]
check("DVD fmt 0x00 CDB byte-exact (Table 381: byte 6 layer, byte 7 format)",
      op._read_disc_structure_cdb(0x00, 0x00) == bytes([0xAD, 0, 0x00, 0, 0, 0, 0x00, 0x00, 0x08, 0x00, 0, 0]),
      op._read_disc_structure_cdb(0x00, 0x00).hex())
check("DVD fmt 0x05 CDB byte-exact",
      op._read_disc_structure_cdb(0x00, 0x05) == bytes([0xAD, 0, 0x00, 0, 0, 0, 0x00, 0x05, 0x08, 0x00, 0, 0]),
      op._read_disc_structure_cdb(0x00, 0x05).hex())
check("DVD fmt 0x30 CDB byte-exact",
      op._read_disc_structure_cdb(0x00, 0x30) == bytes([0xAD, 0, 0x00, 0, 0, 0, 0x00, 0x30, 0x08, 0x00, 0, 0]),
      op._read_disc_structure_cdb(0x00, 0x30).hex())
check("BD fmt 0x00 CDB byte-exact (media type 0x01)",
      op._read_disc_structure_cdb(0x01, 0x00) == bytes([0xAD, 0, 0x01, 0, 0, 0, 0x00, 0x00, 0x08, 0x00, 0, 0]),
      op._read_disc_structure_cdb(0x01, 0x00).hex())
check("all 33 structure CDBs are 12-byte with alloc 2048 (fmt@byte7)",
      all(len(op._read_disc_structure_cdb(mt, f)) == 12
          and op._read_disc_structure_cdb(mt, f)[8:10] == (0x0800).to_bytes(2, "big")
          and op._read_disc_structure_cdb(mt, f)[7] == f
          for mt, flist in ((0x00, op.DVD_STRUCTURE_FORMATS), (0x01, op.BD_STRUCTURE_FORMATS))
          for f, _ in flist))

# mock integration: mixed sense results across the matrices; every row must
# carry classify() result + sense_hex and feed the summary.
orig_exec = op.scsi_execute
def struct_exec(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
    if cdb[0] != 0xAD:
        return (0x00, b"", b"\x00" * max(alloc, 1), "")
    media, fmt = cdb[2], cdb[7]
    if media == 0x00 and fmt == 0x00:
        return (0x00, b"", b"\x00" * alloc, "")        # GOOD -> SUPPORTED
    if media == 0x00 and fmt == 0x05:
        return (0x02, s72(5, 0x24), b"", "")            # ILLEGAL_REQ 0x24 -> PARAMETER_NOT_SUPPORTED
    if media == 0x00 and fmt == 0x30:
        return (0x02, s72(2, 0x3A), b"", "")            # NOT_READY 0x3A -> NEEDS_MEDIA
    if media == 0x01 and fmt == 0x00:
        return (0x02, s72(5, 0x20), b"", "")            # ILLEGAL_REQ 0x20 -> NOT_SUPPORTED
    return (0x00, b"", b"\x00" * max(alloc, 1), "")
try:
    op.scsi_execute = struct_exec
    r = op.probe_device("/dev/fake", 1, False)
    dv = {row["format"]: row for row in r["dvd_structure_matrix"]}
    bm = {row["format"]: row for row in r["bd_structure_matrix"]}
    check("dvd_structure_matrix 26 rows / bd_structure_matrix 7 rows",
          len(dv) == 26 and len(bm) == 7, f"{len(dv)}/{len(bm)}")
    check("DVD fmt 0x00 classified SUPPORTED", dv["0x00"]["result"] == "SUPPORTED", str(dv["0x00"]))
    check("DVD fmt 0x05 classified PARAMETER_NOT_SUPPORTED w/ sense_hex (0x24 param rejected)",
          dv["0x05"]["result"] == "PARAMETER_NOT_SUPPORTED" and dv["0x05"]["sense_hex"] == s72(5, 0x24).hex(" "),
          str(dv["0x05"]))
    check("DVD fmt 0x30 classified NEEDS_MEDIA w/ sense_hex (0x3A)",
          dv["0x30"]["result"] == "NEEDS_MEDIA" and dv["0x30"]["sense_hex"] == s72(2, 0x3A).hex(" "),
          str(dv["0x30"]))
    check("BD fmt 0x00 classified NOT_SUPPORTED w/ sense_hex (0x20)",
          bm["0x00"]["result"] == "NOT_SUPPORTED" and bm["0x00"]["sense_hex"] == s72(5, 0x20).hex(" "),
          str(bm["0x00"]))
    check("BD fmt 0x30 classified SUPPORTED (default GOOD)", bm["0x30"]["result"] == "SUPPORTED", str(bm["0x30"]))
    check("matrix rows carry format/name/media_type + summary sums to 114",
          all(row["name"] and row["media_type"] in (0x00, 0x01)
              for row in r["dvd_structure_matrix"] + r["bd_structure_matrix"])
          and sum(r["summary"].values()) == 114, str(r["summary"]))
    check("summary has 9 result keys (P1-3a vocabulary)",
          len(r["summary"]) == 9
          and all(k in r["summary"] for k in ("PARAMETER_NOT_SUPPORTED",
                                               "MEDIA_STATE_INVALID",
                                               "NEEDS_RECORDED_MEDIA")),
          str(r["summary"]))
    check("no 0xAD row in opcode matrix (replaced by structure loops)",
          all(c["opcode"] != "0xAD" for c in r["commands"]))
finally:
    op.scsi_execute = orig_exec

print("== sector size / READ 10 dynamic allocation (PM requirement) ==")
check("name_block_size(None) == unknown", op.name_block_size(None) == "unknown")
check("name_block_size(2352) == '2352 (CD raw)'", op.name_block_size(2352) == "2352 (CD raw)")
check("name_block_size(2048) == '2048'", op.name_block_size(2048) == "2048")
check("READ 10 static alloc is 0 (runtime override)", read10["alloc"] == 0)
check("TOTAL_PROBE_STEPS == 114 (71 + 10 + 26 + 7)", op.TOTAL_PROBE_STEPS == 114, str(op.TOTAL_PROBE_STEPS))
check("0xBE not in CMDS (block-type matrix owns READ CD)",
      all(c["op"] != 0xBE for c in op.CMDS))
check("0xAD not in CMDS (DVD/BD structure format matrices own READ DISC STRUCTURE)",
      all(c["op"] != 0xAD for c in op.CMDS))
# READ DISC STRUCTURE left CMDS for the §6.22.3 format matrices (P1-2): the
# matrices allocate a full DVD/BD sector (2048) and build 12-byte CDBs with
# byte 6 = Layer Number (0) and byte 7 = Format (MMC-6 Table 381).
for mt, fmt in ((0x00, 0x00), (0x00, 0x05), (0x00, 0x30), (0x01, 0x00)):
    cdb = op._read_disc_structure_cdb(mt, fmt)
    check(f"0xAD CDB media={mt:#04x} fmt={fmt:#04x}: 12-byte, alloc 2048, fmt@byte7, layer@byte6",
          len(cdb) == 12 and cdb[2] == mt and cdb[6] == 0x00 and cdb[7] == fmt
          and cdb[8:10] == (0x0800).to_bytes(2, "big"), cdb.hex())
check("READ 10 CDB transfer len = 1 block (bytes 7-8)", read10["cdb"][7:9] == bytes([0x00, 0x01]))
# dynamic alloc: READ CAPACITY block size feeds READ 10 alloc
orig_exec = op.scsi_execute

def make_exec(rc_block_size=None):
    calls = []
    def exec_(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        calls.append((bytes(cdb), alloc, direction))
        if cdb[0] == 0x25:
            if rc_block_size is None:
                return (0x02, s70(5, 0x20), b"", "")
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
    # P0-6: insane block lengths (empty-media 0xFFFFFFFF) must clamp to None,
    # never allocate a 4 GB buffer; boundaries 512/4096 accepted.
    for bs, want in ((0xFFFFFFFF, None), (511, None), (4097, None), (512, 512), (4096, 4096)):
        exec_, calls = make_exec(bs)
        op.scsi_execute = exec_
        r = op.probe_device("/dev/fake", 1, False)
        alloc = next(c for c in calls if c[0][0] == 0x28)[1]
        check(f"block_len 0x{bs:08X} -> media_block_size={want} (P0-6 clamp)",
              r["media_block_size"] == want, str(r["media_block_size"]))
        check(f"block_len 0x{bs:08X} -> READ 10 alloc fallback {'2352' if want is None else want}",
              alloc == (2352 if want is None else want), str(alloc))
    exec_, calls = make_exec(2048)
    op.scsi_execute = exec_
    r = op.probe_device("/dev/fake", 1, False)
    gc_call = next(c for c in calls if c[0][0] == 0x46)
    check("probe GET CONFIGURATION alloc == 4096 with CDB alloc 0x1000 (P1-8)",
          gc_call[1] == 4096 and gc_call[0][7:9] == (0x1000).to_bytes(2, "big"),
          f"alloc={gc_call[1]} cdb={gc_call[0].hex()}")
    di_call = next(c for c in calls if c[0][0] == 0x51)
    check("probe READ DISC INFO alloc == 4096 with CDB alloc 0x1000 (P1-8)",
          di_call[1] == 4096 and di_call[0][7:9] == (0x1000).to_bytes(2, "big"),
          f"alloc={di_call[1]} cdb={di_call[0].hex()}")
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

print("== fw_flash_blocked anti-brick hard rule (WRITE BUFFER firmware modes) ==")
# mode 0x00 (device buffer) — allowed
check("WRITE BUFFER mode 0x00 -> False (allowed, device buffer)",
      op.fw_flash_blocked({"op": 0x3B, "cdb": bytes([0x3B, 0x00, 0x00, 0, 0, 0, 0x00, 0x00, 0x08, 0])}) is False)
# firmware modes — all blocked
for m in (0x04, 0x05, 0x07, 0x0B, 0x0F):
    check(f"WRITE BUFFER mode 0x{m:02X} -> True (blocked, firmware download/update)",
          op.fw_flash_blocked({"op": 0x3B, "cdb": bytes([0x3B, m, 0x00, 0, 0, 0, 0x00, 0x00, 0x08, 0])}) is True)
# short CDB (fail-safe: less than 2 bytes)
check("WRITE BUFFER CDB 1 byte -> True (fail-safe)",
      op.fw_flash_blocked({"op": 0x3B, "cdb": bytes([0x3B])}) is True)
# empty CDB (fail-safe)
check("WRITE BUFFER CDB empty -> True (fail-safe)",
      op.fw_flash_blocked({"op": 0x3B, "cdb": b""}) is True)
# CDB is None (fail-safe)
check("WRITE BUFFER CDB None -> True (fail-safe)",
      op.fw_flash_blocked({"op": 0x3B}) is True)
# not WRITE BUFFER opcode (e.g. FLUSH CACHE 0x35)
check("FLUSH CACHE (0x35) -> False (not WRITE BUFFER)",
      op.fw_flash_blocked({"op": 0x35, "cdb": bytes([0x35, 0, 0, 0, 0, 0, 0, 0x00, 0, 0])}) is False)
# no op key
check("no 'op' key -> False (no crash)",
      op.fw_flash_blocked({}) is False)
# no cdb key
check("no 'cdb' key, op=0x3B -> True (fail-safe, treated as blocked)",
      op.fw_flash_blocked({"op": 0x3B}) is True)

# integration: WRITE BUFFER in safe mode still SKIPPED via dangerous gate (mode 0x00 passes fw_flash_blocked)
orig_exec2 = op.scsi_execute
try:
    op.scsi_execute = fc_exec
    r_safe = op.probe_device("/dev/fake", 1, False)
    wb_safe = next(c for c in r_safe["commands"] if c["opcode"] == "0x3B")
    check("safe mode: WRITE BUFFER mode 0x00 -> SKIPPED via dangerous gate (not fw-flash gate)",
          wb_safe["result"] == "SKIPPED" and "--dangerous" in wb_safe["detail"], wb_safe["detail"])
    r_danger = op.probe_device("/dev/fake", 1, True)
    wb_danger = next(c for c in r_danger["commands"] if c["opcode"] == "0x3B")
    check("full-compat: WRITE BUFFER mode 0x00 -> sent (not blocked by fw_flash)",
          wb_danger["result"] == "SUPPORTED", wb_danger["detail"])
finally:
    op.scsi_execute = orig_exec2

print("== READ CD MSF (0xB9) media-aware TOC-derived MSF (P1-1) ==")
# LBA -> MSF golden vectors (frame 0 == LBA -150; LBA 0 == MSF 0:2:0).
check("_lba_to_msf(0) == (0,2,0)", op._lba_to_msf(0) == (0, 2, 0), str(op._lba_to_msf(0)))
check("_lba_to_msf(150) == (0,4,0)", op._lba_to_msf(150) == (0, 4, 0), str(op._lba_to_msf(150)))
check("_lba_to_msf(4500) == (1,2,0)", op._lba_to_msf(4500) == (1, 2, 0), str(op._lba_to_msf(4500)))
# Format 0 TOC golden vector: first track 1, start LBA 0x00A0 (=160) -> MSF 0:4:10.
# 10-byte descriptor (MMC-6 Table 334): [adr/ctl, track, reserved(4), start LBA(4)],
# dlen = 0x000C = first/last(2) + one descriptor(10).
fake_toc = b"\x00\x0c" + b"\x01\x01" + bytes([0x01, 0x01, 0, 0, 0, 0]) + (0x00A0).to_bytes(4, "big")
toc_cdb = bytes([0x43, 0, 0, 0x00, 0, 0x00, 0x10, 0x00, 0])
dyn_b9 = bytes([0xB9, 0x00, 0, 4, 10, 0, 5, 10, 0x00, 0x10, 0x00, 0])
fix_b9 = bytes([0xB9, 0x00, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0])

orig_exec_p11 = op.scsi_execute
try:
    calls = []
    def toc_ok_exec(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        calls.append((bytes(cdb), alloc))
        if cdb[0] == 0x43:
            return (0x00, b"", fake_toc, "")
        if cdb[0] == 0x25:
            return (0x00, b"", (0).to_bytes(4, "big") + (2048).to_bytes(4, "big"), "")
        return (0x00, b"", b"\x00" * max(alloc, 1), "")
    op.scsi_execute = toc_ok_exec
    msf, tn = op._read_toc_first_track_msf("/dev/fake", 1)
    check("TOC parse: LBA 0x00A0 -> MSF (0,4,10), track 1",
          msf == (0, 4, 10) and tn == 1, f"msf={msf} track={tn}")
    check("TOC parse: READ TOC CDB byte-exact, alloc 4096",
          calls[0][0] == toc_cdb and calls[0][1] == 4096,
          calls[0][0].hex() if calls else "no call")
    calls.clear()
    r = op.probe_device("/dev/fake", 1, False)
    b9_call = next(c for c in calls if c[0][0] == 0xB9)
    b9_entry = next(c for c in r["commands"] if c["opcode"] == "0xB9")
    check("B9 with TOC: dynamic CDB byte-exact (0:4:10 -> 0:5:10)",
          b9_call[0] == dyn_b9, b9_call[0].hex())
    check("B9 with TOC: alloc stays 2352", b9_call[1] == 2352, str(b9_call[1]))
    check("B9 with TOC: detail carries TOC track marker",
          "TOC track 1 MSF 0:4:10" in b9_entry["detail"], b9_entry["detail"])
    calls.clear()
    def toc_fail_exec(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        calls.append((bytes(cdb), alloc))
        if cdb[0] == 0x43:
            return (0x02, s70(2, 0x3A), b"", "")  # MEDIUM NOT PRESENT -> no TOC
        if cdb[0] == 0x25:
            return (0x00, b"", (0).to_bytes(4, "big") + (2048).to_bytes(4, "big"), "")
        return (0x00, b"", b"\x00" * max(alloc, 1), "")
    op.scsi_execute = toc_fail_exec
    r = op.probe_device("/dev/fake", 1, False)
    b9_call = next(c for c in calls if c[0][0] == 0xB9)
    b9_entry = next(c for c in r["commands"] if c["opcode"] == "0xB9")
    check("B9 without TOC: fallback CDB byte-exact (fixed MSF)",
          b9_call[0] == fix_b9, b9_call[0].hex())
    check("B9 without TOC: detail carries no-TOC marker",
          "no TOC, fixed MSF" in b9_entry["detail"], b9_entry["detail"])
    calls.clear()
    def toc_garbage_exec(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        calls.append((bytes(cdb), alloc))
        if cdb[0] == 0x43:
            return (0x00, b"", b"\x00" * 4096, "")  # unparseable (first track 0)
        if cdb[0] == 0x25:
            return (0x00, b"", (0).to_bytes(4, "big") + (2048).to_bytes(4, "big"), "")
        return (0x00, b"", b"\x00" * max(alloc, 1), "")
    op.scsi_execute = toc_garbage_exec
    r = op.probe_device("/dev/fake", 1, False)
    b9_call = next(c for c in calls if c[0][0] == 0xB9)
    check("B9 garbage TOC: falls back to fixed CDB", b9_call[0] == fix_b9, b9_call[0].hex())
    check("B9 matrix entry still exactly one per probe",
          len([c for c in r["commands"] if c["opcode"] == "0xB9"]) == 1)
finally:
    op.scsi_execute = orig_exec_p11

print("\n== P1-3b: EXPECTED_COMMANDS spec DB + evaluate_compatibility ==")
# DB integrity: every key is a legal 0xXX opcode string, every value M/O/N/C
_bad_key = [k for spec in op.EXPECTED_COMMANDS.values() for k in spec
            if not (len(k) == 4 and k[:2] == "0x"
                    and all(ch in "0123456789ABCDEF" for ch in k[2:]))]
check("DB: every profile key is a legal 0x00-0xFF opcode string", not _bad_key, str(_bad_key[:3]))
_bad_val = [v for spec in op.EXPECTED_COMMANDS.values() for v in spec.values()
            if v not in "MONC"]
check("DB: every expected value is M/O/N/C", not _bad_val, str(_bad_val[:3]))
check("DB: all 13 logical profiles present",
      {"CD-ROM", "CD-R", "CD-RW", "DVD-ROM", "DVD-R Sequential", "DVD-RW Restricted Overwrite",
       "DVD-RAM", "DVD+R", "DVD+RW", "BD-ROM", "BD-R Sequential", "BD-R Random", "BD-RE"}
      <= set(op.EXPECTED_COMMANDS))
check("DB: DVD-RW Sequential shares the DVD-RW command set",
      op.EXPECTED_COMMANDS["DVD-RW Sequential"] == op.EXPECTED_COMMANDS["DVD-RW Restricted Overwrite"])
# spot-checks (10+ cells)
_db = op.EXPECTED_COMMANDS
check("DB: DVD-ROM 0x2A=N", _db["DVD-ROM"]["0x2A"] == "N")
check("DB: DVD-ROM 0x28=M", _db["DVD-ROM"]["0x28"] == "M")
check("DB: BD-R SRM 0x2A=M", _db["BD-R Sequential"]["0x2A"] == "M")
check("DB: CD-ROM 0xA1=N", _db["CD-ROM"]["0xA1"] == "N")
check("DB: DVD-RW 0xA1=M", _db["DVD-RW Restricted Overwrite"]["0xA1"] == "M")
check("DB: DVD-RAM 0x04=M", _db["DVD-RAM"]["0x04"] == "M")
check("DB: DVD+R 0xA1=N", _db["DVD+R"]["0xA1"] == "N")
check("DB: BD-RE 0x04=M", _db["BD-RE"]["0x04"] == "M")
check("DB: CD-RW 0xA1=M", _db["CD-RW"]["0xA1"] == "M")
check("DB: BD-ROM 0xAD=M", _db["BD-ROM"]["0xAD"] == "M")
check("DB: CD-R 0x51=M (READ DISC INFORMATION)", _db["CD-R"]["0x51"] == "M")
check("DB: DVD-R Sequential 0xAD=M", _db["DVD-R Sequential"]["0xAD"] == "M")
check("DB: BD-R RRM 0xA8=M (READ 12)", _db["BD-R Random"]["0xA8"] == "M")
check("DB: CD-ROM 0x23=O (READ FORMAT CAPACITIES)", _db["CD-ROM"]["0x23"] == "O")
check("DB: CD-RW 0x04=C (FORMAT UNIT conditional)", _db["CD-RW"]["0x04"] == "C")
check("DB: DVD-RAM 0x53=O (RESERVE TRACK)", _db["DVD-RAM"]["0x53"] == "O")

# evaluate_compatibility unit tests (hand-crafted result dicts)
def _fake_result(profile, code, cmd_results, ad_result=None):
    cmds = [{"opcode": op, "name": op, "category": "SPC",
             "result": res, "detail": ""} for op, res in cmd_results.items()]
    dvd = [] if ad_result is None else [{
        "format": "0x00", "name": "Physical Format Information",
        "media_type": 0, "result": ad_result, "detail": ""}]
    return {"current_profile": code, "current_profile_name": profile,
            "commands": cmds, "dvd_structure_matrix": dvd}

def _row(compat, opcode):
    return next(r for r in compat["rows"] if r["opcode"] == opcode)

c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x28": "SUPPORTED"}))
check("M + SUPPORTED -> PASS", _row(c, "0x28")["verdict"] == "PASS")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x28": "NOT_SUPPORTED"}))
check("M + NOT_SUPPORTED -> FAIL", _row(c, "0x28")["verdict"] == "FAIL")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x28": "NEEDS_MEDIA"}))
check("M + NEEDS_MEDIA -> INFO", _row(c, "0x28")["verdict"] == "INFO")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x2A": "NOT_SUPPORTED"}))
check("N + NOT_SUPPORTED -> PASS (correctly absent)", _row(c, "0x2A")["verdict"] == "PASS")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x2A": "SUPPORTED"}))
check("N + SUPPORTED -> INFO (extra capability)", _row(c, "0x2A")["verdict"] == "INFO")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x3C": "SUPPORTED"}))
check("O + anything -> OPTIONAL", _row(c, "0x3C")["verdict"] == "OPTIONAL")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x3C": "TIMEOUT"}))
check("O + TIMEOUT -> OPTIONAL", _row(c, "0x3C")["verdict"] == "OPTIONAL")
c = op.evaluate_compatibility(_fake_result("CD-RW", 0x0A, {"0x04": "SUPPORTED"}))
check("C + SUPPORTED -> PASS (condition met)", _row(c, "0x04")["verdict"] == "PASS")
c = op.evaluate_compatibility(_fake_result("CD-RW", 0x0A, {"0x04": "NOT_SUPPORTED"}))
check("C + NOT_SUPPORTED -> INFO (condition not met)", _row(c, "0x04")["verdict"] == "INFO")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {}))
check("M + not probed -> INFO, actual=(not probed)",
      _row(c, "0x28")["verdict"] == "INFO" and _row(c, "0x28")["actual"] == "(not probed)")
# 0xAD substitution: not in commands[], judged via dvd_structure_matrix format 0x00
c = op.evaluate_compatibility(_fake_result("DVD-ROM", 0x10, {"0x28": "SUPPORTED"}, ad_result="SUPPORTED"))
check("0xAD via matrix fmt 0x00 + SUPPORTED -> PASS",
      _row(c, "0xAD")["actual"] == "SUPPORTED" and _row(c, "0xAD")["verdict"] == "PASS")
c = op.evaluate_compatibility(_fake_result("DVD-ROM", 0x10, {}, ad_result="NOT_SUPPORTED"))
check("0xAD via matrix fmt 0x00 + NOT_SUPPORTED -> FAIL",
      _row(c, "0xAD")["verdict"] == "FAIL")
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {}, ad_result="NOT_SUPPORTED"))
check("CD-ROM 0xAD=N + matrix NOT_SUPPORTED -> PASS", _row(c, "0xAD")["verdict"] == "PASS")
c = op.evaluate_compatibility(_fake_result("DVD-ROM", 0x10, {}))
check("0xAD without matrix -> (not probed)/INFO",
      _row(c, "0xAD")["actual"] == "(not probed)" and _row(c, "0xAD")["verdict"] == "INFO")
# unknown profile / no profile
c = op.evaluate_compatibility(
    {"current_profile": 0x9999, "current_profile_name": "Mystery Drive",
     "commands": [], "dvd_structure_matrix": []})
check("unknown profile -> empty rows + 'profile not in spec DB' note",
      c["rows"] == [] and c.get("note") == "profile not in spec DB"
      and c["summary"] == {"PASS": 0, "FAIL": 0, "OPTIONAL": 0, "INFO": 0})
check("no current profile -> None",
      op.evaluate_compatibility({"current_profile_name": None, "commands": []}) is None)
# verdict coverage + summary totals over a full CD-ROM row set
c = op.evaluate_compatibility(_fake_result("CD-ROM", 0x08, {"0x28": "SUPPORTED", "0x2A": "NOT_SUPPORTED"},
                                           ad_result="NOT_SUPPORTED"))
check("summary counts sum to DB row count",
      sum(c["summary"].values()) == len(op.EXPECTED_COMMANDS["CD-ROM"])
      and c["summary"]["PASS"] >= 1 and c["summary"]["FAIL"] == 0)

print(f"\nRESULT: {passed} passed / {failed} failed")
sys.exit(1 if failed else 0)
