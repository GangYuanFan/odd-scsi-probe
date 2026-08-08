#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
odd_probe.py — USB ODD (optical disc drive) SCSI command support probe

Scans a SCSI/ATAPI optical device and reports:
  * INQUIRY identity (vendor / product / revision / peripheral type / serial)
  * GET CONFIGURATION feature & profile list (CD / DVD / BD / HD-DVD / DDCD)
  * READ DISC INFORMATION media type
  * READ CAPACITY media sector size (drives READ 10 buffer sizing)
  * Per-opcode support matrix for 72 SCSI commands: MMC-6 Table 7 optical-disc
    probe coverage (mandatory/optional/legacy + SPC-3 inheritance; 49 MMC-6
    opcodes incl. VERIFY 12 0xAF — READ CD 0xBE represented by the Table 352
    Expected Sector Type matrix, 10 block types) + 23 legacy/extra commands
    (SPC-3 extras / MMC Annex E / MMC-4 gap closure).
  * Per-command data direction (dir: in/out/none) — write-class commands are
    sent with SG_DXFER_TO_DEV / SCSI_IOCTL_DATA_OUT so DOUT opcodes are
    detected correctly.

Zero third-party dependencies — pure Python stdlib (ctypes / struct / os / ...).

Usage:
  python3 odd_probe.py list                              # list SCSI/optical devices
  python3 odd_probe.py --device /dev/sr0                 # full probe, human output
  python3 odd_probe.py --device /dev/sg2 --json          # machine-readable JSON
  python3 odd_probe.py --device /dev/sg2 --dangerous     # FULL COMPATIBILITY mode:
                                                         # sends every command with
                                                         # real parameters (BLANK /
                                                         # FORMAT / WRITE / eject ...)
  python3 odd_probe.py --device /dev/sg2 --timeout 5     # per-command timeout (s)

Modes (per product owner):
  * default (safe):   destructive commands are SKIPPED with a hint to use
                      --dangerous; read/inquiry commands run for real.
  * --dangerous:      FULL COMPATIBILITY TESTING — every command is sent with
                      real parameters, including BLANK (erases disc), FORMAT
                      UNIT (formats media), CLOSE TRACK/SESSION, LOAD/UNLOAD
                      (operates the tray) and WRITE commands (real data).
  * Sole exception:   WRITE BUFFER (0x3B) never uses firmware download/update
                      modes (0x05/0x0F/0x0A ...) — bricking risk, no value for
                      compatibility testing; other modes (e.g. 0x00) are used.

Version 1.3.0 (2026-08-08) — P0/P1 fixes from REVIEW-2026-08-08.md:
  * READ CD (0xBE) matrix redesigned per MMC-6 Table 352 + Linux
    drivers/cdrom/cdrom.c cdrom_read_block() (EST<<2 / TL bytes 6-8 /
    flags byte 9 / sub-channel byte 10)
  * RSOC / REPORT LUNS allocation length fields corrected; GET PERFORMANCE
    trimmed to the 12-byte MMC-6 Table 290 CDB; START STOP UNIT / PLAY AUDIO
    10 / WRITE BUFFER / READ MEDIA SERIAL CDBs corrected
  * Linux sg resid honored + GET CONFIGURATION Data Length clamp (no more
    zero-fill pollution); media block size clamped to 512..4096
  * Sense parsing supports descriptor format 0x72/0x73 (kernel
    scsi_normalize_sense) + one-shot REQUEST SENSE rescue when a bridge
    swallows auto-sense
  * GET CONFIGURATION / READ DISC INFO / READ TRACK INFO / MODE SENSE 10
    alloc capped at 4096 (Windows SCSI_PASS_THROUGH 64KB limit)
  * scsi_execute catches OSError so a mid-probe hot-unplug keeps the result
"""

import argparse
import ctypes
import json
import os
import platform
import struct
import sys
import time

__version__ = "1.4.0"  # v1.4.0: P0 spec fixes — RESERVE 10 / RELEASE 6/10 / VERIFY 12 + 0x56 relabel (MMC-6 Table 7 verified)

# ---------------------------------------------------------------------------
# SCSI constants
# ---------------------------------------------------------------------------
SG_IO = 0x2285  # Linux: _IOWR('S', 0x10, struct sg_io_hdr)
SG_DXFER_NONE = 0
SG_DXFER_TO_DEV = 1
SG_DXFER_FROM_DEV = 2

IOCTL_SCSI_PASS_THROUGH = 0x0004D004  # Windows
SCSI_IOCTL_DATA_IN = 1
SCSI_IOCTL_DATA_OUT = 0
SCSI_IOCTL_DATA_UNSPECIFIED = 2

MAX_SECTOR_SIZE = 2352  # CD raw sector (DVD/BD/HD-DVD are fixed 2048 B)

# MMC-6 Table 352 — READ CD (0xBE) Expected Sector Type (EST, byte 1 bits
# 7-2) matrix, 10 probed variants. Each row fixes the CDB fields that fully
# describe the returned data: EST (byte 1), byte 9 flags (Sync/Header/User
# Data/EDC; 0xF8 = raw all, 0x10 = user data only, 0x50 = sub-header+user)
# and byte 10 Sub-channel selection (0x00 none / 0x01 P&Q 16B / 0x02 P-W
# pack 96B / 0x03 raw P-W 96B). Mandatory EST set per Table 352:
# 000b / 010b / 100b / 101b (raw / Mode 1 / XA form 1 / XA form 2).
CD_BLOCK_TYPES = {
    1:  {"size": 2352, "name": "Raw data (sync+header+user+EDC)", "est": 0x00, "flags": 0xF8, "subch": 0x00, "mandatory": True},
    2:  {"size": 2368, "name": "Raw data with P and Q Sub-channel", "est": 0x00, "flags": 0xF8, "subch": 0x01, "mandatory": False},
    3:  {"size": 2448, "name": "Raw data with P-W Sub-channel appended, pack form", "est": 0x00, "flags": 0xF8, "subch": 0x02, "mandatory": False},
    4:  {"size": 2448, "name": "Raw data with raw P-W Sub-channel appended", "est": 0x00, "flags": 0xF8, "subch": 0x03, "mandatory": False},
    5:  {"size": 2048, "name": "Mode 1 ISO/IEC 10149", "est": 0x02, "flags": 0x10, "subch": 0x00, "mandatory": True},
    6:  {"size": 2336, "name": "Mode 2 ISO/IEC 10149 (formless)", "est": 0x03, "flags": 0x10, "subch": 0x00, "mandatory": False},
    7:  {"size": 2048, "name": "Mode 2 CD-ROM XA form 1", "est": 0x04, "flags": 0x10, "subch": 0x00, "mandatory": True},
    8:  {"size": 2056, "name": "Mode 2 XA form 1 + 8B sub-header", "est": 0x04, "flags": 0x50, "subch": 0x00, "mandatory": False},
    9:  {"size": 2324, "name": "Mode 2 XA form 2", "est": 0x05, "flags": 0x10, "subch": 0x00, "mandatory": True},
    10: {"size": 2332, "name": "Mode 2 XA form 2 + 8B sub-header", "est": 0x05, "flags": 0x50, "subch": 0x00, "mandatory": False},
}
CD_BLOCK_TYPE_CODES = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

# ---------------------------------------------------------------------------
# Lookup tables (built in per spec)
# ---------------------------------------------------------------------------
PROFILE_NAMES = {
    0x03: "MO Erasable", 0x04: "MO Write Once",
    0x05: "DDCD-ROM", 0x06: "DDCD-R", 0x07: "DDCD-RW",
    0x08: "CD-ROM", 0x09: "CD-R", 0x0A: "CD-RW",
    0x10: "DVD-ROM", 0x11: "DVD-R Sequential", 0x12: "DVD-RAM",
    0x13: "DVD-RW Restricted Overwrite", 0x14: "DVD-RW Sequential",
    0x15: "DVD-R Dual Layer Sequential", 0x16: "DVD-R Dual Layer Jump",
    0x17: "DVD+R", 0x1A: "DVD+RW", 0x1B: "DVD+R Dual Layer",
    0x1C: "DVD+RW Dual Layer", 0x20: "DVD-RW Dual Layer",
    0x40: "BD-ROM", 0x41: "BD-R Sequential", 0x42: "BD-R Random", 0x43: "BD-RE",
    0x50: "HD DVD-ROM", 0x51: "HD DVD-R", 0x52: "HD DVD-RAM",
    0x53: "HD DVD-RW", 0x58: "HD DVD-R Dual Layer", 0x5A: "HD DVD-RW Dual Layer",
}

FEATURE_NAMES = {
    0x0000: "Profile List", 0x0001: "Core", 0x0002: "Morphing",
    0x0003: "Removable Medium", 0x0004: "Write Protect",
    0x0010: "Random Readable", 0x001D: "Multi-Read", 0x001E: "CD Read",
    0x001F: "DVD Read", 0x0020: "Random Writable",
    0x0021: "Incremental Streaming Writable", 0x0023: "Restricted Overwrite",
    0x0024: "CD-RW CAV Write", 0x0025: "MRW", 0x0026: "Enhanced Defect Reporting",
    0x0027: "DVD+RW", 0x0028: "DVD+R", 0x002A: "Rigid Restricted Overwrite",
    0x002B: "CD Track at Once", 0x002C: "CD Mastering at Once",
    0x002D: "DVD-RW SR", 0x002E: "DVD-RW RO", 0x002F: "DVD-RAM",
    0x0030: "DVD-R", 0x0031: "DVD+RW Dual Layer", 0x0032: "DVD+R Dual Layer",
    0x0033: "Layer Jump Recording", 0x0034: "CD-RW Media",
    0x0037: "DVD+RW Middle", 0x0038: "DVD-RW Dual Layer",
    0x003A: "DVD+R Middle", 0x003B: "HD DVD Read", 0x003C: "HD DVD Write",
    0x003D: "Hybrid Disc", 0x0040: "BD Read", 0x0041: "BD Write",
    0x0043: "AACS", 0x0045: "CSS", 0x0047: "CPPM",
    0x0100: "Power Management", 0x0104: "Microcode Upgrade", 0x0105: "Timeout",
    0x0107: "DVD CSS", 0x0108: "Real Time Streaming",
    0x0109: "Logical Unit Serial Number", 0x010B: "Disc Control Blocks",
    0x010C: "DVD CPRM", 0x010D: "Firmware Date", 0x010F: "BD+",
}

DISC_TYPE_NAMES = {
    0x00: "CD-DA", 0x01: "CD-ROM", 0x02: "CD-R", 0x03: "CD-RW",
    0x04: "DVD-ROM", 0x05: "DVD-R", 0x06: "DVD-RAM", 0x07: "DVD-RW",
    0x08: "DVD+R", 0x09: "DVD+RW", 0x0A: "DVD+R DL", 0x0B: "DVD+RW DL",
    0x0C: "BD-ROM", 0x0D: "BD-R", 0x0E: "BD-RE",
    0x10: "HD DVD-ROM", 0x11: "HD DVD-R", 0x12: "HD DVD-RAM", 0x13: "HD DVD-RW",
}

PERIPHERAL_NAMES = {
    0x00: "direct access", 0x05: "CD/DVD device", 0x07: "optical memory",
}

SENSE_KEY_NAMES = {
    0x00: "NO SENSE", 0x01: "RECOVERED ERROR", 0x02: "NOT READY",
    0x03: "MEDIUM ERROR", 0x04: "HARDWARE ERROR", 0x05: "ILLEGAL REQUEST",
    0x06: "UNIT ATTENTION", 0x07: "DATA PROTECT", 0x08: "BLANK CHECK",
    0x09: "VENDOR SPECIFIC", 0x0A: "COPY ABORTED", 0x0B: "ABORTED COMMAND",
    0x0E: "MISCOMPARE",
}

ASC_NAMES = {
    0x00: "NO ADDITIONAL SENSE INFORMATION",
    0x04: "LOGICAL UNIT NOT READY, CAUSE NOT REPORTABLE",
    0x20: "INVALID COMMAND OPERATION CODE",
    0x24: "INVALID FIELD IN CDB",
    0x25: "LOGICAL BLOCK ADDRESS OUT OF RANGE",
    0x26: "INVALID FIELD IN PARAMETER LIST",
    0x27: "WRITE PROTECTED",
    0x28: "NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED",
    0x3A: "MEDIUM NOT PRESENT",
}

# ---------------------------------------------------------------------------
# Command matrix: 72 opcodes = MMC-6 Table 7 optical-disc probe coverage
# (mandatory/optional/legacy + SPC-3 inheritance; 49 MMC-6 opcodes incl.
# VERIFY 12 0xAF — READ CD 0xBE is represented by the Table 352 block-type
# matrix below) + 23 legacy/extra commands (SPC-3 variants / MMC Annex E /
# MMC-4 gap closure)
# kept for completeness and flagged legacy. CDB templates per MMC-6 rev 2g
# (T10/1836-D), cross-checked against SPC-3 for the security/read-media-serial
# opcodes.
#   cdb:  bytes of the CDB template
#   alloc: data buffer size (0 = no data phase)
#   dir:  data direction — "in" (device->host buffer), "out" (host->device
#         buffer), "none" (no data phase)
#   dangerous: only sent when --dangerous, then with REAL parameters
#   legacy: not in MMC-6 Table 226/227 (SPC-3 extra / Annex E obsolete)
# ---------------------------------------------------------------------------
MMC6_OPCODES = frozenset((
    0x00, 0x03, 0x04, 0x12, 0x1B, 0x1E, 0x23, 0x25, 0x28, 0x2A,
    0x2B, 0x2E, 0x2F, 0x35, 0x3B, 0x3C, 0x43, 0x46, 0x4A, 0x51,
    0x52, 0x53, 0x54, 0x55, 0x58, 0x5A, 0x5B, 0x5C, 0x5D, 0xA0,
    0xA1, 0xA2, 0xA3, 0xA4, 0xA6, 0xA7, 0xA8, 0xAA, 0xAB, 0xAC,
    0xAD, 0xAF, 0xB5, 0xB6, 0xB9, 0xBB, 0xBD, 0xBE, 0xBF,
))

CMDS = [
    # ---- SPC base (MMC-6 references SPC-3) ----
    {"op": 0x00, "name": "TEST UNIT READY", "cat": "SPC", "cdb": bytes([0x00, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none"},
    {"op": 0x03, "name": "REQUEST SENSE", "cat": "SPC", "cdb": bytes([0x03, 0, 0, 0, 0x12, 0]), "alloc": 18, "dir": "in"},
    {"op": 0x12, "name": "INQUIRY", "cat": "SPC", "cdb": bytes([0x12, 0, 0, 0, 0x60, 0]), "alloc": 96, "dir": "in"},
    {"op": 0x1A, "name": "MODE SENSE 6", "cat": "SPC", "cdb": bytes([0x1A, 0, 0x3F, 0, 0xFF, 0]), "alloc": 255, "dir": "in"},
    {"op": 0x1B, "name": "START STOP UNIT", "cat": "SPC", "cdb": bytes([0x1B, 0x01, 0, 0, 0x01, 0]), "alloc": 0, "dir": "none"},  # kernel CDROMSTART (cdrom.c mmc_ioctl_cdrom_start_stop): byte1=0x01 IMMED, START bit at byte 4 bit 0 — SFF-8020i/ATAPI encoding (SPC-3's byte-1 bit-7 START does not apply to ODD firmware); spin-up, no LoEJ
    {"op": 0x1E, "name": "PREVENT ALLOW MEDIUM REMOVAL", "cat": "SPC", "cdb": bytes([0x1E, 0, 0, 0, 0x00, 0]), "alloc": 0, "dir": "none"},  # prevent=0
    {"op": 0x25, "name": "READ CAPACITY", "cat": "SPC", "cdb": bytes([0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 8, "dir": "in"},
    {"op": 0x28, "name": "READ 10", "cat": "SPC", "cdb": bytes([0x28, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0]), "alloc": 0, "dir": "in"},  # alloc overridden at runtime: media block size (READ CAPACITY) or 2352 fallback
    {"op": 0x2B, "name": "SEEK 10", "cat": "SPC", "cdb": bytes([0x2B, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none"},
    {"op": 0x2F, "name": "VERIFY 10", "cat": "SPC", "cdb": bytes([0x2F, 0, 0, 0, 0, 0, 0, 0x00, 0, 0]), "alloc": 0, "dir": "none"},  # BYTCHK=0,len=0
    {"op": 0xAF, "name": "VERIFY 12", "cat": "SPC", "cdb": bytes([0xAF, 0, 0, 0, 0, 0, 0, 0x00, 0, 0, 0, 0]), "alloc": 0, "dir": "none"},  # BYTCHK=0, verification length=0 -> verifies nothing (safe); MMC-6 Table 7: VERIFY = 2Fh/AFh
    {"op": 0x35, "name": "SYNCHRONIZE CACHE / FLUSH CACHE", "cat": "SPC", "cdb": bytes([0x35, 0, 0, 0, 0, 0, 0, 0x00, 0, 0]), "alloc": 0, "dir": "none"},  # range 0 = no-op; MMC-2 FLUSH CACHE = ATAPI 12-byte variant of same opcode
    {"op": 0x3C, "name": "READ BUFFER", "cat": "SPC", "cdb": bytes([0x3C, 0x00, 0x00, 0, 0, 0, 0x00, 0x04, 0, 0]), "alloc": 4, "dir": "in"},  # mode 0 capacity header
    {"op": 0x5A, "name": "MODE SENSE 10", "cat": "SPC", "cdb": bytes([0x5A, 0, 0x3F, 0, 0, 0, 0, 0, 0x10, 0x00]), "alloc": 4096, "dir": "in"},  # P1-8: alloc 4096 (Windows SCSI_PASS_THROUGH 64KB cap; MMC allows truncated responses),
    {"op": 0x1C, "name": "RECEIVE DIAGNOSTIC RESULTS", "cat": "SPC", "cdb": bytes([0x1C, 0, 0x00, 0x00, 0x04, 0]), "alloc": 4, "dir": "in"},
    {"op": 0x1D, "name": "SEND DIAGNOSTIC", "cat": "SPC", "cdb": bytes([0x1D, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none"},  # self-test=0
    # ---- MMC-4 / SPC legacy additions (v1.2.1) ----
    {"op": 0x01, "name": "REZERO UNIT", "cat": "SPC", "cdb": bytes([0x01, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "legacy": True},  # obsolete SPC
    {"op": 0x16, "name": "RESERVE 6", "cat": "SPC", "cdb": bytes([0x16, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "legacy": True},  # obsolete SPC
    {"op": 0x17, "name": "RELEASE 6", "cat": "SPC", "cdb": bytes([0x17, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "legacy": True},  # MMC-6 Table 7: RELEASE = 17h,57h
    {"op": 0x34, "name": "PREFETCH 10", "cat": "SPC", "cdb": bytes([0x34, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0]), "alloc": 0, "dir": "none"},  # LBA=0 len=1
    {"op": 0x36, "name": "LOCK/UNLOCK CACHE", "cat": "SPC", "cdb": bytes([0x36, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none"},
    {"op": 0x4C, "name": "LOG SENSE", "cat": "SPC", "cdb": bytes([0x4C, 0, 0x00, 0, 0, 0, 0, 0, 0xFF, 0xFF]), "alloc": 4096, "dir": "in"},
    {"op": 0xA3, "name": "MAINTENANCE IN (RSOC)", "cat": "SPC", "cdb": bytes([0xA3, 0x0C, 0, 0, 0, 0, 0x10, 0x00, 0, 0, 0, 0]), "alloc": 4096, "dir": "in", "rsoc": True},  # SPC-3 SA=0x0C REPORT SUPPORTED OPERATION CODES — allocation length at bytes 6-7 = 0x1000 (was at 8-9, alloc=0); drive reports its own opcode list (shares opcode with MMC-6 SEND KEY; distinguished by service action)

    # ---- MMC optical commands (all disc formats, MMC-6 rev 2g) ----
    {"op": 0x23, "name": "READ FORMAT CAPACITIES", "cat": "MMC", "cdb": bytes([0x23, 0, 0, 0, 0, 0, 0x00, 0xFF, 0, 0]), "alloc": 255, "dir": "in"},
    {"op": 0x42, "name": "READ SUBCHANNEL", "cat": "MMC", "cdb": bytes([0x42, 0, 0x40, 0x01, 0, 0, 0x00, 0x20, 0, 0]), "alloc": 32, "dir": "in", "legacy": True},  # Annex E
    {"op": 0x43, "name": "READ TOC/PMA/ATIP", "cat": "MMC", "cdb": bytes([0x43, 0, 0, 0x00, 0, 0x00, 0x10, 0x00, 0, 0]), "alloc": 4096, "dir": "in"},
    {"op": 0x44, "name": "READ HEADER", "cat": "MMC", "cdb": bytes([0x44, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x20]), "alloc": 32, "dir": "in", "legacy": True},  # Annex E
    {"op": 0x45, "name": "PLAY AUDIO 10", "cat": "MMC", "cdb": bytes([0x45, 0, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0]), "alloc": 0, "dir": "none", "legacy": True, "dangerous": True},  # 10-byte per SFF-8020i Table 72; TL at bytes 7-8 = 0x0001 (kernel cdrom_play_blk); real play in --dangerous
    {"op": 0x46, "name": "GET CONFIGURATION", "cat": "MMC", "cdb": bytes([0x46, 0, 0, 0, 0, 0, 0, 0x10, 0x00, 0]), "alloc": 4096, "dir": "in"},  # P1-8: alloc + CDB allocation length 4096 (was 65535 -> SCSI_PASS_THROUGH >64KB),
    {"op": 0x47, "name": "PLAY AUDIO MSF", "cat": "MMC", "cdb": bytes([0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "legacy": True, "dangerous": True},
    {"op": 0x48, "name": "PLAY AUDIO TRACK INDEX", "cat": "MMC", "cdb": bytes([0x48, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "legacy": True, "dangerous": True},
    {"op": 0x4A, "name": "GET EVENT STATUS NOTIFICATION", "cat": "MMC", "cdb": bytes([0x4A, 0x01, 0x00, 0, 0, 0, 0x00, 0x08, 0, 0]), "alloc": 8, "dir": "in"},
    {"op": 0x4B, "name": "PAUSE/RESUME", "cat": "MMC", "cdb": bytes([0x4B, 0, 0, 0, 0, 0, 0, 0, 0x00, 0]), "alloc": 0, "dir": "none", "legacy": True},  # resume=0 -> pause; Annex E
    {"op": 0x51, "name": "READ DISC INFORMATION", "cat": "MMC", "cdb": bytes([0x51, 0, 0, 0, 0, 0, 0, 0x10, 0x00, 0]), "alloc": 4096, "dir": "in"},  # P1-8: alloc + CDB allocation length 4096,
    {"op": 0x52, "name": "READ TRACK INFORMATION", "cat": "MMC", "cdb": bytes([0x52, 0, 0, 0, 0, 0, 0, 0x10, 0x00, 0]), "alloc": 4096, "dir": "in"},  # P1-8: alloc + CDB allocation length 4096,
    {"op": 0xA0, "name": "REPORT LUNS", "cat": "MMC", "cdb": bytes([0xA0, 0, 0, 0, 0, 0, 0x00, 0x10, 0, 0, 0, 0]), "alloc": 16, "dir": "in"},  # SPC-3 12-byte REPORT LUNS — allocation length at bytes 6-7 = 0x0010 (was a malformed 6-byte CDB)
    {"op": 0xA2, "name": "SECURITY PROTOCOL IN", "cat": "MMC", "cdb": bytes([0xA2, 0x06, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0, 0]), "alloc": 16, "dir": "in"},  # protocol 06h OSSC (6.32); was wrongly labeled SEND KEY
    {"op": 0xA4, "name": "REPORT KEY", "cat": "MMC", "cdb": bytes([0xA4, 0, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x08, 0, 0]), "alloc": 8, "dir": "in"},  # key class 0
    {"op": 0xAC, "name": "GET PERFORMANCE", "cat": "MMC", "cdb": bytes([0xAC, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0]), "alloc": 32, "dir": "in"},  # MMC-6 Table 290: 12-byte CDB — Max Descriptors bytes 8-9 = 0x0001, Type byte 10 = 0x00 (was 16-byte with stray 0x20 tail),
    {"op": 0xAD, "name": "READ DVD STRUCTURE", "cat": "MMC", "cdb": bytes([0xAD, 0, 0x00, 0, 0, 0, 0, 0x00, 0x08, 0x00, 0, 0]), "alloc": 2048, "dir": "in"},  # format 0 = physical
    {"op": 0xA8, "name": "READ 12", "cat": "MMC", "cdb": bytes([0xA8, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0]), "alloc": 0, "dir": "in"},  # LBA=0, len=1; alloc runtime
    {"op": 0xAB, "name": "READ MEDIA SERIAL NUMBER", "cat": "MMC", "cdb": bytes([0xAB, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x80, 0]), "alloc": 128, "dir": "in"},  # SERVICE ACTION IN (12) SA=01h; allocation length bytes 9-10 = 0x0080 (P1-5, was 0x8000=32768)
    {"op": 0xB9, "name": "READ CD MSF", "cat": "MMC", "cdb": bytes([0xB9, 0x00, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0]), "alloc": 2352, "dir": "in"},  # MSF 0:0:0 -> 0:0:1, user data
    {"op": 0xBD, "name": "MECHANISM STATUS", "cat": "MMC", "cdb": bytes([0xBD, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x0C, 0, 0]), "alloc": 12, "dir": "in"},
    {"op": 0xBB, "name": "SET CD SPEED", "cat": "MMC", "cdb": bytes([0xBB, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none"},  # max speed
    {"op": 0x5C, "name": "READ BUFFER CAPACITY", "cat": "MMC", "cdb": bytes([0x5C, 0x00, 0, 0, 0, 0, 0, 0x00, 0x0C, 0]), "alloc": 12, "dir": "in"},  # Block=0, alloc 12
    {"op": 0xA7, "name": "SET READ AHEAD", "cat": "MMC", "cdb": bytes([0xA7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none"},  # trigger LBA 0, read-ahead LBA 0

    # ---- Write-class / destructive (--dangerous only; then sent with REAL parameters) ----
    {"op": 0x04, "name": "FORMAT UNIT", "cat": "DANGEROUS", "cdb": bytes([0x04, 0x11, 0, 0, 0, 0]), "alloc": 12, "dir": "out", "dangerous": True, "danger_note": "formats media (FMTDATA=1, full format)"},
    {"op": 0x15, "name": "MODE SELECT 6", "cat": "DANGEROUS", "cdb": bytes([0x15, 0, 0x00, 0x00, 0x00, 0]), "alloc": 0, "dir": "out", "dangerous": True},  # paramlen=0
    {"op": 0x2A, "name": "WRITE 10", "cat": "DANGEROUS", "cdb": bytes([0x2A, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0]), "alloc": 0, "dir": "out", "dangerous": True, "danger_note": "writes 1 block at LBA 0"},  # alloc runtime (block size)
    {"op": 0x2E, "name": "WRITE AND VERIFY 10", "cat": "DANGEROUS", "cdb": bytes([0x2E, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0]), "alloc": 0, "dir": "out", "dangerous": True, "danger_note": "writes + verifies 1 block at LBA 0"},
    {"op": 0x3B, "name": "WRITE BUFFER", "cat": "DANGEROUS", "cdb": bytes([0x3B, 0x00, 0x00, 0, 0, 0, 0x00, 0x00, 0x08, 0]), "alloc": 8, "dir": "out", "dangerous": True, "danger_note": "mode 0x00 device buffer only — firmware modes NEVER used"},  # param list length bytes 6-8 = 0x000008 (4B header + 4B data, P1-4),
    {"op": 0x53, "name": "RESERVE TRACK", "cat": "DANGEROUS", "cdb": bytes([0x53, 0x01, 0, 0, 0x00, 0x01, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True},  # ARSV=1, track 1
    {"op": 0x54, "name": "SEND OPC INFORMATION", "cat": "DANGEROUS", "cdb": bytes([0x54, 0x01, 0, 0, 0, 0, 0, 0x00, 0x00, 0]), "alloc": 0, "dir": "none", "dangerous": True},  # DoOpc=1
    {"op": 0x55, "name": "MODE SELECT 10", "cat": "DANGEROUS", "cdb": bytes([0x55, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0]), "alloc": 0, "dir": "out", "dangerous": True},  # paramlen=0
    {"op": 0x56, "name": "RESERVE 10", "cat": "SPC", "cdb": bytes([0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "legacy": True},  # MMC-6 Table 7: RESERVE = 16h,56h (舊標 CLOSE TRACK/SESSION (old) 為誤標；真正的 CLOSE TRACK/SESSION = 5Bh)
    {"op": 0x57, "name": "RELEASE 10", "cat": "SPC", "cdb": bytes([0x57, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "legacy": True},  # MMC-6 Table 7: RELEASE = 17h,57h
    {"op": 0x58, "name": "REPAIR TRACK", "cat": "DANGEROUS", "cdb": bytes([0x58, 0x01, 0, 0, 0x00, 0x01, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True},  # Immed=1, track 1
    {"op": 0x5B, "name": "CLOSE TRACK/SESSION", "cat": "DANGEROUS", "cdb": bytes([0x5B, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True, "danger_note": "closes session / finalizes disc"},
    {"op": 0x5D, "name": "SEND CUE SHEET", "cat": "DANGEROUS", "cdb": bytes([0x5D, 0, 0, 0, 0, 0, 0x00, 0x04, 0, 0]), "alloc": 4, "dir": "out", "dangerous": True},  # cue sheet size 4
    {"op": 0xA1, "name": "BLANK", "cat": "DANGEROUS", "cdb": bytes([0xA1, 0x10, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True, "danger_note": "erases entire disc (blank type 000b, Immed=1)"},
    {"op": 0xA3, "name": "SEND KEY", "cat": "DANGEROUS", "cdb": bytes([0xA3, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x08, 0x00, 0]), "alloc": 8, "dir": "out", "dangerous": True},  # 12-byte; Function 0, KeyClass 0 (CSS), param len 8
    {"op": 0xA6, "name": "LOAD/UNLOAD MEDIUM", "cat": "DANGEROUS", "cdb": bytes([0xA6, 0x01, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True, "danger_note": "operates the tray (unload/eject)"},
    {"op": 0xAA, "name": "WRITE 12", "cat": "DANGEROUS", "cdb": bytes([0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0]), "alloc": 0, "dir": "out", "dangerous": True, "danger_note": "writes 1 block at LBA 0"},  # alloc runtime
    {"op": 0xB5, "name": "SECURITY PROTOCOL OUT", "cat": "DANGEROUS", "cdb": bytes([0xB5, 0x06, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0, 0]), "alloc": 4, "dir": "out", "dangerous": True},  # protocol 06h OSSC, param len 4
    {"op": 0xB6, "name": "SET STREAMING", "cat": "DANGEROUS", "cdb": bytes([0xB6, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x14, 0]), "alloc": 20, "dir": "out", "dangerous": True},  # Type 0 = performance descriptor (20 B)
    {"op": 0xBF, "name": "SEND DISC STRUCTURE", "cat": "DANGEROUS", "cdb": bytes([0xBF, 0x00, 0, 0, 0, 0, 0, 0x00, 0x00, 0x04, 0x00, 0]), "alloc": 4, "dir": "out", "dangerous": True},  # media type 0 (DVD), format code 0, param len 4
    # ---- MMC-4 / SPC legacy additions (v1.2.1) ----
    {"op": 0x2C, "name": "ERASE 10", "cat": "DANGEROUS", "cdb": bytes([0x2C, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0]), "alloc": 0, "dir": "none", "dangerous": True, "danger_note": "erases media blocks (LBA 0, 1 block)"},
    {"op": 0x4D, "name": "LOG SELECT", "cat": "DANGEROUS", "cdb": bytes([0x4D, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0]), "alloc": 0, "dir": "out", "dangerous": True},  # paramlen=0
    {"op": 0x4E, "name": "STOP PLAY/SCAN", "cat": "DANGEROUS", "cdb": bytes([0x4E, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True, "legacy": True, "danger_note": "stops playback/scan"},
    {"op": 0xA5, "name": "PLAY AUDIO 12", "cat": "DANGEROUS", "cdb": bytes([0xA5, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True, "legacy": True, "danger_note": "plays 1 block of audio"},  # 12-byte
    {"op": 0xBA, "name": "SCAN", "cat": "DANGEROUS", "cdb": bytes([0xBA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dir": "none", "dangerous": True, "legacy": True},  # 12-byte
]

# Total probe steps = 72 opcodes + 10 READ CD Table 352 block types (82).
# progress_cb totals and the GUI progress bar must use this, not len(CMDS).
TOTAL_PROBE_STEPS = len(CMDS) + len(CD_BLOCK_TYPE_CODES)

# ---------------------------------------------------------------------------
# Linux backend (SG_IO ioctl)
# ---------------------------------------------------------------------------
if os.name == "posix":
    _libc = ctypes.CDLL(None, use_errno=True)

    class SgIoHdr(ctypes.Structure):
        """struct sg_io_hdr from <scsi/sg.h> (64-bit safe via c_void_p)."""
        _fields_ = [
            ("interface_id", ctypes.c_int),
            ("dxfer_direction", ctypes.c_int),
            ("cmd_len", ctypes.c_ubyte),
            ("mx_sb_len", ctypes.c_ubyte),
            ("iovec_count", ctypes.c_ushort),
            ("dxfer_len", ctypes.c_uint),
            ("dxferp", ctypes.c_void_p),
            ("cmdp", ctypes.c_void_p),
            ("sbp", ctypes.c_void_p),
            ("timeout", ctypes.c_uint),       # ms; kernel aborts after this
            ("flags", ctypes.c_uint),
            ("pack_id", ctypes.c_int),
            ("usr_ptr", ctypes.c_void_p),
            ("status", ctypes.c_ubyte),
            ("masked_status", ctypes.c_ubyte),
            ("msg_status", ctypes.c_ubyte),
            ("sb_len_wr", ctypes.c_ubyte),
            ("host_status", ctypes.c_ushort),
            ("driver_status", ctypes.c_ushort),
            ("resid", ctypes.c_int),
            ("duration", ctypes.c_uint),
            ("info", ctypes.c_uint),
        ]

    def scsi_execute(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        """Run one SCSI command via SG_IO. Returns (status, sense_bytes, data_bytes, err_str).

        direction: "in" (device->host buffer), "out" (host->device buffer),
        "none" (no data phase). out_data: payload for "out" commands (default
        zero-filled). alloc==0 always implies no data phase.
        """
        if alloc > 0 and direction == "out":
            dxfer_dir = SG_DXFER_TO_DEV
        elif alloc > 0:
            dxfer_dir = SG_DXFER_FROM_DEV
        else:
            dxfer_dir = SG_DXFER_NONE
        cdb_buf = ctypes.create_string_buffer(bytes(cdb), len(cdb))
        sense_buf = ctypes.create_string_buffer(32)  # 32B: classification needs ASC/ASCQ at 12/13
        data_buf = ctypes.create_string_buffer(max(alloc, 1)) if alloc > 0 else None
        if data_buf is not None and direction == "out":
            fill = bytes(out_data[:alloc]) if out_data else b"\x00" * alloc
            data_buf[:len(fill)] = fill
        hdr = SgIoHdr()
        hdr.interface_id = ord("S")
        hdr.dxfer_direction = dxfer_dir
        hdr.cmd_len = len(cdb)
        hdr.mx_sb_len = 32
        hdr.iovec_count = 0
        hdr.dxfer_len = alloc
        hdr.dxferp = ctypes.cast(data_buf, ctypes.c_void_p) if data_buf else None
        hdr.cmdp = ctypes.cast(cdb_buf, ctypes.c_void_p)
        hdr.sbp = ctypes.cast(sense_buf, ctypes.c_void_p)
        hdr.timeout = max(1, int(timeout_s * 1000))
        hdr.flags = 0
        hdr.pack_id = -1

        try:
            fd = os.open(path, os.O_RDWR)
            try:
                rc = _libc.ioctl(fd, SG_IO, ctypes.byref(hdr))
            finally:
                os.close(fd)
        except OSError as e:
            # P1-9: hot-unplug mid-probe (USB ODD pulled) must not discard the
            # whole result — return an error tuple so probe_device keeps the
            # remaining 78 steps instead of raising out of main().
            return (0, b"", b"", f"OSError: {e}")
        if rc != 0:
            errno = ctypes.get_errno()
            if hdr.status == 0x02:  # CHECK CONDITION delivered despite ioctl error
                pass  # fall through to sense classification
            else:
                return (0, bytes(sense_buf.raw), b"", f"ioctl error errno={errno}")
        if data_buf:
            # Linux sg reports resid = bytes NOT transferred; keep only what
            # the device actually returned (resid < 0 overrun => full buffer)
            # so zero padding never pollutes parsers (P0-4).
            n = max(0, alloc - hdr.resid) if hdr.resid > 0 else alloc
            data = bytes(data_buf.raw[:n])
        else:
            data = b""
        return (hdr.status, bytes(sense_buf.raw[: hdr.sb_len_wr or 32]), data, "")

# ---------------------------------------------------------------------------
# Windows backend (IOCTL_SCSI_PASS_THROUGH)
# ---------------------------------------------------------------------------
# SCSI_PASS_THROUGH is defined on every platform so its ctypes layout can be
# verified against <ntddscsi.h> (pshpack4) without a Windows host (tests/).
class ScsiPassThrough(ctypes.Structure):
    """struct _SCSI_PASS_THROUGH (16-byte CDB + 32-byte sense inline)."""
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("ScsiStatus", ctypes.c_ubyte),
        ("PathId", ctypes.c_ubyte),
        ("TargetId", ctypes.c_ubyte),
        ("Lun", ctypes.c_ubyte),
        ("CdbLength", ctypes.c_ubyte),
        ("SenseInfoLength", ctypes.c_ubyte),
        ("DataIn", ctypes.c_ubyte),
        ("DataTransferLength", ctypes.c_uint),
        ("TimeOutValue", ctypes.c_uint),
        ("DataBufferOffset", ctypes.c_uint),
        ("SenseInfoOffset", ctypes.c_uint),
        ("Cdb", ctypes.c_ubyte * 16),
        ("SenseBuf", ctypes.c_ubyte * 32),
    ]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _configure_windows_ctypes(kernel32):
    """Declare ctypes signatures: HANDLE/BOOL are 64-bit — default c_int would
    truncate the handle and break the INVALID_HANDLE_VALUE check on x64."""
    import ctypes.wintypes as wt
    kernel32.CreateFileW.restype = wt.HANDLE
    kernel32.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE,
    ]
    kernel32.DeviceIoControl.restype = wt.BOOL
    kernel32.DeviceIoControl.argtypes = [
        wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD, wt.LPVOID, wt.DWORD,
        ctypes.POINTER(wt.DWORD), wt.LPVOID,  # lpOverlapped (always None)
    ]


if os.name == "nt":
    import ctypes.wintypes as wt
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3

    # Capture Win32 error codes via a dedicated kernel32 handle created with
    # use_last_error=True: setting the flag on ctypes.windll.kernel32 AFTER
    # function creation is a no-op, so get_last_error() would return stale 0.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_windows_ctypes(kernel32)

    def scsi_execute(path, cdb, alloc, timeout_s, direction="in", out_data=b""):
        """Run one SCSI command via IOCTL_SCSI_PASS_THROUGH. Same return contract.

        direction: "in" / "out" / "none"; out_data: payload for "out" commands.
        """
        spt = ScsiPassThrough()
        data_buf = ctypes.create_string_buffer(max(alloc, 1)) if alloc > 0 else ctypes.create_string_buffer(1)
        if alloc > 0 and direction == "out":
            fill = bytes(out_data[:alloc]) if out_data else b"\x00" * alloc
            data_buf[:len(fill)] = fill
        total = ctypes.sizeof(ScsiPassThrough) + max(alloc, 1)
        io_buf = ctypes.create_string_buffer(total)
        ctypes.memmove(ctypes.byref(io_buf, 0), ctypes.byref(spt), ctypes.sizeof(ScsiPassThrough))
        ctypes.memmove(ctypes.byref(io_buf, ctypes.sizeof(ScsiPassThrough)), data_buf, len(data_buf))

        spt_ptr = ctypes.cast(io_buf, ctypes.POINTER(ScsiPassThrough)).contents
        spt_ptr.Length = ctypes.sizeof(ScsiPassThrough)
        spt_ptr.PathId = 0
        spt_ptr.TargetId = 0
        spt_ptr.Lun = 0
        spt_ptr.CdbLength = len(cdb)
        spt_ptr.SenseInfoLength = 32
        spt_ptr.DataIn = (SCSI_IOCTL_DATA_OUT if direction == "out" else SCSI_IOCTL_DATA_IN) if alloc > 0 else SCSI_IOCTL_DATA_UNSPECIFIED
        spt_ptr.DataTransferLength = alloc
        spt_ptr.TimeOutValue = max(1, int(timeout_s))
        spt_ptr.DataBufferOffset = ctypes.sizeof(ScsiPassThrough)
        spt_ptr.SenseInfoOffset = ScsiPassThrough.SenseBuf.offset
        for i, b in enumerate(cdb):
            spt_ptr.Cdb[i] = b

        try:
            handle = kernel32.CreateFileW(
                path, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
            if handle == INVALID_HANDLE_VALUE:
                return (0, b"", b"", f"CreateFileW failed ({ctypes.get_last_error()})")
            try:
                returned = wt.DWORD(0)
                ok = kernel32.DeviceIoControl(
                    handle, IOCTL_SCSI_PASS_THROUGH, io_buf, total, io_buf, total,
                    ctypes.byref(returned), None)
                if not ok:
                    return (0, b"", b"", f"DeviceIoControl failed ({ctypes.get_last_error()})")
            finally:
                kernel32.CloseHandle(handle)
        except OSError as e:
            # P1-9: keep the probe alive on unexpected OS errors (parity with posix).
            return (0, b"", b"", f"OSError: {e}")

        spt_out = ctypes.cast(io_buf, ctypes.POINTER(ScsiPassThrough)).contents
        data = bytes(io_buf.raw[ctypes.sizeof(ScsiPassThrough): ctypes.sizeof(ScsiPassThrough) + alloc])
        sense = bytes(spt_out.SenseBuf[: spt_out.SenseInfoLength])
        return (spt_out.ScsiStatus, sense, data, "")

elif os.name != "posix":  # posix backend defined above; only guard exotic platforms
    def scsi_execute(path, cdb, alloc, timeout_s):  # pragma: no cover
        raise RuntimeError(f"unsupported platform: {platform.system()}")

# ---------------------------------------------------------------------------
# Sense classification
# ---------------------------------------------------------------------------
def _sense_is_invalid(sense):
    """True when a CHECK CONDITION arrived without usable sense data: too
    short, or the response code is not a valid fixed/descriptor format
    (kernel scsi_sense_valid: (sense[0] & 0x70) == 0x70)."""
    return len(sense) < 2 or (sense[0] & 0x70) != 0x70


def _parse_sense(sense):
    """Normalize a sense buffer into (key, asc, ascq) per Linux
    drivers/scsi/scommon.c scsi_normalize_sense() (P1-6):
      * descriptor format (response code >= 0x72, e.g. 0x72/0x73):
        key at byte 1 bits 3-0, ASC/ASCQ at bytes 2/3 (additional length
        at byte 7)
      * fixed format (0x70/0x71): key at byte 2 bits 3-0, ASC/ASCQ at
        bytes 12/13, clamped by the additional length field (byte 7 + 8)
    Returns (0, 0, 0) for invalid/empty sense data."""
    if _sense_is_invalid(sense):
        return 0, 0, 0
    response_code = sense[0] & 0x7F
    if response_code >= 0x72:  # descriptor format
        return sense[1] & 0x0F, sense[2], sense[3]
    # fixed format (0x70/0x71)
    key = sense[2] & 0x0F
    total = min(len(sense), sense[7] + 8) if len(sense) > 7 else len(sense)
    asc = sense[12] if total > 12 else 0
    ascq = sense[13] if total > 13 else 0
    return key, asc, ascq


def classify(status, sense, err_str):
    """Map (status, sense, err) to a result label + human detail string."""
    if err_str:
        # SG_IO aborts after hdr.timeout and returns EIO (5); ETIMEDOUT (110) too
        if "errno=5" in err_str or "errno=110" in err_str:
            return "TIMEOUT", f"ioctl error ({err_str})"
        return "OTHER", err_str
    if status == 0x00:
        return "SUPPORTED", "GOOD"
    if status != 0x02:  # not CHECK CONDITION
        return "OTHER", f"status=0x{status:02x} sense={sense.hex(' ')}"

    # CHECK CONDITION with invalid/empty sense data (e.g. some virtual devices)
    if _sense_is_invalid(sense):
        return "OTHER", f"CHECK CONDITION, empty sense data sense={sense.hex(' ')}"

    key, asc, ascq = _parse_sense(sense)
    key_name = SENSE_KEY_NAMES.get(key, f"key 0x{key:02x}")
    asc_name = ASC_NAMES.get(asc, "")
    brief = f"{key_name} ({key}/0x{asc:02x}/0x{ascq:02x})"
    if asc_name:
        brief += f" {asc_name}"

    if key == 0x05:  # ILLEGAL_REQUEST
        if asc == 0x20 and ascq == 0x00:
            return "NOT_SUPPORTED", brief  # INVALID COMMAND OPERATION CODE
        return "SUPPORTED", brief            # opcode exists, parameters rejected
    if key == 0x02 and asc in (0x3A, 0x04):
        return "NEEDS_MEDIA", brief
    if key == 0x06:  # UNIT ATTENTION (media change) -> command exists
        return "SUPPORTED", brief
    if key == 0x07 and asc == 0x27:  # WRITE PROTECTED
        return "SUPPORTED", brief
    return "OTHER", brief + f" sense={sense.hex(' ')}"


def classify_cd_block_type(status, sense, err_str):
    """Per-Data-Block-Type result for READ CD (MMC-6 Table 352).

    Unlike classify(): for READ CD, a 'parameter rejected' (ILLEGAL REQUEST
    + INVALID FIELD IN CDB 0x24 / LBA OUT OF RANGE 0x25) means the drive
    rejects that particular block type, so the TYPE is NOT_SUPPORTED even
    though the opcode exists (other types may still be SUPPORTED).
    """
    label, detail = classify(status, sense, err_str)
    if label == "SUPPORTED":
        key, asc, _ascq = _parse_sense(sense)
        if key == 0x05 and asc in (0x24, 0x25):
            return "NOT_SUPPORTED", detail
    return label, detail


REQUEST_SENSE_CDB = bytes([0x03, 0, 0, 0, 0x12, 0])


def _scsi_execute_rescued(dev, cdb, alloc, timeout_s, direction="in", out_data=b""):
    """scsi_execute + one-shot REQUEST SENSE rescue (P1-7): when a command
    returns CHECK CONDITION with invalid/empty sense (some USB bridges
    swallow auto-sense), re-issue REQUEST SENSE (0x03, alloc 18) once and
    classify with the recovered sense. Never recurses — the rescue call
    goes straight to scsi_execute."""
    status, sense, data, err = scsi_execute(dev, cdb, alloc, timeout_s,
                                            direction=direction, out_data=out_data)
    if status == 0x02 and not err and _sense_is_invalid(sense):
        rs_status, rs_sense, rs_data, rs_err = scsi_execute(dev, REQUEST_SENSE_CDB, 18, timeout_s)
        recovered = rs_data if (len(rs_data) >= 2 and rs_data[0] != 0) else rs_sense
        if not rs_err and rs_status == 0x00 and not _sense_is_invalid(recovered):
            return status, recovered, data, err
    return status, sense, data, err


def _read_cd_cdb(code):
    """READ CD (0xBE) CDB for one Table 352 matrix row. Layout mirrors Linux
    drivers/cdrom/cdrom.c cdrom_read_block(): cmd[1] = EST<<2, cmd[6..8] =
    24-bit transfer length (fixed 1 block), cmd[9] = flags (0xF8 raw /
    0x10 user data / 0x50 sub-header+user), cmd[10] = sub-channel."""
    bt = CD_BLOCK_TYPES[code]
    return bytes([0xBE, (bt["est"] & 0x3F) << 2, 0, 0, 0, 0,
                  0x00, 0x00, 0x01, bt["flags"], bt["subch"], 0])

# ---------------------------------------------------------------------------
# Payload parsers
# ---------------------------------------------------------------------------
def _txt(b):
    """ASCII text field, tolerant of NUL / space padding."""
    return b.decode("ascii", "replace").replace("\x00", "").strip()

def parse_inquiry(data):
    if len(data) < 36:
        return None
    out = {
        "peripheral_type": data[0] & 0x1F,
        "additional_length": data[4],
        "vendor": _txt(data[8:16]),
        "product": _txt(data[16:32]),
        "revision": _txt(data[32:36]),
    }
    return out

def parse_get_configuration(data):
    """Returns (current_profile, profiles, features)."""
    if len(data) < 8:
        return None, [], []
    # Belt-and-suspenders (P0-4): bytes 0-1 Data Length give the true response
    # size (8-byte header + descriptor list); drop zero padding / stale tail.
    data_len = struct.unpack(">H", data[0:2])[0]
    total = 8 + data_len
    if total < len(data):
        data = data[:total]
    current_profile = struct.unpack(">H", data[6:8])[0]
    profiles, features = [], []
    off = 8
    seen = 0
    while off + 4 <= len(data) and seen < 100:
        code = struct.unpack(">H", data[off:off + 2])[0]
        flags = data[off + 2]
        add_len = data[off + 3]
        off += 4
        body = data[off:off + add_len]
        off += add_len
        seen += 1
        if code == 0x0000:  # Profile List feature
            p = 0
            while p + 4 <= len(body):
                pnum = struct.unpack(">H", body[p:p + 2])[0]
                cur = bool(body[p + 2] & 0x01)
                profiles.append({"code": pnum, "current": cur})
                p += 4
        features.append({"code": code, "current": bool(flags & 0x01),
                         "persistent": bool(flags & 0x02)})
        if off >= len(data):
            break
    return current_profile, profiles, features

def parse_disc_info(data):
    """Disc Type lives in byte 8 bits 3-0 (MMC-3 r10g Disc Information block)."""
    if len(data) <= 8:
        return None
    return data[8] & 0x0F

def name_profile(code):
    return PROFILE_NAMES.get(code, "unknown")

def name_feature(code):
    return FEATURE_NAMES.get(code, "unknown")

def name_disc_type(t):
    return DISC_TYPE_NAMES.get(t, "unknown")

def name_block_size(size):
    """Human label for a READ CAPACITY block length (media sector size).
    2352 = CD raw sector; DVD/BD/HD-DVD are fixed 2048; None = no media."""
    if size is None:
        return "unknown"
    if size == 2352:
        return "2352 (CD raw)"
    return str(size)

def name_peripheral(t):
    return PERIPHERAL_NAMES.get(t, "unknown")

# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------
def discover_devices():
    """Return a list of candidate device paths for the current platform."""
    if os.name == "posix":
        paths = []
        for pat in ("/dev/sg*", "/dev/sr*"):
            paths.extend(__import__("glob").glob(pat))
        return sorted(set(paths))
    if os.name == "nt":
        paths = []
        for i in range(16):
            paths.append(rf"\\.\CdRom{i}")
        for i in range(16):
            paths.append(rf"\\.\Scsi{i}")
        return paths
    return []

def inquiry(dev, timeout_s):
    """Best-effort INQUIRY (EVPD=0). Returns (info_dict, ok_bool, err)."""
    status, sense, data, err = scsi_execute(dev, bytes([0x12, 0, 0, 0, 0x60, 0]), 96, timeout_s)
    if err or status != 0x00:
        return None, False, err or f"status=0x{status:02x}"
    info = parse_inquiry(data)
    return info, info is not None, "" if info else "short INQUIRY data"

def inquiry_serial(dev, timeout_s):
    """Best-effort INQUIRY EVPD page 0x80 (unit serial number). Never fatal."""
    status, sense, data, err = scsi_execute(dev, bytes([0x12, 0x01, 0x80, 0, 0xFC, 0]), 252, timeout_s)
    if err or status != 0x00 or len(data) < 5:
        return None
    return data[4:].decode("ascii", "replace").strip()

# ---------------------------------------------------------------------------
# Full device probe
# ---------------------------------------------------------------------------
def parse_rsoc(data):
    """MAINTENANCE IN / REPORT SUPPORTED OPERATION CODES (SPC-3 SA=0x0C).
    Returns sorted list of opcodes the drive reports as supported (RT=0:
    8-byte descriptors, opcode in byte 0)."""
    if len(data) < 4:
        return []
    ops = []
    off = 4  # 2-byte data length + 2 reserved
    while off + 4 <= len(data):
        op = data[off]
        if op != 0:
            ops.append(op)
        off += 8  # RT=0: 8-byte support descriptors
    return sorted(set(ops))


def fw_flash_blocked(cmd):
    """Anti-brick hard rule (Jerry): WRITE BUFFER (0x3B) with any firmware
    download/update mode (mode byte != 0x00, e.g. 0x04-0x0F) would flash the
    ODD firmware — never sent, not even under --dangerous. Fail-safe: a
    malformed/short CDB is treated as blocked."""
    if cmd.get("op") != 0x3B:
        return False
    cdb = cmd.get("cdb") or b""
    return len(cdb) < 2 or cdb[1] != 0x00


def probe_device(dev, timeout_s, dangerous, progress_cb=None):
    """Probe one device; returns a dict (JSON-serializable).

    progress_cb(done, total) is invoked after each matrix command when given
    (GUI progress bar); the CLI never passes one, so output is unchanged.
    """
    t0 = time.time()
    result = {
        "device": dev,
        "mode": "full-compat" if dangerous else "safe",
        "rsoc_opcodes": [],
        "vendor": None, "product": None, "revision": None,
        "peripheral_type": None, "peripheral_type_name": None,
        "serial_number": None,
        "current_profile": None, "current_profile_name": None,
        "profiles": [], "features": [], "media_type": None,
        "media_block_size": None, "media_block_size_name": "unknown",
        "block_type_matrix": [],
        "commands": [], "summary": {}, "duration_sec": 0.0,
    }

    # 1) INQUIRY
    info, ok, err = inquiry(dev, timeout_s)
    if ok and info:
        result.update({
            "vendor": info["vendor"], "product": info["product"],
            "revision": info["revision"],
            "peripheral_type": info["peripheral_type"],
            "peripheral_type_name": name_peripheral(info["peripheral_type"]),
        })
        result["serial_number"] = inquiry_serial(dev, timeout_s)

    # 2) GET CONFIGURATION (also feeds the matrix below)
    gc_cmd = next(c for c in CMDS if c["op"] == 0x46)
    gc_status, gc_sense, gc_data, gc_err = _scsi_execute_rescued(
        dev, gc_cmd["cdb"], gc_cmd["alloc"], timeout_s)
    if not gc_err and gc_status == 0x00 and gc_data:
        current, profiles, features = parse_get_configuration(gc_data)
        result["current_profile"] = current
        result["current_profile_name"] = name_profile(current)
        result["profiles"] = profiles
        result["features"] = features

    # 3) READ DISC INFORMATION
    disc_type = None
    di_cmd = next(c for c in CMDS if c["op"] == 0x51)
    di_status, di_sense, di_data, di_err = _scsi_execute_rescued(
        dev, di_cmd["cdb"], di_cmd["alloc"], timeout_s)
    if not di_err and di_status == 0x00:
        disc_type = parse_disc_info(di_data)
    if disc_type is not None:
        result["media_type"] = f"{name_disc_type(disc_type)} (disc type 0x{disc_type:02x})"
    elif result["current_profile_name"] and result["current_profile_name"] != "unknown":
        result["media_type"] = f"{result['current_profile_name']} (via current profile 0x{result['current_profile']:04x})"
    else:
        result["media_type"] = "unknown"

    # 4) READ CAPACITY — media sector (block) size; READ 10 alloc depends on
    #    it (CD raw is 2352 B, DVD/BD/HD-DVD are fixed 2048 B).
    media_block_size = None
    rc_status, rc_sense, rc_data, rc_err = _scsi_execute_rescued(
        dev, bytes([0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 8, timeout_s)
    if not rc_err and rc_status == 0x00 and len(rc_data) >= 8:
        block_len = struct.unpack(">I", rc_data[4:8])[0]
        # P0-6: accept sane media sector sizes only (512..4096). Empty-media
        # firmware sometimes reports 0xFFFFFFFF — treat as None (READ 10 / WRITE
        # alloc falls back to 2352) instead of a 4 GB create_string_buffer.
        if 512 <= block_len <= 4096:
            media_block_size = block_len
    result["media_block_size"] = media_block_size
    result["media_block_size_name"] = name_block_size(media_block_size)

    # 5) READ CD — probe every Table 352 matrix row. Each
    #    type is one matrix row (alloc = that type's block size); results are
    #    merged into the summary and drive the progress bar (82 total steps).
    block_type_matrix = []
    for code in CD_BLOCK_TYPE_CODES:
        bt = CD_BLOCK_TYPES[code]
        status, sense, data, err = _scsi_execute_rescued(dev, _read_cd_cdb(code), bt["size"], timeout_s)
        label, detail = classify_cd_block_type(status, sense, err)
        block_type_matrix.append({
            "code": code, "size": bt["size"], "name": bt["name"],
            "mandatory": bt["mandatory"], "result": label, "detail": detail,
            "sense_hex": sense.hex(" ") if sense else "",
        })
    result["block_type_matrix"] = block_type_matrix

    # 6) Command matrix (cache the commands already executed above)
    cache = {}
    for cmd in CMDS:
        op = cmd["op"]
        if op == 0x12:
            if ok and info:
                cache[op] = ("SUPPORTED", "GOOD (cached from INQUIRY)")
            else:
                # Device could not be opened / INQUIRY failed — do NOT claim
                # support (found via Windows real-machine test: CreateFileW
                # failure previously still reported 0x12 as SUPPORTED).
                cache[op] = classify(0, b"", err or "INQUIRY failed")
        elif op == 0x46:
            if not gc_err and gc_status == 0x00:
                cache[op] = ("SUPPORTED", "GOOD (cached from GET CONFIGURATION)")
            else:
                cache[op] = classify(gc_status, gc_sense, gc_err)
        elif op == 0x51:
            if not di_err and di_status == 0x00:
                cache[op] = ("SUPPORTED", "GOOD (cached from READ DISC INFORMATION)")
            else:
                cache[op] = classify(di_status, di_sense, di_err)
        elif op == 0x25:
            if not rc_err and rc_status == 0x00:
                cache[op] = ("SUPPORTED", "GOOD (cached from READ CAPACITY)")
            else:
                cache[op] = classify(rc_status, rc_sense, rc_err)

    summary = {"SUPPORTED": 0, "NOT_SUPPORTED": 0, "NEEDS_MEDIA": 0,
               "SKIPPED": 0, "TIMEOUT": 0, "OTHER": 0}
    for idx, cmd in enumerate(CMDS):
        if progress_cb:
            progress_cb(idx + 1, TOTAL_PROBE_STEPS)
        op = cmd["op"]
        entry = {"opcode": f"0x{op:02X}", "name": cmd["name"], "category": cmd["cat"]}
        if cmd.get("legacy"):
            entry["legacy"] = True

        if fw_flash_blocked(cmd):
            entry.update(result="SKIPPED",
                         detail=f"BLOCKED by firmware-flash protection: WRITE BUFFER mode 0x{cmd['cdb'][1]:02X} (firmware download/update) is never sent — anti-brick hard rule")
            summary["SKIPPED"] += 1
            result["commands"].append(entry)
            continue

        if cmd.get("dangerous") and not dangerous:
            entry.update(result="SKIPPED", detail="--dangerous full-compat mode not enabled")
            summary["SKIPPED"] += 1
            result["commands"].append(entry)
            continue

        if op in cache:
            label, detail = cache[op]
        else:
            alloc = cmd["alloc"]
            out_data = b""
            if op in (0x28, 0xA8):
                # READ 10 / READ 12: exactly 1 block — allocate the media's real
                # sector size (READ CAPACITY) or the CD raw maximum when unknown.
                alloc = media_block_size or MAX_SECTOR_SIZE
            elif op in (0x2A, 0xAA, 0x2E):
                # WRITE 10 / WRITE 12 / WRITE AND VERIFY: full-compat real write.
                alloc = media_block_size or MAX_SECTOR_SIZE
                out_data = b"\xAA" * alloc
            elif op == 0x04:
                # FORMAT UNIT: 12-byte parameter list (FmtData=1, descriptor: 0
                # blocks = whole disc, Full Format, Type Dependent 0800h).
                out_data = bytes([0x10, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x08, 0x00, 0x00])
            elif op == 0x3B and dangerous:
                # WRITE BUFFER mode 0x00 (combined header+data): 4-byte header
                # (buffer id 0, offset 0) + 4 data bytes. Firmware modes are NEVER used.
                out_data = bytes([0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA])
            status, sense, data, err = _scsi_execute_rescued(dev, cmd["cdb"], alloc, timeout_s,
                                                             direction=cmd.get("dir", "in"),
                                                             out_data=out_data)
            label, detail = classify(status, sense, err)
            if cmd.get("rsoc") and label == "SUPPORTED" and data:
                result["rsoc_opcodes"] = parse_rsoc(data)
            entry["sense_hex"] = sense.hex(" ") if sense else ""
            if cmd.get("danger_note") and dangerous:
                detail = f"{detail} [{cmd['danger_note']}]"
        entry["result"] = label
        entry["detail"] = detail
        summary[label] = summary.get(label, 0) + 1
        result["commands"].append(entry)

    # 7) Block type results are part of the probe: merged into the summary
    #    and counted by the progress bar (total = TOTAL_PROBE_STEPS).
    for bi, bt in enumerate(block_type_matrix):
        if progress_cb:
            progress_cb(len(CMDS) + bi + 1, TOTAL_PROBE_STEPS)
        summary[bt["result"]] = summary.get(bt["result"], 0) + 1

    result["summary"] = summary
    result["duration_sec"] = round(time.time() - t0, 2)
    return result

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def format_human(r):
    mode_tag = "FULL COMPATIBILITY TEST MODE (--dangerous)" if r.get("mode") == "full-compat" else "safe mode"
    lines = [f"=== Device: {r['device']} ==="]
    lines.append(f"Mode                   : {mode_tag}")
    lines.append(f"Vendor / Product / Rev : {r['vendor'] or '?'} / {r['product'] or '?'} / {r['revision'] or '?'}")
    pt = r["peripheral_type"]
    lines.append(f"Peripheral Type        : {'0x%02x (%s)' % (pt, r['peripheral_type_name'])}" if pt is not None else "Peripheral Type        : ?")
    lines.append(f"Serial Number          : {r['serial_number'] or 'n/a'}")
    if r["current_profile"] is not None:
        lines.append(f"Current Profile        : 0x{r['current_profile']:04x} ({r['current_profile_name']})")
    if r["profiles"]:
        prof_strs = []
        for p in sorted(r["profiles"], key=lambda x: x["code"]):
            mark = "[*]" if p["current"] else "[ ]"
            prof_strs.append(f"{mark}0x{p['code']:02x} {name_profile(p['code'])}")
        lines.append(f"Supported Profiles ({len(r['profiles'])}): " + " ".join(prof_strs))
    if r["features"]:
        feat_strs = [f"0x{f['code']:04x} {name_feature(f['code'])}{'*' if f['current'] else ''}"
                     for f in r["features"]]
        lines.append(f"Features ({len(r['features'])}): " + ", ".join(feat_strs))
    lines.append(f"Media Detected         : {r['media_type']}")
    lines.append(f"Media Block Size       : {r['media_block_size_name']}")
    if r.get("rsoc_opcodes"):
        lines.append(f"Drive-Reported Opcodes   : {len(r['rsoc_opcodes'])} supported ({', '.join(f'0x{op:02X}' for op in r['rsoc_opcodes'][:24])}{'...' if len(r['rsoc_opcodes'])>24 else ''})")
    lines.append("")
    lines.append("SCSI Command Matrix:")
    lines.append(f"  {'Opcode':<8}{'Name':<34}{'Category':<11}{'Result':<14}Detail")
    for c in r["commands"]:
        icon = {"SUPPORTED": "✅", "NOT_SUPPORTED": "❌", "NEEDS_MEDIA": "💿",
                "SKIPPED": "🔒", "TIMEOUT": "⏱️", "OTHER": "⚠️"}.get(c["result"], "?")
        lines.append(f"  {c['opcode']:<8}{c['name']:<34}{c['category']:<11}{icon + ' ' + c['result']:<14} {c['detail']}")
    if r.get("block_type_matrix"):
        lines.append("")
        lines.append("Data Block Type Matrix (READ CD 0xBE):")
        lines.append(f"  {'Code':<6}{'Size':<7}{'Type':<50}Result")
        for bt in r["block_type_matrix"]:
            icon = {"SUPPORTED": "✅", "NOT_SUPPORTED": "❌", "NEEDS_MEDIA": "💿",
                    "SKIPPED": "🔒", "TIMEOUT": "⏱️", "OTHER": "⚠️"}.get(bt["result"], "?")
            lines.append(f"  {bt['code']:<6}{bt['size']:<7}{bt['name']:<50}{icon} {bt['result']}")
    s = r["summary"]
    lines.append("")
    lines.append(f"Summary: {s['SUPPORTED']} SUPPORTED / {s['NOT_SUPPORTED']} NOT SUPPORTED / "
                 f"{s['NEEDS_MEDIA']} NEEDS_MEDIA / {s['SKIPPED']} SKIPPED / "
                 f"{s['TIMEOUT']} TIMEOUT / {s['OTHER']} OTHER")
    return "\n".join(lines)

def format_list(dev, info, ok, err):
    if ok and info:
        pt = info["peripheral_type"]
        return (f"{dev:<16} {info['vendor'] or '?':<10} {info['product'] or '?':<20} "
                f"rev {info['revision'] or '?':<6} type 0x{pt:02x} ({name_peripheral(pt)})")
    return f"{dev:<16} (unavailable: {err})"

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _positive_int(text):
    """argparse type: reject 0 / negatives instead of silently clamping to 1ms."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer (got {value})")
    return value


def main(argv=None):
    # Windows consoles use legacy codepages (cp950 on zh-TW); the human report
    # contains symbols (✅ ⚠ …) that cannot be encoded there. Replace instead
    # of crashing; UTF-8 terminals keep the full glyphs.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass  # not a text stream (test capture) or already configured

    p = argparse.ArgumentParser(
        prog="odd_probe.py",
        description="USB ODD (optical disc drive) SCSI command support probe — CD/DVD/BD/HD-DVD/DDCD",
        epilog="Modes: default = safe (destructive commands skipped with a hint); "
               "--dangerous = FULL COMPATIBILITY TESTING (every command sent with real "
               "parameters, incl. BLANK/FORMAT/CLOSE TRACK/WRITE/tray eject). "
               "Only exception: WRITE BUFFER firmware modes are never used.",
    )
    p.add_argument("mode", nargs="?", choices=["list"], help="list detected SCSI/optical devices")
    p.add_argument("--device", metavar="PATH", help="device node to probe (e.g. /dev/sr0, /dev/sg2, \\\\.\\CdRom0)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--html", action="store_true", help="standalone fancy HTML report to stdout")
    p.add_argument("--dangerous", action="store_true",
                   help="FULL COMPATIBILITY mode: send every command with real parameters "
                        "(BLANK erases disc, FORMAT UNIT formats, WRITE writes, LOAD/UNLOAD "
                        "operates the tray). Intended for ODD product compatibility testing.")
    p.add_argument("--timeout", type=_positive_int, default=5, metavar="SEC", help="per-command timeout in seconds (default 5)")
    args = p.parse_args(argv)

    if args.mode == "list":
        if args.device:
            p.error("'list' cannot be combined with --device")
        devs = discover_devices()
        print(f"Found {len(devs)} candidate device(s):")
        for dev in devs:
            try:
                info, ok, err = inquiry(dev, args.timeout)
            except OSError as e:
                print(format_list(dev, None, False, str(e)))
                continue
            print(format_list(dev, info, ok, err))
        return 0

    if not args.device:
        p.error("either 'list' or --device is required")
    if not os.path.exists(args.device) and os.name == "posix":
        print(f"error: {args.device} does not exist", file=sys.stderr)
        return 2

    try:
        res = probe_device(args.device, args.timeout, args.dangerous)
    except OSError as e:
        print(f"error: cannot access {args.device}: {e}", file=sys.stderr)
        return 2

    if args.html:
        import report_html
        print(report_html.format_html(res))
    elif args.json:
        json.dump(res, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print(format_human(res))
    return 0

if __name__ == "__main__":
    sys.exit(main())
