#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
odd_probe.py — USB ODD (optical disc drive) SCSI command support probe

Scans a SCSI/ATAPI optical device and reports:
  * INQUIRY identity (vendor / product / revision / peripheral type / serial)
  * GET CONFIGURATION feature & profile list (CD / DVD / BD / HD-DVD / DDCD)
  * READ DISC INFORMATION media type
  * READ CAPACITY media sector size (drives READ 10 buffer sizing)
  * Per-opcode support matrix for 45 SCSI commands + READ CD Table 600
    Data Block Type matrix (10 block types, safe probes only)

Zero third-party dependencies — pure Python stdlib (ctypes / struct / os / ...).

Usage:
  python3 odd_probe.py list                              # list SCSI/optical devices
  python3 odd_probe.py --device /dev/sr0                 # full probe, human output
  python3 odd_probe.py --device /dev/sg2 --json          # machine-readable JSON
  python3 odd_probe.py --device /dev/sg2 --dangerous     # enable write-class opcode probes
  python3 odd_probe.py --device /dev/sg2 --timeout 5     # per-command timeout (s)

Safety red lines (never compromise):
  * BLANK (0xA1) and CLOSE TRACK/SESSION (0x5B / 0x56) are NEVER sent,
    even with --dangerous.
  * Write-class commands are probed with zero-length / invalid parameter
    CDBs only, so no media is ever written.
  * No tray load/eject (no LoEJ), no formatting, no media writing.
"""

import argparse
import ctypes
import json
import os
import platform
import struct
import sys
import time

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

# MMC-6 Table 600 — READ CD Data Block Type (byte 1 bits 7-2): block size,
# name and Mandatory/Optional status. Codes 4-6 are Reserved, 7/15 NA Vendor
# Specific (never probed). Codes 8/10/13 are Mandatory for CD drives.
CD_BLOCK_TYPES = {
    0:  {"size": 2352, "name": "Raw data", "mandatory": False},
    1:  {"size": 2368, "name": "Raw data with P and Q Sub-channel", "mandatory": False},
    2:  {"size": 2448, "name": "Raw data with P-W Sub-channel appended, pack form", "mandatory": False},
    3:  {"size": 2448, "name": "Raw data with raw P-W Sub-channel appended", "mandatory": False},
    8:  {"size": 2048, "name": "Mode 1 ISO/IEC 10149", "mandatory": True},
    9:  {"size": 2336, "name": "Mode 2 ISO/IEC 10149", "mandatory": False},
    10: {"size": 2048, "name": "Mode 2 CD-ROM XA form 1", "mandatory": True},
    11: {"size": 2056, "name": "Mode 2 XA form 1 + 8B sub-header", "mandatory": False},
    12: {"size": 2324, "name": "Mode 2 XA form 2", "mandatory": False},
    13: {"size": 2332, "name": "Mode 2 XA form 1/2 mixed + 8B sub-header", "mandatory": True},
}
CD_BLOCK_TYPE_CODES = (0, 1, 2, 3, 8, 9, 10, 11, 12, 13)

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
# Command matrix: 45 opcodes covering SPC + MMC (all disc formats). READ CD
# (0xBE) is deliberately absent: it is expanded at probe time into the Table
# 600 Data Block Type matrix (10 types, see CD_BLOCK_TYPES / _read_cd_cdb).
#   cdb: bytes of the CDB template; alloc: data-in buffer size (0 = none)
#   unsafe: never send (destructive / would actually play audio)
#   dangerous: only sent when --dangerous, with inert parameter CDBs
# ---------------------------------------------------------------------------
CMDS = [
    # ---- SPC base ----
    {"op": 0x00, "name": "TEST UNIT READY", "cat": "SPC", "cdb": bytes([0x00, 0, 0, 0, 0, 0]), "alloc": 0},
    {"op": 0x03, "name": "REQUEST SENSE", "cat": "SPC", "cdb": bytes([0x03, 0, 0, 0, 0x12, 0]), "alloc": 18},
    {"op": 0x12, "name": "INQUIRY", "cat": "SPC", "cdb": bytes([0x12, 0, 0, 0, 0x60, 0]), "alloc": 96},
    {"op": 0x1A, "name": "MODE SENSE 6", "cat": "SPC", "cdb": bytes([0x1A, 0, 0x3F, 0, 0xFF, 0]), "alloc": 255},
    {"op": 0x1B, "name": "START STOP UNIT", "cat": "SPC", "cdb": bytes([0x1B, 0x01, 0, 0, 0x01, 0]), "alloc": 0},  # IMMED+START, no LoEJ
    {"op": 0x1E, "name": "PREVENT ALLOW MEDIUM REMOVAL", "cat": "SPC", "cdb": bytes([0x1E, 0, 0, 0, 0x00, 0]), "alloc": 0},  # prevent=0
    {"op": 0x25, "name": "READ CAPACITY", "cat": "SPC", "cdb": bytes([0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 8},
    {"op": 0x28, "name": "READ 10", "cat": "SPC", "cdb": bytes([0x28, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0]), "alloc": 512},  # LBA=0, transfer len=1 block; alloc overridden at runtime to media block size (READ CAPACITY) or 2352 fallback
    {"op": 0x2B, "name": "SEEK 10", "cat": "SPC", "cdb": bytes([0x2B, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0},
    {"op": 0x2F, "name": "VERIFY 10", "cat": "SPC", "cdb": bytes([0x2F, 0, 0, 0, 0, 0, 0, 0x00, 0, 0]), "alloc": 0},  # BYTCHK=0,len=0
    {"op": 0x35, "name": "SYNCHRONIZE CACHE 10", "cat": "SPC", "cdb": bytes([0x35, 0, 0, 0, 0, 0, 0, 0x00, 0, 0]), "alloc": 0},  # range 0 = no-op
    {"op": 0x3C, "name": "READ BUFFER", "cat": "SPC", "cdb": bytes([0x3C, 0x00, 0x00, 0, 0, 0, 0x00, 0x04, 0, 0]), "alloc": 4},  # mode 0 capacity header
    {"op": 0x5A, "name": "MODE SENSE 10", "cat": "SPC", "cdb": bytes([0x5A, 0, 0x3F, 0, 0, 0, 0, 0, 0xFF, 0xFF]), "alloc": 65535},
    {"op": 0x1C, "name": "RECEIVE DIAGNOSTIC RESULTS", "cat": "SPC", "cdb": bytes([0x1C, 0, 0x00, 0x00, 0x04, 0]), "alloc": 4},
    {"op": 0x1D, "name": "SEND DIAGNOSTIC", "cat": "SPC", "cdb": bytes([0x1D, 0, 0, 0, 0, 0]), "alloc": 0},  # self-test=0

    # ---- MMC optical commands (all formats) ----
    {"op": 0x23, "name": "READ FORMAT CAPACITIES", "cat": "MMC", "cdb": bytes([0x23, 0, 0, 0, 0, 0, 0x00, 0xFF, 0, 0]), "alloc": 255},
    {"op": 0x42, "name": "READ SUBCHANNEL", "cat": "MMC", "cdb": bytes([0x42, 0, 0x40, 0x01, 0, 0, 0x00, 0x20, 0, 0]), "alloc": 32},
    {"op": 0x43, "name": "READ TOC/PMA/ATIP", "cat": "MMC", "cdb": bytes([0x43, 0, 0, 0x00, 0, 0x00, 0x10, 0x00, 0, 0]), "alloc": 4096},
    {"op": 0x44, "name": "READ HEADER", "cat": "MMC", "cdb": bytes([0x44, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x20]), "alloc": 32},
    {"op": 0x45, "name": "PLAY AUDIO 10", "cat": "MMC", "cdb": bytes([0x45, 0, 0, 0, 0, 0, 0x00, 0x00, 0, 0]), "alloc": 0},  # len=0, no playback
    {"op": 0x46, "name": "GET CONFIGURATION", "cat": "MMC", "cdb": bytes([0x46, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0]), "alloc": 65535},
    {"op": 0x47, "name": "PLAY AUDIO MSF", "cat": "MMC", "cdb": bytes([0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "unsafe": "would actually play audio"},
    {"op": 0x48, "name": "PLAY AUDIO TRACK INDEX", "cat": "MMC", "cdb": bytes([0x48, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "unsafe": "would actually play audio"},
    {"op": 0x4A, "name": "GET EVENT STATUS NOTIFICATION", "cat": "MMC", "cdb": bytes([0x4A, 0x01, 0x00, 0, 0, 0, 0x00, 0x08, 0, 0]), "alloc": 8},
    {"op": 0x4B, "name": "PAUSE/RESUME", "cat": "MMC", "cdb": bytes([0x4B, 0, 0, 0, 0, 0, 0, 0, 0x00, 0]), "alloc": 0},  # resume=0 -> pause
    {"op": 0x51, "name": "READ DISC INFORMATION", "cat": "MMC", "cdb": bytes([0x51, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0]), "alloc": 65535},
    {"op": 0x52, "name": "READ TRACK INFORMATION", "cat": "MMC", "cdb": bytes([0x52, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0]), "alloc": 65535},
    {"op": 0xA0, "name": "REPORT KEY", "cat": "MMC", "cdb": bytes([0xA0, 0, 0x00, 0, 0, 0, 0, 0, 0x08, 0]), "alloc": 8},  # legacy class 0
    {"op": 0xA4, "name": "REPORT KEY", "cat": "MMC", "cdb": bytes([0xA4, 0, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x08, 0, 0]), "alloc": 8},
    {"op": 0xAC, "name": "GET PERFORMANCE", "cat": "MMC", "cdb": bytes([0xAC, 0, 0x00, 0, 0, 0, 0, 0, 0x00, 0x01, 0, 0, 0x00, 0x20, 0, 0]), "alloc": 32},
    {"op": 0xAD, "name": "READ DVD STRUCTURE", "cat": "MMC", "cdb": bytes([0xAD, 0, 0x00, 0, 0, 0, 0, 0x00, 0x08, 0x00, 0, 0]), "alloc": 2048},
    {"op": 0xBB, "name": "SET CD SPEED", "cat": "MMC", "cdb": bytes([0xBB, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0]), "alloc": 0},  # max speed

    # ---- write-class (dangerous, default skipped; inert parameter CDBs only) ----
    {"op": 0x15, "name": "MODE SELECT 6", "cat": "DANGEROUS", "cdb": bytes([0x15, 0, 0x00, 0x00, 0x00, 0x00]), "alloc": 0, "dangerous": True},  # paramlen=0
    {"op": 0x2A, "name": "WRITE 10", "cat": "DANGEROUS", "cdb": bytes([0x2A, 0, 0, 0, 0, 0, 0, 0x00, 0, 0]), "alloc": 0, "dangerous": True},  # len=0, no write
    {"op": 0x3B, "name": "WRITE BUFFER", "cat": "DANGEROUS", "cdb": bytes([0x3B, 0x00, 0x00, 0, 0, 0, 0x00, 0x00, 0, 0]), "alloc": 0, "dangerous": True},  # len=0
    {"op": 0x53, "name": "RESERVE TRACK", "cat": "DANGEROUS", "cdb": bytes([0x53, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0]), "alloc": 0, "dangerous": True},  # invalid track
    {"op": 0x54, "name": "SEND OPC INFORMATION", "cat": "DANGEROUS", "cdb": bytes([0x54, 0x00, 0, 0, 0, 0, 0, 0x00, 0x00, 0]), "alloc": 0, "dangerous": True},  # paramlen=0
    {"op": 0x55, "name": "MODE SELECT 10", "cat": "DANGEROUS", "cdb": bytes([0x55, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0]), "alloc": 0, "dangerous": True},  # paramlen=0
    {"op": 0x56, "name": "CLOSE TRACK/SESSION (old)", "cat": "DANGEROUS", "cdb": bytes([0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "unsafe": "closes session/track"},
    {"op": 0x5B, "name": "CLOSE TRACK/SESSION", "cat": "DANGEROUS", "cdb": bytes([0x5B, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "unsafe": "closes session/track"},
    {"op": 0x5D, "name": "SEND CUE SHEET", "cat": "DANGEROUS", "cdb": bytes([0x5D, 0, 0x00, 0, 0, 0, 0, 0, 0x00, 0x00]), "alloc": 0, "dangerous": True},  # paramlen=0
    {"op": 0xA1, "name": "BLANK", "cat": "DANGEROUS", "cdb": bytes([0xA1, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "unsafe": "erases entire disc"},
    {"op": 0xA2, "name": "SEND KEY", "cat": "DANGEROUS", "cdb": bytes([0xA2, 0, 0x00, 0, 0, 0, 0, 0, 0x00, 0]), "alloc": 0, "dangerous": True},  # paramlen=0
    {"op": 0xB6, "name": "SET STREAMING", "cat": "DANGEROUS", "cdb": bytes([0xB6, 0, 0, 0, 0, 0, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]), "alloc": 0, "dangerous": True},  # paramlen=0
    {"op": 0xBF, "name": "SEND DVD STRUCTURE", "cat": "DANGEROUS", "cdb": bytes([0xBF, 0x00, 0x00, 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0x00, 0x00, 0, 0]), "alloc": 0, "dangerous": True},  # paramlen=0
]

# Total probe steps = 45 opcodes + 10 READ CD Table 600 block types (55).
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

    def scsi_execute(path, cdb, alloc, timeout_s):
        """Run one SCSI command via SG_IO. Returns (status, sense_bytes, data_bytes, err_str)."""
        dxfer_dir = SG_DXFER_FROM_DEV if alloc > 0 else SG_DXFER_NONE
        cdb_buf = ctypes.create_string_buffer(bytes(cdb), len(cdb))
        sense_buf = ctypes.create_string_buffer(32)  # 32B: classification needs ASC/ASCQ at 12/13
        data_buf = ctypes.create_string_buffer(max(alloc, 1)) if alloc > 0 else None
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

        fd = os.open(path, os.O_RDWR)
        try:
            rc = _libc.ioctl(fd, SG_IO, ctypes.byref(hdr))
        finally:
            os.close(fd)
        if rc != 0:
            errno = ctypes.get_errno()
            if hdr.status == 0x02:  # CHECK CONDITION delivered despite ioctl error
                pass  # fall through to sense classification
            else:
                return (0, bytes(sense_buf.raw), b"", f"ioctl error errno={errno}")
        data = bytes(data_buf.raw[:alloc]) if data_buf else b""
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

    _configure_windows_ctypes(ctypes.windll.kernel32)

    def scsi_execute(path, cdb, alloc, timeout_s):
        """Run one SCSI command via IOCTL_SCSI_PASS_THROUGH. Same return contract."""
        kernel32 = ctypes.windll.kernel32
        spt = ScsiPassThrough()
        data_buf = ctypes.create_string_buffer(max(alloc, 1)) if alloc > 0 else ctypes.create_string_buffer(1)
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
        spt_ptr.DataIn = SCSI_IOCTL_DATA_IN if alloc > 0 else SCSI_IOCTL_DATA_UNSPECIFIED
        spt_ptr.DataTransferLength = alloc
        spt_ptr.TimeOutValue = max(1, int(timeout_s))
        spt_ptr.DataBufferOffset = ctypes.sizeof(ScsiPassThrough)
        spt_ptr.SenseInfoOffset = ScsiPassThrough.SenseBuf.offset
        for i, b in enumerate(cdb):
            spt_ptr.Cdb[i] = b

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
    if len(sense) < 2 or (sense[0] == 0 and sense[1] == 0):
        return "OTHER", f"CHECK CONDITION, empty sense data sense={sense.hex(' ')}"

    key = sense[2] & 0x0F if len(sense) > 2 else 0
    asc = sense[12] if len(sense) > 12 else 0
    ascq = sense[13] if len(sense) > 13 else 0
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
    """Per-Data-Block-Type result for READ CD (MMC Table 600).

    Unlike classify(): for READ CD, a 'parameter rejected' (ILLEGAL REQUEST
    + INVALID FIELD IN CDB 0x24 / LBA OUT OF RANGE 0x25) means the drive
    rejects that particular block type, so the TYPE is NOT_SUPPORTED even
    though the opcode exists (other types may still be SUPPORTED).
    """
    label, detail = classify(status, sense, err_str)
    if label == "SUPPORTED":
        key = sense[2] & 0x0F if len(sense) > 2 else 0
        asc = sense[12] if len(sense) > 12 else 0
        if key == 0x05 and asc in (0x24, 0x25):
            return "NOT_SUPPORTED", detail
    return label, detail


def _read_cd_cdb(code):
    """READ CD (0xBE) CDB for one Data Block Type code: byte 1 bits 7-2 =
    code, byte 6 = user-data flag for user-data types (8-13), 1 block."""
    byte6 = 0x10 if code >= 8 else 0x00  # User Data bit for user-data types
    return bytes([0xBE, (code & 0x3F) << 2, 0, 0, 0, 0, byte6, 0x00, 0x01, 0, 0, 0])

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
def probe_device(dev, timeout_s, dangerous, progress_cb=None):
    """Probe one device; returns a dict (JSON-serializable).

    progress_cb(done, total) is invoked after each matrix command when given
    (GUI progress bar); the CLI never passes one, so output is unchanged.
    """
    t0 = time.time()
    result = {
        "device": dev,
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
    gc_status, gc_sense, gc_data, gc_err = scsi_execute(
        dev, bytes([0x46, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0]), 65535, timeout_s)
    if not gc_err and gc_status == 0x00 and gc_data:
        current, profiles, features = parse_get_configuration(gc_data)
        result["current_profile"] = current
        result["current_profile_name"] = name_profile(current)
        result["profiles"] = profiles
        result["features"] = features

    # 3) READ DISC INFORMATION
    disc_type = None
    di_status, di_sense, di_data, di_err = scsi_execute(
        dev, bytes([0x51, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0]), 65535, timeout_s)
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
    rc_status, rc_sense, rc_data, rc_err = scsi_execute(
        dev, bytes([0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 8, timeout_s)
    if not rc_err and rc_status == 0x00 and len(rc_data) >= 8:
        block_len = struct.unpack(">I", rc_data[4:8])[0]
        if block_len > 0:
            media_block_size = block_len
    result["media_block_size"] = media_block_size
    result["media_block_size_name"] = name_block_size(media_block_size)

    # 5) READ CD — probe every valid Data Block Type (MMC Table 600). Each
    #    type is one matrix row (alloc = that type's block size); results are
    #    merged into the summary and drive the progress bar (55 total steps).
    block_type_matrix = []
    for code in CD_BLOCK_TYPE_CODES:
        bt = CD_BLOCK_TYPES[code]
        status, sense, data, err = scsi_execute(dev, _read_cd_cdb(code), bt["size"], timeout_s)
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
            cache[op] = ("SUPPORTED", "GOOD (cached from INQUIRY)")
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

        if cmd.get("unsafe"):
            entry.update(result="SKIPPED", detail=f"🔒 unsafe to test ({cmd['unsafe']})")
            summary["SKIPPED"] += 1
            result["commands"].append(entry)
            continue
        if cmd.get("dangerous") and not dangerous:
            entry.update(result="SKIPPED", detail="--dangerous not enabled")
            summary["SKIPPED"] += 1
            result["commands"].append(entry)
            continue

        if op in cache:
            label, detail = cache[op]
        else:
            # READ 10 transfers exactly 1 block — allocate the media's actual
            # sector size (READ CAPACITY) or the CD raw maximum when unknown.
            if op == 0x28:
                alloc = media_block_size or MAX_SECTOR_SIZE
            else:
                alloc = cmd["alloc"]
            status, sense, data, err = scsi_execute(dev, cmd["cdb"], alloc, timeout_s)
            label, detail = classify(status, sense, err)
            entry["sense_hex"] = sense.hex(" ") if sense else ""
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
    lines = [f"=== Device: {r['device']} ==="]
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
    p = argparse.ArgumentParser(
        prog="odd_probe.py",
        description="USB ODD (optical disc drive) SCSI command support probe — CD/DVD/BD/HD-DVD/DDCD",
        epilog="Safety: BLANK / CLOSE TRACK/SESSION are NEVER sent, even with --dangerous.",
    )
    p.add_argument("mode", nargs="?", choices=["list"], help="list detected SCSI/optical devices")
    p.add_argument("--device", metavar="PATH", help="device node to probe (e.g. /dev/sr0, /dev/sg2, \\\\.\\CdRom0)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--dangerous", action="store_true",
                   help="probe write-class opcodes with inert parameter CDBs (BLANK/CLOSE never sent)")
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

    if args.json:
        json.dump(res, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print(format_human(res))
    return 0

if __name__ == "__main__":
    sys.exit(main())
