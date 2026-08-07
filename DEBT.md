# Technical Debt Ledger (`DEBT.md`)

| Date | Module/Line | Shortcut Taken | Reason/Blocker | Upgrade Path (How to fix) | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-08-07 | `odd_probe.py` `scsi_execute()` (posix) | sense buffer 用 32B（任務書寫 8B） | 判定邏輯需要 ASC/ASCQ（固定 sense offset 12/13），8B 裝不下 | 無需升級：屬必要偏離，已於 README 註明 | Low |
| 2026-08-07 | `odd_probe.py` Windows backend | 已補 `CreateFileW`/`DeviceIoControl` 的 `restype`/`argtypes`（HANDLE/BOOL，64-bit 不截斷）並程式化驗證 `SCSI_PASS_THROUGH` layout（pshpack4，76B，含 round-trip）；仍僅結構驗證，未實機測試 | 開發環境為 WSL2/Linux，無 Windows 主機 | 在真實 Windows 機器以光碟機實測 `list` / `--device \\.\CdRom0`（含 64-bit OS 驗證 HANDLE 不截斷） | High |
| 2026-08-07 | `odd_probe.py` `CMDS` (0x47/0x48) | PLAY AUDIO MSF / TRACK INDEX 永久 SKIP（含 `--dangerous`） | 無法以 len=0 或無效參數保證不真的播放 | 若需測存在性，需實機驗證某無害參數組合（風險自負） | Low |
| 2026-08-07 | `odd_probe.py` `parse_get_configuration()` / `parse_disc_info()` | 以構造資料單元測試驗證（本機僅 WSL2 Virtual Disk，無真實 ODD） | 開發環境無真實光碟裝置 | 以真實 ODD（CD/DVD/BD 各一片 media）實測解析 | High |
| 2026-08-07 | `odd_probe.py` `probe_device()` | INQUIRY / GET CONFIGURATION / READ DISC INFO 三指令結果快取至指令矩陣（不重發） | 避免重複 ioctl、降低 hang 風險 | 無需升級：設計選擇 | Low |
| 2026-08-07 | `odd_probe.py` `READ CD` CDB byte1=0x00 | 任務書註解「user=1」與值 0x00 矛盾，依值實作 | READ CD byte1 bit5=user data；0x00 表示不讀 user data，僅測 opcode 存在性 | 實機驗證時若需讀 1 sector user data，設 byte1=0x10 | Low |

---
*Note: All `ponytail:` comments in code must have a corresponding entry here.*
