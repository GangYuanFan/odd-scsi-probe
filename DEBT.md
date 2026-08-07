# Technical Debt Ledger (`DEBT.md`)

| Date | Module/Line | Shortcut Taken | Reason/Blocker | Upgrade Path (How to fix) | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-08-07 | `odd_probe.py` `scsi_execute()` (posix) | sense buffer 用 32B（任務書寫 8B） | 判定邏輯需要 ASC/ASCQ（固定 sense offset 12/13），8B 裝不下 | 無需升級：屬必要偏離，已於 README 註明 | Low |
| 2026-08-07 | `odd_probe.py` Windows backend | ~~已補 `CreateFileW`/`DeviceIoControl` 的 `restype`/`argtypes`（HANDLE/BOOL，64-bit 不截斷）並程式化驗證 `SCSI_PASS_THROUGH` layout~~（已解） | 2026-08-07 Windows 真機實測（Python 3.14.3）：`list` 32 候選裝置全部優雅 unavailable、`--device \\.\CdRom0` 55 項矩陣完整執行不 crash、exe 啟動正常。**但該機無實體光碟機**，INQUIRY 成功路徑（含 64-bit HANDLE 實機驗證）仍未實測 | 需有實體 ODD 的 Windows 機器以光碟機實測 `list` / `--device \\.\CdRom0` | High |
| 2026-08-07 | `odd_probe.py` `_configure_windows_ctypes()` | ~~`use_last_error` 未啟用 → 錯誤訊息恆顯示 `CreateFileW failed (0)`~~（已解） | 真機實測發現：`ctypes.windll.kernel32` 函式物件建立後再設 `use_last_error=True` 是 no-op，`get_last_error()` 回 stale 0 | 改用 `ctypes.WinDLL("kernel32", use_last_error=True)` 專用實例（已實作），錯誤碼現為真實值（如 2 = ERROR_FILE_NOT_FOUND） | Low |
| 2026-08-07 | `odd_probe.py` CLI 輸出 | ~~cp950 主控台（zh-TW Windows）印出 ✅⚠ 等符號時 `UnicodeEncodeError` 崩潰~~（已解） | 真機實測發現：`list`/`--device` 在中文 Windows 主控台直接 traceback | `main()` 開頭對 stdout/stderr `reconfigure(errors="replace")`（已實作）；UTF-8 終端仍顯示完整符號 | Low |
| 2026-08-07 | `odd_probe.py` `probe_device()` 0x12 快取 | ~~無條件標 INQUIRY 為 SUPPORTED，裝置打不開時也誤報~~（已解） | 真機實測發現：CreateFileW 全失敗時 0x12 仍顯示 `SUPPORTED (cached from INQUIRY)`，誤導（實測前即存在，Windows 無 ODD 環境最明顯） | 改為依 `inquiry()` 實際結果快取；失敗時 `classify()` 回 OTHER（已實作 + 新增 assertion，105 項全 PASS） | Low |
| 2026-08-07 | Windows 編譯流程 | ~~build.bat 僅 2 行（pip install + pyinstaller），無 Python 偵測/無 UNC 處理~~（已解） | 交付品質要求；且實測發現 Windows→`\\wsl.localhost` 9P 寫入被拒（repo root 擁有） | 已重寫 build.bat（自動偵測 py/python/python3、自動裝 PyInstaller、`--clean`/`--version-file`/`--icon`、CRLF + block 內避開 `()` 與 `<path>` 重導向字元）+ 新增 build-windows.sh（複製到 `%TEMP%\odd-build` 打包再拷回）+ README 指南 | Low |
| 2026-08-07 | `odd_probe.py` `CMDS` (0x47/0x48) | ~~PLAY AUDIO MSF / TRACK INDEX 永久 SKIP（含 `--dangerous`）~~（已解） | v1.0.0 無法以 len=0 或無效參數保證不真的播放 | v1.1.0 起依老闆決策改為 `--dangerous` 完整相容性模式下**真實發送**（真的播放）；safe 模式仍 SKIP | Low |
| 2026-08-07 | `odd_probe.py` 安全紅線設計 | ~~BLANK / CLOSE TRACK / FORMAT / LOAD-UNLOAD 永不發送~~（已解） | v1.0.0 以「永不發送」防誤用 | v1.1.0 依老闆決策（USB ODD 產品廠商，測完整相容性）改為 `--dangerous` 下**真實發送**（BLANK 抹碟 / FORMAT 格式化 / CLOSE TRACK 關 session / LOAD-UNLOAD 彈 tray / WRITE 真實寫入）；safe 模式仍 SKIP；**唯一例外 WRITE BUFFER firmware mode（磚機風險）** | Low |
| 2026-08-07 | `odd_probe.py` `scsi_execute()` | ~~僅 FROM_DEV/NONE 兩方向，寫入類指令方向錯誤（EINVAL）~~（已解） | v1.0.0 未實作 TO_DEV | v1.1.0 新增 `dir` 欄位 + `SG_DXFER_TO_DEV` / `SCSI_IOCTL_DATA_OUT`（已實作，assertion 驗證） | Low |
| 2026-08-07 | `odd_probe.py` `parse_get_configuration()` / `parse_disc_info()` | 以構造資料單元測試驗證（本機僅 WSL2 Virtual Disk，無真實 ODD） | 開發環境無真實光碟裝置 | 以真實 ODD（CD/DVD/BD 各一片 media）實測解析 | High |
| 2026-08-07 | `odd_probe.py` `probe_device()` | INQUIRY / GET CONFIGURATION / READ DISC INFO / READ CAPACITY 四指令結果快取至指令矩陣（不重發） | 避免重複 ioctl、降低 hang 風險 | 無需升級：設計選擇 | Low |
| 2026-08-07 | ~~`READ CD` CDB byte1=0x00~~（已解） | 原單一 0xBE 測試項 byte1=0x00，未測 user data | 已由 Table 600 block type 迴圈取代：byte1 = code<<2、user-data types (8-13) byte6=0x10，每 type 各測一次；0xBE 自 opcode 矩陣移除 | 無需升級：已實作 | Low |
| 2026-08-07 | `odd_probe.py` `probe_device()` READ CD block types | 每裝置多發 10 次 READ CD ioctl（MMC Table 600 各 code 一次） | PM 需求：type 級支援度鑑別（燒錄機 vs 唯讀機）；無 CD media 時成本為 10 次快速 CHECK CONDITION | 若需加速：以 GET CONFIGURATION 的 CD Read feature 存在與否先行過濾 | Low |
| 2026-08-08 | `odd_probe.py` `CMDS` 0x4D LOG SELECT | 靜態 alloc=0 但 dir=out，靠測試白名單放行（paramlen=0 實際無資料外送） | 安全考量：不帶參數送出（LOG SELECT 帶參數可改寫 drive 的 log 設定）；paramlen=0 時無資料 phase，僅驗證指令存在 | 若要真送資料：runtime 覆寫 alloc（類似 READ 10 的 media block size 覆寫） | Low |

---
*Note: All `ponytail:` comments in code must have a corresponding entry here.*
