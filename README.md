# odd-scsi-probe

USB ODD（光碟機）SCSI command 支援度檢測工具 — 支援 CD / DVD / BD / HD-DVD / DDCD 全格式。

以 Python 3 stdlib（ctypes / struct / os）實作，**零第三方依賴**，單檔可攜。

## 功能

- 列出系統中的 SCSI / 光碟裝置（Linux: `/dev/sg*` `/dev/sr*`；Windows: `\\.\CdRom*` `\\.\Scsi*`）
- 完整裝置檢測：
  - **INQUIRY**：Vendor / Product / Revision / Peripheral Device Type / Serial Number (EVPD 0x80)
  - **GET CONFIGURATION**：Current Profile、全部支援 Profile（含 current 標記）、Feature List（49 個內建對照）
  - **READ DISC INFORMATION**：目前碟片 Disc Type（與 current profile 交叉比對）
  - **指令矩陣**：71 個 opcode（MMC-6 Table 7 光碟指令探測覆蓋：mandatory/optional/legacy + SPC 繼承，含 MMC-4 gap closure 10 指令）逐指令判定支援度，外加 READ CD Table 600 Data Block Type 支援矩陣（10 種 block type）、READ DISC STRUCTURE DVD（26 格式）/ BD（7 格式）結構矩陣 = 共 **114 步**
  - **Spec 相容性矩陣**（v1.5.0）：依 MMC-6 Table 7 期望指令集（13 個 profile）逐指令比對實測結果，輸出 PASS / FAIL / OPTIONAL / INFO 判定（CLI 文字 + HTML 報告）
- 人類可讀輸出 + `--json` 機器可讀輸出（通過 `python3 -m json.tool` 驗證）
- **雙模式**：預設 safe 模式（破壞性指令 SKIP）／ `--dangerous` 完整相容性測試模式（所有指令真實發送，見下方說明）

## 需求

- Python 3.8+（開發驗證於 3.12）
- Linux：需要 `/dev/sg*` 或 `/dev/sr*` 的讀寫權限（通常需 `root` 或 `disk` 群組）
- Windows：需要 Administrator（原始 SCSI 指令需管理權限）

## 安裝

無需安裝。直接執行：

```bash
git clone <repo-url> odd-scsi-probe
cd odd-scsi-probe
python3 odd_probe.py --help
```

## CLI 用法

```bash
# 列出所有 SCSI/光碟裝置
python3 odd_probe.py list

# 對指定裝置完整檢測
python3 odd_probe.py --device /dev/sr0
python3 odd_probe.py --device /dev/sg2

# JSON 輸出（可被 jq 解析）
python3 odd_probe.py --device /dev/sg2 --json

# 啟用完整相容性測試模式（產品測試用）：所有指令真實發送，
# 含 BLANK（抹碟）/ FORMAT（格式化）/ CLOSE TRACK / WRITE / 彈 tray
python3 odd_probe.py --device /dev/sg2 --dangerous

# 每指令 timeout 秒數（預設 5）
python3 odd_probe.py --device /dev/sg2 --timeout 5
```

Windows 範例：

```powershell
python odd_probe.py list
python odd_probe.py --device \\.\CdRom0
```

## GUI 使用（Tkinter）

`odd_probe_gui.py` 提供圖形介面，**重用 `odd_probe.py` 核心引擎**（不重寫邏輯），讓不熟指令的使用者也能在 Windows / Linux 測試 USB ODD。繁體中文介面，零第三方依賴（Tkinter 為 Python 內建）。

### 啟動

```bash
# Linux / WSLg（直接顯示視窗）
python3 odd_probe_gui.py

# Windows（無 console 視窗）
pythonw odd_probe_gui.py
```

### 操作流程

1. **掃描裝置** → 下拉選單列出候選裝置（Linux: `/dev/sg*` `/dev/sr*`；Windows: `\\.\CdRom*`），選取後「開始檢測」才會啟用
2. 可選調整：`--dangerous` 完整相容性模式勾選（預設關閉；勾選時彈出確認警告，所有指令包含 BLANK / FORMAT / CLOSE TRACK / 彈 tray 皆真實發送）、Timeout（1-30 秒，預設 5）
3. **開始檢測** → 背景執行緒執行完整探測，進度列顯示 `x/114`（71 opcodes + 10 READ CD block types + 26 DVD + 7 BD structure formats），UI 不凍結
4. 結果分四頁顯示：
   - **裝置資訊**：Vendor / Product / Revision / Peripheral Type / Serial / Current Profile / Media Detected
   - **支援格式**：Profile 清單（current 標 `[*]`）+ Feature 清單
   - **指令矩陣**：Opcode / 名稱 / 類別 / 結果 / 詳細，結果顏色標記（✅綠 ❌紅 💿藍 🔒灰 ⏱橙 ⚠黑）
   - **統計**：六類結果計數 + 裝置摘要
5. **匯出報告** → 存成 JSON 或文字報告（filedialog）

裝置打不開（無權限等）會以訊息框顯示原因；掃描無裝置時也會提示。

### 打包成單一執行檔

```bash
# Windows（需 Python 3.8+）：產生 dist\odd-probe.exe
build.bat

# 從 WSL2 直接編譯 Windows exe（interop，自動複製到 Windows Temp 再打包）：
./build-windows.sh

# Linux：產生 dist/odd-probe
./build.sh
```

三個腳本行為一致：自動偵測 Python（`py -3` → `python` → `python3`）、
PyInstaller 不存在時自動 `pip install pyinstaller`、帶 `--clean` 避免殘留 cache、
有 `version_info.txt` 就帶 `--version-file`（exe 屬性含 FileVersion / ProductName）、
repo 內有 `.ico` 就自動帶 `--icon`。

等價的 PyInstaller 指令：

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name odd-probe --clean \
  --version-file version_info.txt odd_probe_gui.py
```

`odd_probe.py` 會被自動打包進執行檔（GUI import 它）。

### Windows 編譯指南

#### 前置需求

- Windows 10/11 + Python 3.8+（[python.org](https://www.python.org/downloads/) 安裝時勾選
  “Add python.exe to PATH”，建議同時裝 **py launcher**，`build.bat` 會優先使用）
- 建議以 Administrator 執行（原始 SCSI 指令需管理權限，但編譯本身不需要）

#### 步驟

1. 把 repo 放進 Windows 可讀路徑（如 `C:\Users\you\odd-scsi-probe`）
2. 雙擊 `build.bat`（或於 cmd 執行），等待輸出 `BUILD OK: ...dist\odd-probe.exe`
3. 產出單檔 `dist\odd-probe.exe`（約 12 MB），可直接複製到任何 Windows 10/11 x64 使用

#### 從 WSL2 編譯（本專案開發環境）

repo 在 WSL 檔案系統時，直接 `cmd.exe /c build.bat` 會遇到兩個坑，請用
`./build-windows.sh` 自動處理：

1. **UNC 工作目錄**：CMD 不能以 `\\wsl.localhost\...` 作為起始目錄；腳本改用
   Windows 側 `%TEMP%\odd-build` 執行打包
2. **9P 寫入權限**：Windows 程序寫入 `\\wsl.localhost` 掛載可能被拒（WSL 側 root 擁有），
   改在 Windows 原生路徑寫入，完成後把 exe 複製回 repo 的 `dist/`

#### 常見問題

- **防毒誤報**：PyInstaller 單檔 exe 是自解壓 bootloader，部分防毒會誤判。
  可加白名單，或改用 `--onedir`（多檔，誤報較少）。
- **Python 3.14 相容性**：PyInstaller ≥ 6.15 已支援 3.14（本專案實測 6.21.0 + 3.14.3）。
  若你用的是過舊版 PyInstaller，`build.bat` 偵測不到會自動安裝最新版。
- **輸出亂碼**：`build.bat` 內部已 `chcp 65001`，且訊息全英文，避免中文語系主控台亂碼。
- **CLI 在中文 Windows 主控台**：報告符號（✅⚠ 等）在 cp950 主控台無法顯示，
  程式已自動降級為 `?` 不會崩潰（`stdout.reconfigure(errors="replace")`）。

#### Windows 實測記錄（2026-08-07）

- Python 3.14.3 + PyInstaller 6.21.0：`dist\odd-probe.exe` 12,637,400 B（12.6 MB）編譯成功
- `python odd_probe.py list`：32 個候選裝置（`\\.\CdRom0-15`、`\\.\Scsi0-15`）全部
  優雅回報 `unavailable: CreateFileW failed (2)`（ERROR_FILE_NOT_FOUND，無光碟機環境），不 crash
- `python odd_probe.py --device \\.\CdRom0`：55 項矩陣完整執行（v1.0.0 時期：45 opcodes + 10 block types），無裝置時
  0 SUPPORTED / 40 OTHER / 15 SKIPPED（真實反映打不開）
- exe 啟動驗證：tasklist 可見 `odd-probe.exe`（bootloader + 子進程），啟動不秒退

## 支援格式

| 家族 | Profile / Disc Type |
| --- | --- |
| CD | CD-ROM, CD-R, CD-RW, CD-DA |
| DDCD | DDCD-ROM, DDCD-R, DDCD-RW |
| DVD | DVD-ROM, DVD-R (Seq/DL), DVD-RW (RO/SR/DL), DVD-RAM, DVD+R, DVD+RW, DVD+R DL, DVD+RW DL, DVD-R Dual Layer, DVD-RW Dual Layer |
| BD | BD-ROM, BD-R (Seq/Random), BD-RE |
| HD-DVD | HD DVD-ROM, HD DVD-R, HD DVD-RAM, HD DVD-RW, HD DVD-R DL, HD DVD-RW DL |

## Sector Size 差異（MMC Table 600）

光碟的邏輯 sector size **不是固定值**，會影響 READ 類指令的 buffer 配置：

- **DVD / BD / HD-DVD 以上**：固定 **2048 B**（mode 1 user data）
- **CD**：依 READ CD (0xBE) 的 Data Block Type code 而定，有 8 種有效大小（2048~2448），最常見為 **2048（mode 1）** 與 **2352（raw）**

本工具的處理方式：

1. **READ 10 (0x28)**：先發 READ CAPACITY (0x25) 取得目前 media 的 block length（= sector size），READ 10 的 allocation 動態設為該值（CDB transfer len 恆為 1 block）；READ CAPACITY 失敗（無 media）時 fallback **2352**（最大可能 CD sector）
2. **READ CD (0xBE)**：對每個有效 Data Block Type code 各發一次探測（allocation = 該 type 的 block size），報告輸出「CD Data Block Type 支援矩陣」— 燒錄機 vs 唯讀機的支援度差異在此最明顯
3. 報告顯示 `Media Block Size`（例如 `2048` 或 `2352 (CD raw)`），無 media 顯示 `unknown`

### MMC Table 600 — READ CD Data Block Type 摘要

| Code | Block Size | 名稱 | Mandatory/Optional |
| --- | --- | --- | --- |
| 0 | 2352 | Raw data | Optional |
| 1 | 2368 | Raw data with P and Q Sub-channel | Optional |
| 2 | 2448 | Raw data with P-W Sub-channel appended, pack form | Optional |
| 3 | 2448 | Raw data with raw P-W Sub-channel appended | Optional |
| 4-6 | — | Reserved | — |
| 7 | — | NA Vendor Specific | — |
| 8 | 2048 | Mode 1 ISO/IEC 10149 | **Mandatory** |
| 9 | 2336 | Mode 2 ISO/IEC 10149 | Optional |
| 10 | 2048 | Mode 2 CD-ROM XA form 1 | **Mandatory** |
| 11 | 2056 | Mode 2 XA form 1 + 8B sub-header | Optional |
| 12 | 2324 | Mode 2 XA form 2 | Optional |
| 13 | 2332 | Mode 2 XA form 1/2 mixed + 8B sub-header | **Mandatory** |
| 14 | — | Reserved | — |
| 15 | — | NA Vendor Specific | — |

工具對 code 0/1/2/3/8/9/10/11/12/13 各探測一次（READ CD 0xBE 因此不再出現在 opcode 矩陣中，由 block type 迴圈取代）；type 級分類：0x20（指令不存在）→ 整組 NOT_SUPPORTED，0x24/0x25（該 type 參數被拒）→ 該 type NOT_SUPPORTED，其餘同主矩陣判定邏輯。block type 結果**併入 summary 統計**並計入進度列（114 步）；JSON 輸出位於 `block_type_matrix`（每項含 `code` / `size` / `name` / `mandatory` / `result` / `detail` / `sense_hex`）。

DVD / BD 同理：READ DISC STRUCTURE (0xAD) 以 media type 0x00（DVD，26 格式碼）與 0x01（BD，7 格式碼）各發一輪探測（MMC-6 §6.22.3），結果位於 `dvd_structure_matrix` / `bd_structure_matrix`，同 block type 併入 summary 並計入 114 步。

## 指令矩陣分類

| 類別 | 數量 | 說明 |
| --- | --- | --- |
| SPC | 25 | SCSI Primary Commands 基礎（INQUIRY、MODE SENSE、READ 10、LOG SENSE、LOCK/UNLOCK CACHE、RESERVE/RELEASE 6/10、VERIFY 10/12 等） |
| MMC | 23 | 光碟媒體指令（GET CONFIGURATION、READ DISC INFORMATION、REPORT LUNS、SECURITY PROTOCOL IN、READ/WRITE 12、MECHANISM STATUS 等；READ CD 以 block type 矩陣另行探測） |
| DANGEROUS | 23 | 寫入/破壞性類（BLANK、FORMAT、WRITE、ERASE 10、LOG SELECT、STOP PLAY/SCAN、PLAY AUDIO 12、SCAN 等；僅 `--dangerous` 完整相容性模式時**真實發送**） |
| READ CD block types | +10 | Table 600 每種 block type 各測一次（併入 summary） |
| DVD structure formats | +26 | READ DISC STRUCTURE media type 0x00（MMC-6 §6.22.3）每種格式碼各測一次 |
| BD structure formats | +7 | READ DISC STRUCTURE media type 0x01（MMC-6 §6.22.3）每種格式碼各測一次 |

### 判定邏輯

| 結果 | 判定條件 |
| --- | --- |
| ✅ SUPPORTED | status=GOOD；或 ILLEGAL_REQUEST 但 ASC≠0x20/0x00（參數被拒、指令存在）；UNIT ATTENTION；WRITE PROTECTED |
| ❌ NOT_SUPPORTED | ILLEGAL_REQUEST + ASC=0x20 ASCQ=0x00（INVALID COMMAND OPERATION CODE） |
| 💿 NEEDS_MEDIA | NOT READY + ASC=0x3A (MEDIUM NOT PRESENT) 或 0x04 (NOT READY) |
| 🟡 PARAMETER_NOT_SUPPORTED | ILLEGAL_REQUEST 但非 INVALID COMMAND（opcode 存在、參數/媒體被拒） |
| 🔴 MEDIA_STATE_INVALID | MEDIUM ERROR (0x03)：媒體存在但不可讀（如未 finalize） |
| 🟡 NEEDS_RECORDED_MEDIA | BLANK CHECK (0x08/0x30)：媒體存在但尚未錄製 |
| 🔒 SKIPPED | 危險指令未啟用、或永遠不可安全測試 |
| ⏱️ TIMEOUT | ioctl 逾時（SG_IO 逾時回 EIO） |
| ⚠️ OTHER | 其他 sense（附完整 sense hex） |

## Spec 相容性矩陣（MMC-6 Table 7，v1.5.0）

探測完成後，`evaluate_compatibility()` 以 MMC-6 Table 7 的期望指令集（**13 個 profile**：CD-ROM/R/CD-RW、DVD-ROM/R/RW/RAM/+R/+RW、BD-ROM/R/RE）逐指令比對實測結果，寫入 `result["compatibility"]`（CLI 文字報告新增「Spec Compatibility Matrix」區段、HTML 報告新增同名牌卡）：

| Verdict | 判定 |
| --- | --- |
| ✅ PASS | 實測符合期望（MANDATORY 支援、或 NOT APPLICABLE 正確缺席） |
| 🔴 FAIL | MANDATORY 指令實測 NOT_SUPPORTED（spec 違反） |
| ⚪ OPTIONAL | 期望為 OPTIONAL — 任何結果皆合規 |
| 🟡 INFO | 無法判定（media-dependent 結果、未探測、或 N 指令額外支援的加分能力） |

profile 不在資料庫時（或無 current profile）不會誤判：前者顯示 `profile not in spec DB` 註記、後者不產生相容性區段。

## ⚠️ 測試模式與安全設計（v1.1.0，產品廠商導向）

**兩種模式：**

| 模式 | 行為 | 用途 |
| --- | --- | --- |
| 預設（safe） | 破壞性指令顯示 `🔒 SKIPPED` + 提示 `--dangerous full-compat mode not enabled`；讀取/查詢指令照常真實測試 | 一般使用（避免誤抹資料碟） |
| `--dangerous`（完整相容性） | **所有指令真實發送**：BLANK 抹碟、FORMAT UNIT 格式化、CLOSE TRACK/SESSION 關閉 session、LOAD/UNLOAD 彈 tray、WRITE 10/12 寫入資料、ERASE 10 抹除媒體區塊、LOG SELECT、STOP PLAY/SCAN、PLAY AUDIO 12、SCAN、SEND OPC / SEND KEY / SEND CUE SHEET / SEND DISC STRUCTURE / SECURITY PROTOCOL OUT / REPAIR TRACK / SET STREAMING / MODE SELECT 真實參數 | **USB ODD 產品相容性測試（老闆需求）** |

**唯一例外（永遠不執行）：**

- **WRITE BUFFER (0x3B)**：僅允許 mode 0x00（device buffer）；任何 firmware download/update mode（0x04–0x0F 等）由集中閘門 `fw_flash_blocked()` 硬性拒絕，即使 `--dangerous` 也永不發送（anti-brick 保證）— 磚機風險，對相容性測試無意義

其他設計：
1. 所有指令 timeout 預設 5 秒，防止裝置 hang
2. 每指令標註 data direction（`dir: in/out/none`），寫入類以正確的 `SG_DXFER_TO_DEV` / `SCSI_IOCTL_DATA_OUT` 發送，不會因方向錯誤誤判
3. 報告標題顯示測試模式（`FULL COMPATIBILITY TEST MODE (--dangerous)`），JSON 輸出含 `"mode": "full-compat" | "safe"`

## 平台實作

- **Linux**：`SG_IO` ioctl (0x2285)，ctypes 定義 `struct sg_io_hdr` + 32B sense buffer
- **Windows**：`IOCTL_SCSI_PASS_THROUGH` (0x0004D004)，`DeviceIoControl` + `SCSI_PASS_THROUGH` 結構
- 以 `os.name` 做平台抽象層，自動選用對應 backend

## 已知限制

- Windows backend 已補 `CreateFileW`/`DeviceIoControl` 的 `restype`/`argtypes`（64-bit HANDLE 安全），`SCSI_PASS_THROUGH` layout 經程式化驗證與 ntddscsi.h pshpack4 一致（76B）；尚未在真實 Windows 機器實測 — 待硬體 QA
- 本機開發環境為 WSL2 虛擬 SCSI（無真實光碟機），GET CONFIGURATION / DISC INFO 解析以單元測試（構造資料）驗證 — 建議以真實 ODD（如 BD-RE 燒錄機）複測
- sense buffer 使用 32B（非最小 8B）：分類邏輯需要 ASC/ASCQ（offset 12/13）
- `list` 模式對每個裝置發 INQUIRY；無法開啟（如無權限）的裝置會顯示 `(unavailable: 原因)` 並繼續，不會中斷
- 完整相容性模式（--dangerous）會在可寫媒體上真實執行 BLANK / FORMAT / WRITE — **使用前請確認測試片可犧牲**

## 開發

```bash
python3 -m py_compile odd_probe.py odd_probe_gui.py   # 語法驗證
python3 tests/test_odd_assertions.py                  # Logic Assertion（297 項，含 MMC-6 對齊回歸）
python3 tests/test_odd_gui_logic.py                   # GUI 純邏輯測試（26 項，headless）
xvfb-run -a python3 tests/gui_smoke.py                # GUI 實機 smoke（需顯示；headless 用 xvfb）
```

## License

MIT（依專案管理決定；本倉庫初始提交未含授權檔）。

## 📦 版本與 Release

### v1.5.0 (2026-08-09)
- **P1 series（spec 精確性，P1-1/2/3 全數完成）**：
  - **P1-1 media-aware READ CD MSF (0xB9)**：以 TOC-derived MSF 動態填入 CDB，避免 lead-in 假陰性
  - **P1-2 structure format matrices**：READ DISC STRUCTURE (0xAD) DVD 26 + BD 7 格式碼矩陣（MMC-6 §6.22.3）
  - **P1-3a sense-accurate 結果分類**：新增 PARAMETER_NOT_SUPPORTED / MEDIA_STATE_INVALID / NEEDS_RECORDED_MEDIA
  - **P1-3b/c spec compatibility matrix**：MMC-6 Table 7 EXPECTED_COMMANDS DB（13 profiles）+ `evaluate_compatibility()` 判定引擎 + CLI 文字 / HTML 報告整合（PASS/FAIL/OPTIONAL/INFO）
- **計數同步**：CMDS 71（SPC 25 / MMC 23 / DANGEROUS 23）+ READ CD 10 + DVD 26 + BD 7 = **TOTAL_PROBE_STEPS 114**；assertion 297 項；version_info（exe 版本資源）同步 v1.5.0

### v1.4.0 (2026-08-08)
- **P0 spec fixes（MMC-6 Table 7 交叉驗證）**：
  - 0x56 修正為 **RESERVE (10)**（Table 7：RESERVE = 16h/56h；舊標 CLOSE TRACK/SESSION (old) 為誤標，真正的 CLOSE TRACK/SESSION = 5Bh），並自 DANGEROUS 區塊移至 SPC（不再於 `--dangerous` 真實發送）
  - 新增 **RELEASE (6/10)** 0x17/0x57（Table 7：RELEASE = 17h/57h）
  - 新增 **VERIFY (12)** 0xAF（Table 7：VERIFY = 2Fh/AFh；BYTCHK=0、verification length=0 → 不驗證任何 block，安全）
- **計數同步**：指令矩陣 69 → **72** opcodes（SPC 25 / MMC 24 / DANGEROUS 23）、dangerous 26 項、TOTAL_PROBE_STEPS 82（72 + 10 block types）；0xAF 納入 MMC6_OPCODES

### v1.3.0 (2026-08-08)
- **P0 修復**（2026-08-08 code review）：READ CD (0xBE) block-type 矩陣 CDB 錯位（byte 6 Transfer Length MSB / byte 9 Main Channel Selection）與 Expected Sector Type 規格表誤植、RSOC (0xA3) allocation length 移至 bytes 6-7、REPORT LUNS (0xA0) 改為 12-byte CDB、GET CONFIGURATION Linux resid 截斷（消除零填充假 feature）、READ CAPACITY block_len clamp（0xFFFFFFFF 不再 MemoryError）、GUI --dangerous 確認文案對齊引擎真實行為（BLANK 抹碟 / FORMAT / CLOSE TRACK/SESSION / WRITE / 彈 tray）
- **P1 修復**：GET PERFORMANCE (0xAC) 12-byte、START STOP UNIT (0x1B) START bit 修正、PLAY AUDIO 10 (0x45) TL=1、WRITE BUFFER (0x3B) paramlen=8、READ MEDIA SERIAL (0xAB) alloc=0x80、sense descriptor format (0x72/0x73) 分類、CHECK CONDITION 空 sense 補發 REQUEST SENSE、Windows alloc 縮至 4096、scsi_execute OSError 捕捉保留結果
- **測試強化**：新增 byte-exact CDB 黃金向量測試（P0-1/2/3 漏網主因）＋ resid 截斷 / descriptor sense / block_len clamp / 中途 OSError 等覆蓋
- **版本同步**：report_html TOOL_VERSION 與 version_info.txt（exe 版本資源）對齊 v1.3.0

### v1.2.1 (2026-08-08)
- **MMC-4 gap closure**：指令矩陣 59 → **69** opcodes，新增 10 指令（MMC-4 未收錄、legacy 碟機仍常見）：
  - SPC 區塊 5 個：REZERO UNIT (0x01)、RESERVE 6 (0x16)、PREFETCH 10 (0x34)、LOCK/UNLOCK CACHE (0x36)、LOG SENSE (0x4C)
  - DANGEROUS 區塊 5 個：ERASE 10 (0x2C，抹除媒體區塊)、LOG SELECT (0x4D)、STOP PLAY/SCAN (0x4E)、PLAY AUDIO 12 (0xA5)、SCAN (0xBA)
- **0x4E 範例語法修正**：STOP PLAY/SCAN CDB 範例修正（10-byte，正確 opcode 名稱對應）
- **計數同步**：SPC/MMC/DANGEROUS = 25/24/23、dangerous 26 項、TOTAL_PROBE_STEPS 82（72 opcodes + 10 block types）、assertion 134 項；README / version_info / DEBT 一併更新

### v1.2.0 (2026-08-08)
- **RSOC probe**：新增 MAINTENANCE IN / REPORT SUPPORTED OPERATION CODES（0xA3 SA=0x0C，SPC-3）— 驅動回報自身支援的 opcode 清單，人讀輸出顯示 Drive-Reported Opcodes
- **MMC-2 FLUSH CACHE coverage**：0x35 更名 SYNCHRONIZE CACHE / FLUSH CACHE（MMC-2 12-byte 變體同 opcode，註解說明涵蓋）
- **HTML report export**：新增 `--html` 參數，輸出獨立 HTML 報告（report_html.py）
- 指令矩陣 58 → 59 opcodes（+1 RSOC）

### v1.1.0 (2026-08-07)
- **MMC-6 指令探測覆蓋**：指令矩陣 45 → **58** opcodes（MMC-6 Table 226/227 指令探測覆蓋 + 11 legacy），新增 FORMAT UNIT、WRITE AND VERIFY、REPAIR TRACK、READ BUFFER CAPACITY、REPORT LUNS、SECURITY PROTOCOL IN/OUT、SEND KEY、LOAD/UNLOAD MEDIUM、SET READ AHEAD、READ/WRITE (12)、READ MEDIA SERIAL NUMBER、READ CD MSF、MECHANISM STATUS
- **CDB 錯誤修正**：0xA0 由 REPORT KEY 改為 **REPORT LUNS**；0xA2 由 SEND KEY 改為 **SECURITY PROTOCOL IN**；新增 0xA3 SEND KEY（12-byte）；12-byte/16-byte CDB 支援；全部指令 CDB 依 spec 複查
- **data direction 修正**：新增 `dir: in/out/none` 欄位，`SG_DXFER_TO_DEV` / `SCSI_IOCTL_DATA_OUT` 支援，寫入類指令不再因方向錯誤而 EINVAL
- **完整相容性測試模式**（產品廠商需求）：`--dangerous` 下所有指令真實發送（BLANK 抹碟 / FORMAT / CLOSE TRACK / 彈 tray / WRITE 寫入）；唯一例外 WRITE BUFFER firmware mode
- sector size 動態處理維持（READ 10/12 依 READ CAPACITY block size 對齊）

### v1.0.0 (2026-08-07)
- 首發版。USB ODD SCSI command 支援度檢測工具。
- 功能：
  - CLI（odd_probe.py）與 Tkinter GUI（odd_probe_gui.py）雙介面
  - 45 個 SCSI opcode + 10 種 CD Data Block Type（MMC Table 600）= 55 步指令矩陣
  - 全格式支援：CD / DVD / BD / HD-DVD / DDCD（profile 0x05-0x5A 全家族對照）
  - 雙平台：Linux (SG_IO) / Windows (SCSI Pass-Through)
  - 完整報告：INQUIRY、GET CONFIGURATION（profiles + features）、READ DISC INFORMATION、media 自動偵測
  - JSON 匯出（--json）
  - Windows 單檔 exe 打包（PyInstaller，含版本資訊）
- 安全設計：BLANK (0xA1)、CLOSE TRACK/SESSION (0x5B/0x56)、PLAY AUDIO (0x47/0x48) 任何模式永不執行
- 已知限制：
  - Windows 實體 ODD 的 INQUIRY 成功路徑尚未真機驗證（需有光碟機的機器補測，見 DEBT.md）
  - exe 12.6MB 可能觸發防毒誤報（對策：白名單或 --onedir 打包）
