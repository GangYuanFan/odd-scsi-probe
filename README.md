# odd-scsi-probe

USB ODD（光碟機）SCSI command 支援度檢測工具 — 支援 CD / DVD / BD / HD-DVD / DDCD 全格式。

以 Python 3 stdlib（ctypes / struct / os）實作，**零第三方依賴**，單檔可攜。

## 功能

- 列出系統中的 SCSI / 光碟裝置（Linux: `/dev/sg*` `/dev/sr*`；Windows: `\\.\CdRom*` `\\.\Scsi*`）
- 完整裝置檢測：
  - **INQUIRY**：Vendor / Product / Revision / Peripheral Device Type / Serial Number (EVPD 0x80)
  - **GET CONFIGURATION**：Current Profile、全部支援 Profile（含 current 標記）、Feature List（49 個內建對照）
  - **READ DISC INFORMATION**：目前碟片 Disc Type（與 current profile 交叉比對）
  - **指令矩陣**：45 個 opcode（SPC 基礎 + MMC 全格式 + 寫入類）逐指令判定支援度，外加 READ CD Table 600 Data Block Type 支援矩陣（10 種 block type）
- 人類可讀輸出 + `--json` 機器可讀輸出（通過 `python3 -m json.tool` 驗證）

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

# 啟用寫入類指令存在性測試（預設關閉）
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
2. 可選調整：`--dangerous` 勾選（預設關閉；勾選時彈出確認警告，BLANK / CLOSE TRACK 仍永不執行）、Timeout（1-30 秒，預設 5）
3. **開始檢測** → 背景執行緒執行完整探測，進度列顯示 `x/55`（45 個 opcode + 10 種 READ CD block type），UI 不凍結
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
- `python odd_probe.py --device \\.\CdRom0`：55 項矩陣完整執行，無裝置時
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

工具對 code 0/1/2/3/8/9/10/11/12/13 各探測一次（READ CD 0xBE 因此不再出現在 opcode 矩陣中，由 block type 迴圈取代）；type 級分類：0x20（指令不存在）→ 整組 NOT_SUPPORTED，0x24/0x25（該 type 參數被拒）→ 該 type NOT_SUPPORTED，其餘同主矩陣判定邏輯。block type 結果**併入 summary 統計**並計入進度列（55 步）；JSON 輸出位於 `block_type_matrix`（每項含 `code` / `size` / `name` / `mandatory` / `result` / `detail` / `sense_hex`）。

## 指令矩陣分類

| 類別 | 數量 | 說明 |
| --- | --- | --- |
| SPC | 15 | SCSI Primary Commands 基礎（INQUIRY、MODE SENSE、READ 10 等） |
| MMC | 17 | 光碟媒體指令（GET CONFIGURATION、READ DISC INFORMATION 等；READ CD 以 block type 矩陣另行探測，見上） |
| DANGEROUS | 13 | 寫入類（僅 `--dangerous` 時以**無效參數 CDB** 測存在性） |
| READ CD block types | +10 | Table 600 每種 block type 各測一次（併入 summary） |

### 判定邏輯

| 結果 | 判定條件 |
| --- | --- |
| ✅ SUPPORTED | status=GOOD；或 ILLEGAL_REQUEST 但 ASC≠0x20/0x00（參數被拒、指令存在）；UNIT ATTENTION；WRITE PROTECTED |
| ❌ NOT_SUPPORTED | ILLEGAL_REQUEST + ASC=0x20 ASCQ=0x00（INVALID COMMAND OPERATION CODE） |
| 💿 NEEDS_MEDIA | NOT READY + ASC=0x3A (MEDIUM NOT PRESENT) 或 0x04 (NOT READY) |
| 🔒 SKIPPED | 危險指令未啟用、或永遠不可安全測試 |
| ⏱️ TIMEOUT | ioctl 逾時（SG_IO 逾時回 EIO） |
| ⚠️ OTHER | 其他 sense（附完整 sense hex） |

## ⚠️ 安全紅線（不可妥協）

1. **BLANK (0xA1) 與 CLOSE TRACK/SESSION (0x5B / 0x56) 永遠不發送**，即使 `--dangerous` 也一樣 — 結果標示 `🔒 SKIPPED (unsafe to test)`
2. PLAY AUDIO MSF (0x47) / PLAY AUDIO TRACK INDEX (0x48) 無法以無害參數測試（會真的播放），**永遠不發送**
3. 其他寫入類指令（WRITE 10 / MODE SELECT / WRITE BUFFER / SEND KEY 等）僅在 `--dangerous` 時以**零長度或無效參數 CDB** 測 opcode 存在性（如 WRITE 10 用 transfer len=0 → 回 INVALID FIELD 即證明存在，不實際寫入）
4. 所有指令 timeout 預設 5 秒，防止裝置 hang
5. 不載入/退出 tray（不設 LoEJ）、不格式化、不寫 media

## 平台實作

- **Linux**：`SG_IO` ioctl (0x2285)，ctypes 定義 `struct sg_io_hdr` + 32B sense buffer
- **Windows**：`IOCTL_SCSI_PASS_THROUGH` (0x0004D004)，`DeviceIoControl` + `SCSI_PASS_THROUGH` 結構
- 以 `os.name` 做平台抽象層，自動選用對應 backend

## 已知限制

- Windows backend 已補 `CreateFileW`/`DeviceIoControl` 的 `restype`/`argtypes`（64-bit HANDLE 安全），`SCSI_PASS_THROUGH` layout 經程式化驗證與 ntddscsi.h pshpack4 一致（76B）；尚未在真實 Windows 機器實測 — 待硬體 QA
- 本機開發環境為 WSL2 虛擬 SCSI（無真實光碟機），GET CONFIGURATION / DISC INFO 解析以單元測試（構造資料）驗證 — 建議以真實 ODD（如 BD-RE 燒錄機）複測
- sense buffer 使用 32B（非最小 8B）：分類邏輯需要 ASC/ASCQ（offset 12/13）
- `list` 模式對每個裝置發 INQUIRY；無法開啟（如無權限）的裝置會顯示 `(unavailable: 原因)` 並繼續，不會中斷

## 開發

```bash
python3 -m py_compile odd_probe.py odd_probe_gui.py   # 語法驗證
python3 tests/test_odd_assertions.py                  # Logic Assertion（105 項，含 B1-B6 + Table 600 回歸）
python3 tests/test_odd_gui_logic.py                   # GUI 純邏輯測試（22 項，headless）
xvfb-run -a python3 tests/gui_smoke.py                # GUI 實機 smoke（需顯示；headless 用 xvfb）
```

## License

MIT（依專案管理決定；本倉庫初始提交未含授權檔）。
