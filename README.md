# odd-scsi-probe

USB ODD（光碟機）SCSI command 支援度檢測工具 — 支援 CD / DVD / BD / HD-DVD / DDCD 全格式。

以 Python 3 stdlib（ctypes / struct / os）實作，**零第三方依賴**，單檔可攜。

## 功能

- 列出系統中的 SCSI / 光碟裝置（Linux: `/dev/sg*` `/dev/sr*`；Windows: `\\.\CdRom*` `\\.\Scsi*`）
- 完整裝置檢測：
  - **INQUIRY**：Vendor / Product / Revision / Peripheral Device Type / Serial Number (EVPD 0x80)
  - **GET CONFIGURATION**：Current Profile、全部支援 Profile（含 current 標記）、Feature List（~60 個內建對照）
  - **READ DISC INFORMATION**：目前碟片 Disc Type（與 current profile 交叉比對）
  - **指令矩陣**：~46 個 opcode（SPC 基礎 + MMC 全格式 + 寫入類），逐指令判定支援度
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

## 支援格式

| 家族 | Profile / Disc Type |
| --- | --- |
| CD | CD-ROM, CD-R, CD-RW, CD-DA |
| DDCD | DDCD-ROM, DDCD-R, DDCD-RW |
| DVD | DVD-ROM, DVD-R (Seq/DL), DVD-RW (RO/SR/DL), DVD-RAM, DVD+R, DVD+RW, DVD+R DL, DVD+RW DL, DVD-R Dual Layer, DVD-RW Dual Layer |
| BD | BD-ROM, BD-R (Seq/Random), BD-RE |
| HD-DVD | HD DVD-ROM, HD DVD-R, HD DVD-RAM, HD DVD-RW, HD DVD-R DL, HD DVD-RW DL |

## 指令矩陣分類

| 類別 | 數量 | 說明 |
| --- | --- | --- |
| SPC | 15 | SCSI Primary Commands 基礎（INQUIRY、MODE SENSE、READ 10 等） |
| MMC | 18 | 光碟媒體指令（GET CONFIGURATION、READ CD、READ DISC INFORMATION 等） |
| DANGEROUS | 13 | 寫入類（僅 `--dangerous` 時以**無效參數 CDB** 測存在性） |

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

- Windows backend 以語法正確 + 可 import 驗證（`py_compile`），尚未在真實 Windows 機器實測 — 待硬體 QA
- 本機開發環境為 WSL2 虛擬 SCSI（無真實光碟機），GET CONFIGURATION / DISC INFO 解析以單元測試（構造資料）驗證 — 建議以真實 ODD（如 BD-RE 燒錄機）複測
- sense buffer 使用 32B（非最小 8B）：分類邏輯需要 ASC/ASCQ（offset 12/13）
- `list` 模式對每個裝置發 INQUIRY，無權限的裝置會顯示 `(unavailable: ...)` 而不中斷

## 開發

```bash
python3 -m py_compile odd_probe.py          # 語法驗證
python3 /tmp/test_odd_assertions.py         # Logic Assertion（42 項）
```

## License

MIT（依專案管理決定；本倉庫初始提交未含授權檔）。
