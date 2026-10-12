# graylog-analyzer

Graylog 異常日誌自動分析工具：從 Graylog 撈取交換器等網路設備的異常 log，由 Python 精確統計後交給 LLM 撰寫原因與處置建議，輸出繁體中文日報表（文字 / PDF / Email / LINE）。

## 功能概述

- **完整撈取**：逐小時分頁查詢 Graylog，不受單次 1000 筆上限影響；可指定任意日期補做日報
- **Python 負責數字、LLM 負責解讀**：IP、介面名稱、筆數、Flapping 次數一律由程式統計，LLM 只寫原因與建議
- **多種 LLM 後端**：OpenAI 相容 API（vLLM、LiteLLM）或 Ollama，以設定檔切換
- **去識別化（mask）**：使用外部 LLM 時，IP / 主機名稱 / 帳號 / 系統名稱先換成代號才送出，報告回來後在本機還原（[詳見下方](#去識別化mask)）
- **程式判定優先等級**：依 Flapping 次數、介面事件數、硬體關鍵字等規則分 P0 / P1 / P2，結果穩定可調
- **自動檢核**：報告中出現、但原始統計找不到的 IP / 介面會標註警告；漏分析的設備自動補送
- **PDF 日報表**：中文字型、P0/P1/P2 色塊表格、頁碼

## 處理流程

```
Graylog REST API（逐小時分頁）
   │
   ▼
前處理（preprocessor.py）
   ├─ 去除 syslog 標頭、PID 等變動欄位 → 相同訊息歸併計數
   ├─ Flapping 偵測（DOWN/UP 配對）、過濾正常開關機的零星 link 事件
   └─ 依規則分級 P0 / P1 / P2
   │
   ▼
（選用）去識別化 mask.py ── 送出前換成代號
   │
   ▼
LLM（llm.py）
   ├─ 設備分批、並行分析 → 每台的問題 / 可能原因 / 建議處置
   └─ 優先處理表 + 全設備摘要 → 異常總覽
   │
   ▼
（選用）還原代號 → 標題統一改寫 → 自動檢核
   │
   ▼
輸出（output.py / pdf_report.py）：terminal / file / pdf / email / line
```

## 環境需求

| 項目 | 說明 |
|------|------|
| Python | 3.10 以上 |
| Graylog | 7.x，需有 API Token |
| LLM | 任一 OpenAI 相容 API（vLLM、LiteLLM…）或 Ollama |
| 字型 | PDF 輸出使用 Windows 內建微軟正黑體（`msjh.ttc`），找不到時改用細明體 |

## 安裝

```bash
pip install -r requirements.txt
```

> `truststore` 讓 Python 使用 Windows 憑證存放區驗證 HTTPS。若內網有 SSL 檢查設備，沒有它會出現 `CERTIFICATE_VERIFY_FAILED`。

## 設定

### 1. config.yaml

```bash
copy config.example.yaml config.yaml
```

`config.yaml` 已列入 `.gitignore`，實際位址不會上傳。主要區塊：

```yaml
graylog:
  url: http://graylog.example.local:9000

llm:                          # 預設 LLM（內部服務）
  provider: openai            # openai（vLLM / LiteLLM）或 ollama
  url: http://vllm.example.local:8000/v1
  model: qwen3.8-flash-next
  api_key_env: LLM_API_KEY    # 從 .env 讀取的變數名稱
  concurrency: 2              # 同時送出的請求數
  batch_size: 30              # 每批幾台設備
  batch_thinking: false       # 設備分析關閉思考（較快、不易耗盡 token）
  final_thinking: true        # 總覽保留思考

llm_profiles:                 # 執行時用 --llm-profile <名稱> 覆蓋 llm:
  external:
    url: https://llm.example.com/v1
    model: deepseek-v4.1-flash
    api_key_env: EXTERNAL_API_KEY
    mask: true                # ⚠ 外部服務務必開啟去識別化
    thinking_control: false   # 非 vLLM/Qwen 不送 enable_thinking 參數
```

完整欄位與說明見 [config.example.yaml](config.example.yaml)。

### 2. .env（機密值）

```bash
copy .env.example .env
```

```env
GRAYLOG_TOKEN=your_graylog_api_token
LLM_API_KEY=your_internal_llm_key
EXTERNAL_API_KEY=your_external_llm_key
```

Email（`SMTP_*`）與 LINE（`LINE_NOTIFY_TOKEN`）設定也放在 `.env`，見 [.env.example](.env.example)。

## 使用方式

| 情境 | 指令 |
|------|------|
| 分析最近 24 小時並輸出文字 + PDF | `python graylog_analyzer.py --hours 24 -o file -o pdf` |
| 分析指定日期（台灣時間 00:00~24:00） | `python graylog_analyzer.py --date 2026-08-26 -o pdf` |
| 改用外部 LLM（自動去識別化） | `python graylog_analyzer.py --date 2026-08-26 --llm-profile external -o pdf` |
| 預覽實際要送出的內容（不呼叫 LLM） | 任一指令加 `--dry-run` → `reports/send_preview_*.txt` |
| 只撈資料存快取、不呼叫 LLM | `python graylog_analyzer.py --date 2026-08-26 --fetch-only` |
| 用快取重新產生報告 | `python graylog_analyzer.py --batch-only -o pdf` |
| 每小時撈取 / 從每小時快取彙整 | `--fetch-hour` / `--from-cache --hours 24` |
| 快速模式（單次查詢過去 1 小時） | `python graylog_analyzer.py --range 3600` |

輸出方式（`-o` 可重複指定）：`terminal`、`file`、`pdf`、`email`、`line`。

## 去識別化（mask）

使用外部 LLM 服務時，log 中的內網資訊（設備 IP、主機名稱、內部系統名稱、帳號）不應離開內網。本工具在**送出前**把這些識別資訊換成代號，**報告回來後在本機**換回真實值；對照表只存在本機記憶體，不會送出。

### 為什麼不影響分析品質

LLM 判斷故障原因靠的是錯誤訊息本身（例如 `Fan 1 is NOT spinning correctly`、`SNMP_TRAP_LINK_DOWN`），不需要知道設備的真實 IP 或名稱；而 IP、筆數等精確數字本來就由 Python 統計，再由程式還原。

### 遮罩對象與代號

| 類別 | 代號 | 偵測方式 | 範例 |
|------|------|---------|------|
| 設備（log 來源 IP） | `DEV-001` | 統計資料的設備 key，依異常筆數排序編號 | `10.0.56.16` → `DEV-001` |
| 主機名稱 | `HOST-001` | syslog 標頭解析出的 hostname；送給模型時直接留空 | `SW02-EX46-56.16` → （不送） |
| log 內的其他 IPv4 | `IP-001` | IPv4 正規表示式 | `(10.1.2.3)` → `(IP-003)` |
| MAC 位址 | `MAC-001` | `aa:bb:cc:dd:ee:ff`、`aabb.ccdd.eeff` 等格式 | |
| 系統 / 服務名稱 | `NAME-001` | `server` / `group` / `service-group` / `virtual-server` / `pool` / `role` / `realm` 等關鍵字後的名稱 | `group URL_AppWeb_443` → `group NAME-032` |
| 帳號 | `USER-001` | `user xxx`、`User=xxx`、`for invalid user xxx`、`for xxx from <IP>` | `error for alice from 10.1.2.3` → `error for USER-001 from IP-001` |

**刻意保留**（分析需要且不具識別性）：錯誤訊息內容、介面名稱（`ge-0/0/25`）、ifIndex、通用帳號 `root`、`Realm=LOCAL` 等通用值。

### 處理流程

```
原始統計 ──mask_stats()──▶ 代號化統計 ──▶ 外部 LLM
                                          │
報告 ◀── 自動檢核 ◀── 標題改寫 ◀── unmask() ◀┘
```

1. **建立對照表**：`Masker.mask_stats()` 先登記所有設備與主機名稱，再逐一處理訊息樣式；同一個原始值永遠對應同一個代號
2. **替換順序**：主機名稱（較長，先換以免其中的 IP 片段被拆開）→ IPv4 → MAC → 系統名稱 → 帳號
3. **避免誤遮**：關鍵字比對以完整字詞為準，並排除常見字（`shutdown`、`port`、`local`…）；例如 `failed for port 12` 不會被當成帳號
4. **還原**：`unmask()` 把代號換回原值；模型若把代號縮寫成 `DEV-003/006`，會先展開成 `DEV-003、DEV-006` 再還原
5. **事後檢核**：
   - 對照表中不存在的代號（模型自行捏造）列在報告末尾「⚠ 無法還原的代號」
   - 報告中出現、但原始統計找不到的 IP / 介面列在「⚠ 自動檢核」
   - 設備標題由程式統一改寫為「【IP】主機名稱」，不依賴模型輸出格式

### 送出前自行驗證

```bash
python graylog_analyzer.py --batch-only --llm-profile external --dry-run
```

`--dry-run` 不會送出任何請求，而是把**完整的請求內容**（system / user prompt）寫入 `reports/send_preview_*.txt`，可以人工檢查，或用程式比對對照表中的原始值是否出現在檔案中。建議每遇到新的 log 來源（新設備類型、新服務）時先預覽一次，確認沒有新型態的識別資訊。

> ⚠ 去識別化是降低風險的措施，不是保證。正規表示式只能涵蓋已知的格式；送出前請以 `--dry-run` 確認，並遵守所屬單位的資安規範。

## 優先分級規則

分級由 Python 依 `config.yaml` 的 `priority:` 判定（不交給 LLM），任一條件成立即歸入該級：

| 等級 | 條件（預設值） |
|------|---------------|
| **P0** | 單一介面 Flapping ≥ 100 次；單一介面事件 ≥ 300 筆；嚴重硬體關鍵字（風扇不轉、PSU、WRITE_DMA、過熱、storm…）≥ 10 筆 |
| **P1** | 單一介面 Flapping ≥ 20 次；單一介面事件 ≥ 50 筆；硬體 / 服務警告（溫度偏高、SFP 光衰、SLB down…）≥ 10 筆；總筆數 ≥ 100；最高等級 ERROR 以上且總筆數 ≥ 50 |
| **P2** | 其餘 |

關鍵字以完整字詞比對（避免 `PSU` 誤中 `URL_PSUWeb` 之類名稱）。

## Flapping 偵測

- 針對 `SNMP_TRAP_LINK_DOWN` / `SNMP_TRAP_LINK_UP` 事件，**DOWN + UP 配對才算一次 up/down**
- 同一介面 5 分鐘內配對數 ≥ 10 才視為 Flapping
- 非 Flapping 介面的零星 link 事件（正常開關機、拔線）直接過濾，不計入統計
- Graylog 查詢條件包含 `SNMP_TRAP_LINK_UP`：UP 訊息本身不含異常關鍵字，若不一併撈取就無法配對

## 排程

PowerShell 排程腳本：

```powershell
.\run_fetch_hour.ps1     # 每小時：撈前一小時存入 hourly_cache
.\run_daily_report.ps1   # 每天：從快取彙整 24 小時並輸出文字 + PDF
```

建議使用 Windows 工作排程器，排程建立後不需要其他程式開著也能自動執行：

| 任務名稱 | 排程 | 腳本 |
|---------|------|------|
| `\Graylog\Graylog-FetchHour` | 每小時整點 | `run_fetch_hour.ps1` |
| `\Graylog\Graylog-DailyReport` | 每天早上 08:00 | `run_daily_report.ps1` |

## 檔案結構

```
graylog-analyzer/
├── graylog_analyzer.py      # 主程式（流程、分批並行、覆蓋率檢查、檢核）
├── graylog.py               # Graylog REST API 查詢（逐小時分頁）
├── preprocessor.py          # 前處理：樣式歸併、Flapping 偵測、分級、檢核
├── mask.py                  # 去識別化：代號替換與還原
├── llm.py                   # LLM 呼叫（OpenAI 相容 / Ollama）、重試、dry-run
├── pdf_report.py            # Markdown 報告 → PDF（表格、色塊、頁碼）
├── output.py                # 輸出模組（terminal / file / pdf / email / line）
├── generate_pdf.py          # 將舊版 .txt 報告轉換為 PDF（獨立工具）
├── claude_client.py         # Claude API 客戶端（備用）
├── config.example.yaml      # 設定檔範例（複製為 config.yaml）
├── .env.example             # 機密值範例（複製為 .env）
├── requirements.txt
├── run_daily_report.ps1     # 每日排程腳本
├── run_fetch_hour.ps1       # 每小時排程腳本
├── reports/                 # 報告與快取（.gitignore 排除）
└── logs/                    # 執行紀錄（.gitignore 排除）
```

## 相關專案

- [graylog-mcp](https://github.com/elianfun/graylog-mcp)：透過 Claude Desktop 以自然語言即時查詢 Graylog 的 MCP Server
