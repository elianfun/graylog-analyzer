# graylog-analyzer

Graylog 異常日誌自動分析工具，串接本地 Ollama LLM 進行 AI 分析並輸出繁體中文報告。

## 功能概述

- 自動從 Graylog 撈取指定時間範圍內的異常 log（Error / Critical / Alert）
- 前處理去重、分組後，交由本地 Ollama 模型進行 AI 分析
- 支援多種輸出方式：終端機、檔案、Email、Line Notify
- 支援定時排程自動執行

## 架構

```
Graylog API → 前處理（去重/分組）→ Ollama LLM 分析 → 輸出報告
```

## 環境需求

| 項目 | 說明 |
|------|------|
| Python | 3.10 以上 |
| Graylog | 7.x，需有 API Token |
| Ollama | 已安裝並執行，預設模型 `qwen3.5:4b` |

## 安裝

```bash
pip install -r requirements.txt
```

## 設定

### 1. Graylog 連線

編輯 `config.yaml`：

```yaml
graylog:
  url: http://<your-graylog-host>:9000

ollama:
  url: http://<your-ollama-host>:11434
  model: qwen3.5:4b

query:
  range_seconds: 86400   # 查詢過去幾秒（86400 = 24 小時）
  limit: 1000

output:
  default: terminal      # terminal / file / email / line
  report_dir: ./reports
```

### 2. API Token

在專案目錄建立 `.env`（或沿用 graylog-mcp 的 .env）：

```env
GRAYLOG_URL=http://<your-graylog-host>:9000
GRAYLOG_TOKEN=<your-api-token>
```

### 3. Email 設定（選用）

在 `.env` 補上：

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SENDER=you@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_RECIPIENTS=you@gmail.com,other@gmail.com
```

### 4. Line Notify 設定（選用）

```env
LINE_NOTIFY_TOKEN=your_line_notify_token
```

## 使用方式

### 手動執行（輸出到終端機）

```bash
python graylog_analyzer.py
```

### 輸出到檔案

```bash
python graylog_analyzer.py --output file
```

報告會存在 `reports/` 目錄下。

### 同時輸出終端機 + 檔案

```bash
python graylog_analyzer.py -o terminal -o file
```

### 查詢過去 1 小時

```bash
python graylog_analyzer.py --range 3600
```

### 推送 Line Notify

```bash
python graylog_analyzer.py --output line
```

### 定時排程（每天早上 8 點）

在 `config.yaml` 啟用：

```yaml
schedule:
  enabled: true
  cron: "0 8 * * *"
```

然後執行：

```bash
python graylog_analyzer.py --schedule
```

也可用 PowerShell 排程腳本：

```powershell
.\run_daily_report.ps1   # 每天排程
.\run_fetch_hour.ps1     # 每小時排程
```

## 檔案結構

```
graylog-analyzer/
├── graylog_analyzer.py      # 主程式
├── graylog.py               # Graylog REST API 查詢模組
├── preprocessor.py          # 前處理（去重、分組）
├── ollama.py                # Ollama LLM 分析模組
├── output.py                # 輸出模組（terminal / file / email / line）
├── claude_client.py         # Claude API 客戶端（備用 LLM）
├── config.yaml              # 連線與查詢設定
├── requirements.txt         # Python 套件需求
├── run_daily_report.ps1     # 每日排程 PowerShell 腳本
├── run_fetch_hour.ps1       # 每小時排程 PowerShell 腳本
├── reports/                 # 自動產生的報告（.gitignore 排除）
└── logs/                    # 執行紀錄（.gitignore 排除）
```

## 相依套件

```
requests
pyyaml
python-dotenv
schedule
```

## 相關專案

- [graylog-mcp](https://github.com/elianfun/graylog-mcp)：透過 Claude Desktop 以自然語言即時查詢 Graylog 的 MCP Server
