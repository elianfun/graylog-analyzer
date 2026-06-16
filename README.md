# graylog-analyzer

Graylog 異常日誌自動分析工具，串接本地 Ollama（qwen3.5:4b）進行 AI 分析。

## 環境需求

- Python 3.10+
- Ollama 已安裝並執行於 192.168.223.168:11434
- Graylog API Token 已存放於 C:\Users\inno\Documents\graylog-mcp\.env

## 安裝

```bash
cd C:\Users\inno\Documents\graylog-analyzer
pip install -r requirements.txt
```

## 使用方式

### 手動執行（結果印在終端機）
```bash
python graylog_analyzer.py
```

### 輸出到檔案
```bash
python graylog_analyzer.py --output file
```

### 同時輸出終端機 + 檔案
```bash
python graylog_analyzer.py -o terminal -o file
```

### 只查過去 1 小時
```bash
python graylog_analyzer.py --range 3600
```

### 推送 Line Notify
```bash
python graylog_analyzer.py --output line
```
需在 .env 補上：
```
LINE_NOTIFY_TOKEN=你的token
```

### 定時排程（每天早上 8 點自動執行）
在 config.yaml 設定：
```yaml
schedule:
  enabled: true
  cron: "0 8 * * *"
```
然後執行：
```bash
python graylog_analyzer.py --schedule
```

## Email 設定

在 `C:\Users\inno\Documents\graylog-mcp\.env` 補上：
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SENDER=you@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_RECIPIENTS=you@gmail.com,other@gmail.com
```

## 目錄結構

```
graylog-analyzer/
├── config.yaml              # 連線與查詢設定
├── graylog_analyzer.py      # 主程式
├── requirements.txt
├── modules/
│   ├── graylog.py           # Graylog REST API 查詢
│   ├── preprocessor.py      # 前處理（去重、分組）
│   ├── ollama.py            # Ollama LLM 分析
│   └── output.py            # 輸出模組
└── reports/                 # 自動產生的報告檔案
```
