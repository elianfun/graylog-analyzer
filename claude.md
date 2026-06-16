# graylog-analyzer 專案背景

## 環境
- Graylog：http://192.168.222.77:9000
- Ollama：http://192.168.223.168:11434，模型 qwen3.5:4b
- .env 位於：C:\Users\inno\Documents\graylog-mcp\.env

## 目標
串接 Graylog REST API 撈異常 log，前處理後丟給本地 Ollama 分析，輸出繁體中文異常報告。

## 目前進度
程式碼已完成，尚未實際測試執行。