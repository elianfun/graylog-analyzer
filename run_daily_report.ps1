$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$logDir = "$PSScriptRoot\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
& "C:\Users\inno\AppData\Local\Python\bin\python.exe" "$PSScriptRoot\graylog_analyzer.py" --from-cache --hours 24 --output file --output pdf *>&1 |
    Tee-Object -FilePath "$logDir\daily_report_latest.log"
