$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
Write-Output ('PSVERSION ' + $PSVersionTable.PSVersion.ToString())
Write-Output 'Hello Windows — by Mac Astra'
Write-Output '中文与表情测试 ✅🚀'
if ((6 * 7) -ne 42) { throw 'ARITHMETIC_FAILED' }
Write-Output 'AGENT_ROAD_SMOKE_OK'
