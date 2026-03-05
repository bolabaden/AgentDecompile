$McpUrl = "http://***:8080/mcp/message/"

$InitBody = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ps-check","version":"1.0"}}}'
$InitResp = Invoke-WebRequest -UseBasicParsing -Uri $McpUrl -Method POST -Headers @{
  "Content-Type" = "application/json"
  "Accept"       = "application/json, text/event-stream"
} -Body $InitBody
$SID = $InitResp.Headers["mcp-session-id"]

$NotifBody = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
Invoke-WebRequest -UseBasicParsing -Uri $McpUrl -Method POST -Headers @{
  "Content-Type" = "application/json"
  "Accept"       = "application/json, text/event-stream"
  "Mcp-Session-Id" = $SID
} -Body $NotifBody | Out-Null

function Invoke-McpTool {
  param(
    [string]$Name,
    [string]$ArgumentsJson,
    [int]$Id = 100
  )

  $ArgsObject = $ArgumentsJson | ConvertFrom-Json
  $Body = @{
    jsonrpc = "2.0"
    id = $Id
    method = "tools/call"
    params = @{
      name = $Name
      arguments = $ArgsObject
    }
  } | ConvertTo-Json -Depth 100 -Compress

  Invoke-WebRequest -UseBasicParsing -Uri $McpUrl -Method POST -Headers @{
    "Content-Type" = "application/json"
    "Accept"       = "application/json, text/event-stream"
    "Mcp-Session-Id" = $SID
  } -Body $Body
}

$r = Invoke-McpTool -Id 103 -Name "get_current_program" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe"}'
Write-Host "Status=$($r.StatusCode)"
Write-Host $r.Content.Substring(0,[Math]::Min(300,$r.Content.Length))
