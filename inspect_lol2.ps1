$resp = Invoke-WebRequest -Uri "https://www.loldrivers.io/api/drivers.json" -TimeoutSec 60
Write-Host "StatusCode:" $resp.StatusCode
Write-Host "ContentType:" $resp.Headers["Content-Type"]
Write-Host "Content length (chars):" $resp.Content.Length
Write-Host "First 300 chars:"
Write-Host $resp.Content.Substring(0, 300)
