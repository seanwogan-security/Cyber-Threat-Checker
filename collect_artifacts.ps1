[CmdletBinding()]
param(
    [string]$OutputPath = "..\sample_data\artifacts.json"
)

# Ensure output folder exists
$folder = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

Write-Host "[*] Collecting processes..."

$processes = Get-Process | ForEach-Object {
    $path = $null
    try {
        $path = $_.MainModule.FileName
    } catch {}

    [PSCustomObject]@{
        Type     = "Process"
        Name     = $_.ProcessName
        Id       = $_.Id
        Path     = $path
        CPU      = $_.CPU
        MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
    }
}

Write-Host "[*] Collecting network connections..."

$connections = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $connections = Get-NetTCPConnection | ForEach-Object {
        [PSCustomObject]@{
            Type            = "NetworkConnection"
            LocalAddress    = $_.LocalAddress
            LocalPort       = $_.LocalPort
            RemoteAddress   = $_.RemoteAddress
            RemotePort      = $_.RemotePort
            State           = $_.State
            OwningProcessId = $_.OwningProcess
        }
    }
}

# Combine final object
$allData = [PSCustomObject]@{
    Hostname    = $env:COMPUTERNAME
    CollectedAt = (Get-Date).ToString("o")
    Processes   = $processes
    Connections = $connections
}

Write-Host "[*] Writing JSON..."

$allData | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "[+] Done. JSON saved to $OutputPath"
