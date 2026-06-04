param(
    [switch]$Permanent = $false
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "       CTF-GPT API Key Setup             " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Press Enter to skip any key you don't have.`n"

$hfToken = Read-Host "Enter your HF_TOKEN (HuggingFace)"
$deepseekKey = Read-Host "Enter your DEEPSEEK_API_KEY"
$groqKey = Read-Host "Enter your GROQ_API_KEY"

Write-Host "`nApplying keys..." -ForegroundColor Cyan

function Set-EnvVar {
    param([string]$Name, [string]$Value)
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        # Set for the current running terminal session
        [System.Environment]::SetEnvironmentVariable($Name, $Value, "Process")
        Write-Host "  [+] $Name set in current session." -ForegroundColor Green
        
        if ($Permanent) {
            # Save it permanently in Windows User Environment variables
            [System.Environment]::SetEnvironmentVariable($Name, $Value, "User")
            Write-Host "  [+] $Name saved permanently to Windows." -ForegroundColor DarkGreen
        }
    }
}

Set-EnvVar -Name "HF_TOKEN" -Value $hfToken
Set-EnvVar -Name "DEEPSEEK_API_KEY" -Value $deepseekKey
Set-EnvVar -Name "GROQ_API_KEY" -Value $groqKey

Write-Host "`nSetup complete! You can now run 'ctfgpt ask ...'" -ForegroundColor Cyan
if (-not $Permanent) {
    Write-Host "Note: Keys were only set for this specific PowerShell window." -ForegroundColor Yellow
    Write-Host "Run '.\setup_keys.ps1 -Permanent' to save them permanently across all new terminals." -ForegroundColor Yellow
}
