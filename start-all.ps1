param(
    [switch]$Detach
)

$composeCli = $null
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $composeCli = "docker"
} elseif (Get-Command podman -ErrorAction SilentlyContinue) {
    $composeCli = "podman"
}

if (-not $composeCli) {
    Write-Error "No supported container CLI found. Install Docker or Podman and rerun this script."
    exit 1
}

$composeArgs = "compose up --build"
if ($Detach) {
    $composeArgs += " -d"
}

Write-Host "Starting ImmuniSOC-Nexus stack with: $composeCli $composeArgs"
& $composeCli $composeArgs
