
#Requires -Version 5.1

<#
.SYNOPSIS
    Refreshes the NinjaOne agent, reinstalls it, and schedules a reboot.

.DESCRIPTION
    Validates required files before uninstalling the existing agent.
    Logs progress and errors to the console for NinjaOne activity output.
    Stops if uninstall or installation fails.

.NOTES
    .AUTHOR Eric Ennis
    .COMPANYNAME Advantage Technologies, Inc.
    .COPYRIGHT 2022 (c) Advantage Technologies, Inc. - All Rights Reserved.
    .VERSION 2.0.0
    .LASTUPDATED 2026-10-28
#>

$ErrorActionPreference = 'Stop'

# Configuration
$CliPath       = 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe'
$WorkingPath   = 'C:\Working\NinjaOneRefresh'
$RemovalScript = Join-Path $WorkingPath 'NewAgentRemoval.ps1'
$InstallerPath = Join-Path $WorkingPath 'NinjaRMMAgent_Setup.msi'

# Logging
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$Timestamp] [$Level] $Message"
}

function Stop-Refresh {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [int]$ExitCode = 1
    )

    Write-Log -Message $Message -Level ERROR
    Write-Log -Message "Refresh aborted. Exit code: $ExitCode" -Level ERROR
    exit $ExitCode
}

Write-Log 'Starting NinjaOne agent refresh.'
Write-Log "Working directory: $WorkingPath"

# ------------------------------------------------------------
# STEP 1: Validate prerequisites BEFORE uninstalling anything
# ------------------------------------------------------------

Write-Log 'Checking required files.'

$RequiredFiles = @(
    @{ Path = $InstallerPath; Description = 'NinjaOne MSI installer' },
    @{ Path = $RemovalScript; Description = 'Agent removal script' }
)

foreach ($File in $RequiredFiles) {
    if (-not (Test-Path -LiteralPath $File.Path -PathType Leaf)) {
        Stop-Refresh -Message (
            "Required file missing: {0} ({1}). Existing agent was not uninstalled." -f
            $File.Description, $File.Path
        ) -ExitCode 2
    }

    Write-Log "Found $($File.Description): $($File.Path)" -Level SUCCESS
}

# Check that the installer is not empty.
try {
    $Installer = Get-Item -LiteralPath $InstallerPath

    if ($Installer.Length -le 0) {
        Stop-Refresh -Message "Installer is empty: $InstallerPath" -ExitCode 2
    }

    Write-Log "Installer size: $([Math]::Round($Installer.Length / 1MB, 2)) MB"
}
catch {
    Stop-Refresh -Message "Unable to validate installer: $($_.Exception.Message)" -ExitCode 2
}

# ------------------------------------------------------------
# STEP 2: Set NinjaOne custom field
# ------------------------------------------------------------

if (Test-Path -LiteralPath $CliPath -PathType Leaf) {
    try {
        Write-Log 'Setting NinjaOne Sieve field to DuplicateNinja.'

        $Process = Start-Process `
            -FilePath $CliPath `
            -ArgumentList @('set', 'sieve', 'DuplicateNinja') `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -ErrorAction Stop

        if ($Process.ExitCode -ne 0) {
            Write-Log "Sieve update returned exit code $($Process.ExitCode)." -Level WARNING
        }
        else {
            Write-Log 'Sieve field update completed.' -Level SUCCESS
        }
    }
    catch {
        Write-Log "Unable to update Sieve field: $($_.Exception.Message)" -Level WARNING
    }
}
else {
    Write-Log "NinjaOne CLI not found: $CliPath. Continuing with refresh." -Level WARNING
}

# ------------------------------------------------------------
# STEP 3: Uninstall existing agent
# ------------------------------------------------------------

try {
    Write-Log 'Starting NinjaOne agent removal.'

    $Arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Uninstall -Cleanup' -f $RemovalScript

    $Process = Start-Process `
        -FilePath 'powershell.exe' `
        -ArgumentList $Arguments `
        -Wait `
        -PassThru `
        -NoNewWindow `
        -ErrorAction Stop

    Write-Log "Removal process exit code: $($Process.ExitCode)"

    if ($Process.ExitCode -ne 0) {
        Stop-Refresh -Message 'NinjaOne agent removal failed. MSI installation skipped.' -ExitCode 3
    }

    Write-Log 'NinjaOne agent removed successfully.' -Level SUCCESS
}
catch {
    Stop-Refresh -Message "Removal failed: $($_.Exception.Message)" -ExitCode 3
}

# ------------------------------------------------------------
# STEP 4: Install the new agent
# ------------------------------------------------------------

try {
    Write-Log 'Waiting 5 seconds before installation.'
    Start-Sleep -Seconds 5

    # Recheck the installer in case it was removed during cleanup.
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        Stop-Refresh -Message 'Installer disappeared after uninstall. Cannot continue.' -ExitCode 4
    }

    Write-Log 'Installing NinjaOne agent silently.'

    $MsiArguments = '/i "{0}" /qn /norestart' -f $InstallerPath

    $Process = Start-Process `
        -FilePath "$env:SystemRoot\System32\msiexec.exe" `
        -ArgumentList $MsiArguments `
        -Wait `
        -PassThru `
        -NoNewWindow `
        -ErrorAction Stop

    $MsiExitCode = $Process.ExitCode
    Write-Log "MSI installer exit code: $MsiExitCode"

    switch ($MsiExitCode) {
        0 {
            Write-Log 'NinjaOne agent installed successfully.' -Level SUCCESS
        }
        3010 {
            Write-Log 'NinjaOne agent installed successfully; MSI reports a reboot is required.' -Level SUCCESS
        }
        default {
            Stop-Refresh -Message "NinjaOne installation failed with MSI exit code $MsiExitCode. Reboot not scheduled." -ExitCode 4
        }
    }
}
catch {
    Stop-Refresh -Message "Installation failed: $($_.Exception.Message)" -ExitCode 4
}

# ------------------------------------------------------------
# STEP 5: Schedule reboot for 11:00 PM local time
# ------------------------------------------------------------

try {
    $Now = Get-Date
    $RebootTime = [datetime]::Today.AddHours(23)

    # If 11 PM has already passed, schedule for the next day.
    if ($RebootTime -le $Now) {
        $RebootTime = $RebootTime.AddDays(1)
    }

    $SecondsUntilReboot = [int][Math]::Ceiling(
        ($RebootTime - $Now).TotalSeconds
    )

    if ($SecondsUntilReboot -le 60) {
        Stop-Refresh -Message 'Calculated reboot delay is too short. Reboot not scheduled.' -ExitCode 5
    }

    Write-Log "Scheduling reboot for $($RebootTime.ToString('yyyy-MM-dd hh:mm:ss tt'))."
    Write-Log "Reboot countdown: $([Math]::Round($SecondsUntilReboot / 3600, 2)) hours."

    $Shutdown = Start-Process `
        -FilePath "$env:SystemRoot\System32\shutdown.exe" `
        -ArgumentList @(
            '/r',
            '/t', "$SecondsUntilReboot",
            '/c', '"Regular maintenance - Restart AT 11:00 PM"'
        ) `
        -Wait `
        -PassThru `
        -NoNewWindow `
        -ErrorAction Stop

    if ($Shutdown.ExitCode -ne 0) {
        Stop-Refresh -Message "Failed to schedule reboot. Shutdown exit code: $($Shutdown.ExitCode)" -ExitCode 5
    }

    Write-Log 'Reboot scheduled successfully.' -Level SUCCESS
    Write-Log 'NinjaOne agent refresh completed.' -Level SUCCESS
    exit 0
}
catch {
    Stop-Refresh -Message "Reboot scheduling failed: $($_.Exception.Message)" -ExitCode 5
}
