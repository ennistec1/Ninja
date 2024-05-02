# Ninja Uninstall Script with support for reamoving TeamViewer if '-DelTeamViewer' parameter is used
# to be deleted:
# Usage: [-Uninstall] [-Cleanup] [-DelTeamViewer]
#   -Uninstall calls msiexec {ninjaRmmAgent product ID}
#   -Cleanup removes keys, files, services 
#   -DelTeamViewer deletes TeamViewer
# Examples:
#
# NewAgentRemoval.ps1 -Uninstall
#   disables uninstall prevention and uninstalls using msiexec, does not check if there are any leftovers
#
# NewAgentRemoval.ps1 -Cleanup
#   removes keys, files, services related to NinjaRMMProduct, does not use amy msiexec, uninstall prevention status is ignored
#
# NewAgentRemoval.ps1  -Uninstall -Cleanup
#   combines two actions together
#   order of arguments does not matter, msiexec is called first, cleanup goes second

param (
    [Parameter(Mandatory=$false)]
    [switch]$DelTeamViewer = $false,
	[Parameter(Mandatory=$false)]
	[switch]$Cleanup=$true,
	[Parameter(Mandatory=$false)]
	[switch]$Uninstall=$true,
	[Parameter(Mandatory=$false)]
	[switch]$ShowError
)

$NinjaInstaller = "https://app.ninjarmm.com/v2/organization/$($env:NINJA_ORGANIZATION_ID)/location/$($env:NINJA_LOCATION_ID)/installer/WINDOWS_MSI"

## for finding uninstall string
function Get-UninstallString {
    [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]
  
    Param (
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="Global")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndCurrentUser")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndAllUsers")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="CurrentUser")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="AllUsers")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="Global32")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndCurrentUser32")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="GlobalAndAllUsers32")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="CurrentUser32")]
      [Parameter(Mandatory = $True, ValueFromPipeline=$true, Position=0,ParameterSetName="AllUsers32")]
      [ValidateNotNullOrEmpty()]
      [string]$ApplicationName,
      [Parameter(ParameterSetName="Global32")]
      [Parameter(ParameterSetName="GlobalAndCurrentUser32")]
      [Parameter(ParameterSetName="GlobalAndAllUsers32")]
      [Parameter(ParameterSetName="CurrentUser32")]
      [Parameter(ParameterSetName="AllUsers32")]
      [switch]$Wow6432Only,
      [Parameter(ParameterSetName="Global")]
      [Parameter(ParameterSetName="GlobalAndCurrentUser")]
      [Parameter(ParameterSetName="GlobalAndAllUsers")]
      [Parameter(ParameterSetName="CurrentUser")]
      [Parameter(ParameterSetName="AllUsers")]
      [switch]$NoWow6432,
      [Parameter(ParameterSetName="Global")]
      [Parameter(ParameterSetName="Global32")]
      [switch]$Global,
      [Parameter(ParameterSetName="GlobalAndCurrentUser")]
      [Parameter(ParameterSetName="GlobalAndCurrentUser32")]
      [switch]$GlobalAndCurrentUser,
      [Parameter(ParameterSetName="GlobalAndAllUsers")]
      [Parameter(ParameterSetName="GlobalAndAllUsers32")]
      [switch]$GlobalAndAllUsers,
      [Parameter(ParameterSetName="CurrentUser")]
      [Parameter(ParameterSetName="CurrentUser32")]
      [switch]$CurrentUser,
      [Parameter(ParameterSetName="AllUsers")]
      [Parameter(ParameterSetName="AllUsers32")]
      [switch]$AllUsers
  
    )
  
    # Explicitly set default param to True if used to allow conditionals to work
    if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
      $GlobalAndAllUsers = $true
    }
  
    # Check if running with Administrative privileges if required
    if ($GlobalAndAllUsers -or $AllUsers) {
      $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
      if ($RunningAsAdmin -eq $false) {
        Write-Error "Finding all user applications requires administrative privileges"
        break
      }
    }
  
    # Empty array to store applications
    $Apps = @()
    $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
  
    # Retreive globally installed applications
    if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
      if (!($NoWow6432.IsPresent)) {
        $Apps += Get-ItemProperty "HKLM:\$32BitPath"
      }
      if (!($Wow6432Only.IsPresent)) {
        $Apps += Get-ItemProperty "HKLM:\$64BitPath"
      }
    }
  
    if ($CurrentUser -or $GlobalAndCurrentUser) {
      if (!($NoWow6432.IsPresent)) {
        $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
      }
      if (!($Wow6432Only.IsPresent)) {
        $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
      }
    }
  
    if ($AllUsers -or $GlobalAndAllUsers) {
      $AllProfiles = Get-CimInstance Win32_UserProfile | 
        Select-Object LocalPath, SID, Loaded, Special | 
        Where-Object {$_.SID -like "S-1-5-21-*"}
      $MountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $true}
      $UnmountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $false}
  
      $MountedProfiles | Foreach-Object {
        if (!($NoWow6432.IsPresent)) {
          $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
        }
        if (!($Wow6432Only.IsPresent)) {
          $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
        }
      }
  
      $UnmountedProfiles | ForEach-Object {
  
        $Hive = "$($_.LocalPath)\NTUSER.DAT"
  
        if (Test-Path $Hive) {
              
          REG LOAD HKU\temp $Hive 2>&1>$null
  
          if (!($NoWow6432.IsPresent)) {
            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
          }
          if (!($Wow6432Only.IsPresent)) {
            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"
          }
  
          # Run manual GC to allow hive to be unmounted
          [GC]::Collect()
          [GC]::WaitForPendingFinalizers()
              
          REG UNLOAD HKU\temp 2>&1>$null
  
        } 
      }
    }
  
    foreach ($app in $Apps) {
      if ($app.DisplayName -eq $ApplicationName -and $app.UninstallString -like 'MsiExec*') {
      return Split-Path -Path $app.PSPath -Leaf
      }
    }
    return ""
  }

$ErrorActionPreference = 'SilentlyContinue'

if($ShowError -eq $true) {
    $ErrorActionPreference = 'Continue'
}

Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Uninstall" -PercentComplete 0

if([system.environment]::Is64BitOperatingSystem)
{
    $ninjaPreSoftKey = 'HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC'
    $uninstallKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    $exetomsiKey = 'HKLM:\SOFTWARE\WOW6432Node\EXEMSI.COM\MSI Wrapper\Installed'
}
else
{
    $ninjaPreSoftKey = 'HKLM:\SOFTWARE\NinjaRMM LLC'
    $uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $exetomsiKey = 'HKLM:\SOFTWARE\EXEMSI.COM\MSI Wrapper\Installed'
}

$ninjaSoftKey = Join-Path $ninjaPreSoftKey -ChildPath 'NinjaRMMAgent'
$ninjaDir = [string]::Empty
$ninjaDataDir = Join-Path -Path $env:ProgramData -ChildPath "NinjaRMMAgent"

###################################################################################################
# locating NinjaRMMAgent
###################################################################################################
$ninjaDirRegLocation = $(Get-ItemPropertyValue $ninjaSoftKey -Name Location) 
if($ninjaDirRegLocation)
{
    if(Join-Path -Path $ninjaDirRegLocation -ChildPath "NinjaRMMAgent.exe" | Test-Path)
    {
        #location confirmed from registry location
        $ninjaDir = $ninjaDirRegLocation
    }
}

Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Uninstall" -PercentComplete 10

if(!$ninjaDir)
{
    #attempt to get the path from service
    $ss = Get-CimInstance -ClassName Win32_Service -Filter "name= 'NinjaRMMAgent'"
    if($ss)
    {
        $ninjaDirService = ($(Get-CimInstance -ClassName Win32_Service -Filter "name= 'NinjaRMMAgent'").PathName | Split-Path).Replace("`"", "")
        if(Join-Path -Path $ninjaDirService -ChildPath "NinjaRMMAgentPatcher.exe" | Test-Path)
        {
            #location confirmed from service location
            $ninjaDir = $ninjaDirService
        }
    }
}

if($ninjaDir)
{
    $ninjaDir.Replace('/','\')
}

if($Uninstall)
{
    Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Uninstall" -PercentComplete 30
    Start "$ninjaDir\NinjaRMMAgent.exe" -disableUninstallPrevention NOUI
    # Executes uninstall.exe in Ninja install directory
    $Arguments = @(
        "/x $(Get-UninstallString -ApplicationName NinjaRMMAgent -Wow6432Only -Global)"
        "/quiet"
        "/L*V"
        "C:\windows\temp\NinjaRMMAgent_uninstall.log"
        "WRAPPED_ARGUMENTS=`"--mode unattended`""
    )

#Start Uninstall
Start-Process "msiexec.exe" $arguments
sleep 150
Write-Progress -Activity "Running Ninja Removal Script" -Status "Uninstall Complete" -PercentComplete 45
}


if($Cleanup)
{
    Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Cleanup" -PercentComplete 50
    $service=Get-Service "NinjaRMMAgent"
    if($service)
    {
        Stop-Service $service -Force
        & sc.exe DELETE NinjaRMMAgent
        #Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NinjaRMMAgent
    }
    $proxyservice=Get-Process "NinjaRMMProxyProcess64"
    if($proxyservice)
    {
        Stop-Process $proxyservice -Force
    }
    $nmsservice=Get-Service "nmsmanager"
    if($nmsservice)
    {
        Stop-Service $nmsservice -Force
        & sc.exe DELETE nmsmanager
    }
    # Delete Ninja install directory and all contents
    if(Test-Path $ninjaDir)
    {
        & cmd.exe /c rd /s /q $ninjaDir
    }

    if(Test-Path $ninjaDataDir)
    {
        & cmd.exe /c rd /s /q $ninjaDataDir
    }

    #Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent
    Remove-Item -Path  -Recurse -Force

    # Will search registry locations for NinjaRMMAgent value and delete parent key
    # Search $uninstallKey
    $keys = Get-ChildItem $uninstallKey | Get-ItemProperty -name 'DisplayName'
    foreach ($key in $keys) {
        if ($key.'DisplayName' -eq 'NinjaRMMAgent'){
            Remove-Item $key.PSPath -Recurse -Force
            }
    }

    #Search $installerKey
    $keys = Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' | Get-ItemProperty -name 'ProductName'
    foreach ($key in $keys) {
        if ($key.'ProductName' -eq 'NinjaRMMAgent'){
            Remove-Item $key.PSPath -Recurse -Force
            }
    }
    # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\A0313090625DD2B4F824C1EAE0958B08\InstallProperties
    $keys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
    foreach ($key in $keys) {
        $kn = $key.Name -replace 'HKEY_LOCAL_MACHINE' , 'HKLM:'; 
        $k1 = Join-Path $kn -ChildPath 'InstallProperties';
        if( $(Get-ItemProperty -Path $k1 -Name DisplayName).DisplayName -eq 'NinjaRMMAgent')
        {
            $toremove = 
            Get-Item -LiteralPath $kn | Remove-Item -Recurse -Force
        }
    }

    #Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\EXEMSI.COM\MSI Wrapper\Installed\NinjaRMMAgent 5.3.3681
    Get-ChildItem $exetomsiKey | Where-Object -Property Name -CLike '*NinjaRMMAgent*'  | Remove-Item -Recurse -Force

    #HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC
    Get-Item -Path $ninjaPreSoftKey | Remove-Item -Recurse -Force

    # agent creates this key by mistake but we delete it here
    Get-Item -Path "HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\NinjaRMM LLC" | Remove-Item -Recurse -Force

Write-Progress -Activity "Running Ninja Removal Script" -Status "Cleanup Completed" -PercentComplete 75
sleep 1
}

if(Get-Item -Path $ninjaPreSoftKey)
{
    echo "Failed to remove NinjaRMMAgent reg keys ", $ninjaPreSoftKey
}

if(Get-Service "NinjaRMMAgent")
{
    echo "Failed to remove NinjaRMMAgent service"
}

if($ninjaDir)
{
    if(Test-Path $ninjaDir)
    {
        echo "Failed to remove NinjaRMMAgent program folder"
        if(Join-Path -Path $ninjaDir -ChildPath "NinjaRMMAgent.exe" | Test-Path)
        {
            echo "Failed to remove NinjaRMMAgent.exe"
        }

        if(Join-Path -Path $ninjaDir -ChildPath "NinjaRMMAgentPatcher.exe" | Test-Path)
        {
            echo "Failed to remove NinjaRMMAgentPatcher.exe"
        }
    }
}

# Uninstall TeamViewer only if -DelTeamViewer parameter specified
if($DelTeamViewer -eq $true){
Write-Progress -Activity "Running Ninja Removal Script" -Status "TeamViewer Removal Starting" -PercentComplete 80
    $tvProcess = Get-Process -Name 'teamviewer*'
    Stop-Process -InputObject $tvProcess -Force # Stops TeamViewer process
# Call uninstaller - 32/64-bit (if exists)
$tv64Uninstaller = Test-Path ${env:ProgramFiles(x86)}"\TeamViewer\uninstall.exe"
if ($tv64Uninstaller) {
    & ${env:ProgramFiles(x86)}"\TeamViewer\uninstall.exe" /S | out-null
}
$tv32Uninstaller = Test-Path ${env:ProgramFiles}"\TeamViewer\uninstall.exe"
if ($tv32Uninstaller) {
    & ${env:ProgramFiles}"\TeamViewer\uninstall.exe" /S | out-null
}
# Ensure all registry keys have been removed - 32/64-bit (if exists)
    Remove-Item -path HKLM:\SOFTWARE\TeamViewer -Recurse
    Remove-Item -path HKLM:\SOFTWARE\WOW6432Node\TeamViewer -Recurse 
    Remove-Item -path HKLM:\SOFTWARE\WOW6432Node\TVInstallTemp -Recurse 
    Remove-Item -path HKLM:\SOFTWARE\TeamViewer -Recurse
    Remove-Item -path HKLM:\SOFTWARE\Wow6432Node\TeamViewer -Recurse
Write-Progress -Activity "Running Ninja Removal Script" -Status "TeamViewer Removal Completed" -PercentComplete 90
sleep 1
}

Write-Progress -Activity "Running Ninja Removal Script" -Status "Completed" -PercentComplete 100
sleep 1

$error | out-file C:\Windows\Temp\NinjaRemovalScriptError.txt

"`n`n"
$NinjaInstaller

