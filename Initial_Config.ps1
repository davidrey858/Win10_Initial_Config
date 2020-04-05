if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function Check-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# -----------------------------------------------------------------------------
$computerName = Read-Host 'Enter New Computer Name'
Write-Host "Renaming this computer to: " $computerName  -ForegroundColor Yellow
Rename-Computer -NewName $computerName
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Disable Sleep on AC Power..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Powercfg /Change monitor-timeout-ac 20
Powercfg /Change standby-timeout-ac 0
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Add 'This PC' Desktop Icon..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" 
$item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue 
if ($item) { 
    Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  
} 
else { 
    New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD | Out-Null  
} 

# -----------------------------------------------------------------------------

# To list all appx packages:
# Get-AppxPackage | Format-Table -Property Name,Version,PackageFullName
Write-Host "Removing UWP Rubbish..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$uwpRubbishApps = @(
    "Microsoft.Messaging",
    "king.com.CandyCrushSaga",
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingFinance",
    "Microsoft.XboxApp",
    "Microsoft.WindowsPhone",
    "Microsoft.Office.OneNote",
    "Microsoft.Windows.Photos"
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.SkypeApp",
    "microsoft.windowscommunicationsapps",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.ZuneVideo",
    "Microsoft.ZuneMusic",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxGameOverlay",
    "Microsoft.Xbox.TCUI",
    "Microsoft.WindowsMaps",
    "Microsoft.MicrosoftStickyNotes",
    "microsoft.oneconnect",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.YourPhone",
    "Microsoft.MicrosoftOfficeHub",
    "Fitbit.FitbitCoach",
    "4DF9E0F8.Netflix",
    "Microsoft.GetHelp")

foreach ($uwp in $uwpRubbishApps) {
    Get-AppxPackage -Name $uwp | Remove-AppxPackage
}

# -----------------------------------------------------------------------------
#Write-Host ""
#Write-Host "Installing IIS..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionDynamic -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ServerSideIncludes
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "Enable Windows 10 Developer Mode..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
# -----------------------------------------------------------------------------
#Write-Host ""
#Write-Host "Enable Remote Desktop..." -ForegroundColor Green
#Write-Host "------------------------------------" -ForegroundColor Green
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
#Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 1
#Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

#-----------------------------------------------------------------------------

# Install Chocolatey

Write-Host ""
Write-Host "Installing Chocolatey for Windows..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install software via Chocolatey

Write-Host ""
Write-Host "Installing Applications..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green


choco install git -y
choco install 7zip.install -y
choco install googlechrome -y
choco install dotnetcore-sdk -y
choco install wget -y
choco install openssl.light -y
choco install vscode -y
choco install vscode-icons -y
choco install vscode-powershell -y
choco install sysinternals -y
choco install notepadplusplus.install -y
choco install vmwareworkstation -y
#choco install steam -y
#choco install dotpeek -y
#choco install linqpad -y
#choco install fiddler -y
#choco install beyondcompare -y
#choco install filezilla -y
#choco install lightshot.install -y
#choco install microsoft-teams.install -y
#choco install teamviewer -y
#choco install github-desktop -y
#choco install irfanview -y
#choco install potplayer -y
#choco install ffmpeg -y
#choco install vscode-csharp -y
#choco install vscode-mssql -y
#choco install nodejs -y


#Did not work# Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'

#Install PS 7.0
Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.0.0/PowerShell-7.0.0-win-x64.msi -OutFile .\PS7.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I PS7.msi /quiet'

###Remove Edge Shortcut from desktop
Write-Host ""
Write-Host "Removing Edge Desktop Icon..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$edgeLink = $env:USERPROFILE + "\Desktop\Microsoft Edge.lnk"
Remove-Item $edgeLink

###Remove Chrome Shortcut from desktop
Write-Host ""
Write-Host "Removing Chrome Desktop Icon..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$ChromeLink = $env:USERPROFILE + "\Desktop\Google Chrome.lnk"
Remove-Item $ChromeLink

###Remove Code Shortcut from desktop
Write-Host ""
Write-Host "Removing VS Code Desktop Icon..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$CodeLink = $env:USERPROFILE + "\Desktop\Visual Studio Code.lnk"
Remove-Item $CodeLink

###Remove VMware Workstation Shortcut from desktop
Write-Host ""
Write-Host "Removing VMware Workstation Desktop Icon..." -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$VMwareLink = 'C:\users\Public\Desktop\VMware Workstation Pro.lnk'
Remove-Item $VMwareLink

#Show hidden files and Un-hide file extensions
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key Hidden 1
Set-ItemProperty $key HideFileExt 0
#Set-ItemProperty $key ShowSuperHidden 1 ###Shows everything 
Stop-Process -processname explorer

# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0

# Dark Theme for Windows
If (-Not (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize)) {
	New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes -Name Personalize | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 0

# Disable SMBv1
Write-Host "Disabling SMBv1"

Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

# Disable Cortana
Write-Host "Disabling Cortana"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivicyPolicy" -Type DWord -Value 0 -ErrorAction SilentlyContinue
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 -ErrorAction SilentlyContinue
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 -ErrorAction SilentlyContinue
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force -ErrorAction SilentlyContinue | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowContanaAboveLock" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue

# Add Enviromental Variables

[Environment]::SetEnvironmentVariable("Chrome", "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")

[Environment]::SetEnvironmentVariable("VMware", "C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe")


# Remove OneDrive
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}



# Reboot
Write-Host "------------------------------------" -ForegroundColor Green
Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
Restart-Computer