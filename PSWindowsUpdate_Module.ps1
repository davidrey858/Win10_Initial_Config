###Set Execution Policy

Set-ExecutionPolicy RemoteSigned

###Finds latest version of NuGet PackageProvider

Find-PackageProvider -Name "Nuget" -AllVersions

###Installed the latest 2.8.5.208 version

Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force

###Looks for PSWindowsUpdate Module

Find-Module -Repository PsGallery -Name PSWindowsUpdate

###Install PSWindowsUpdate Module

install-module -Name PSWindowsUpdate -Repository PsGallery 

###Verified Installd

get-module -Name PSWindowsUpdate

###View Commands

get-command -Module PSWindowsUpdate

###Install all critical updates except and force

Install-WindowsUpdate -Severity Critical -AcceptAll -ForceInstall

