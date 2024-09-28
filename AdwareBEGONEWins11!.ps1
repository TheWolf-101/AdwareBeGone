###########################################################################################################
# Created by Noah Campbell                                                                                #
# This script was made to be run after the set up of a PC running Windows 11 to clean up all the Adware   #
# and extra software included with Windows 11 machines right after setting it up. This script should work #
# on Windows 10 machines as well.                                                                         #
###########################################################################################################

###############################################################
# This part elevates the script to admin if it isn't already. #
###############################################################
param([switch]$Elevated)
function Checkpoint-Admin {
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((Checkpoint-Admin) -eq $false)  {
if ($elevated)
{
# could not elevate, quit
}
else {
Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
}
exit
}

# Ask for elevated permissions if required, incase the aboves doesn't work. #
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

##########################################################
# Feel free to comment out things you want on the PC and # 
# uncomment things you want uninstalled from the PC      #
##########################################################

#Get-AppxPackage -AllUsers *3DViewer* | Remove-AppxPackage
#Get-AppxPackage -AllUsers Microsoft.Microsoft3DViewer | Remove-AppxPackage
#Get-AppxPackage -Allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
#Get-AppxPackage -allusers *feedback* | Remove-AppxPackage
#Get-AppxPackage -allusers Microsoft.gethelp | Remove-AppxPackage
#Get-AppxPackage -allusers Microsoft.MixedReality.Portal | Remove-AppxPackage
#Get-AppxPackage -allusers Microsoft.People | Remove-AppxPackage
#Get-AppxPackage -allusers Microsoft.YourPhone | Remove-AppxPackage
#Get-AppxPackage -allusers *Skype* | Remove-AppxPackage
#Get-AppxPackage -allusers *Xbox* | Remove-AppxPackage
#Get-AppxPackage -allusers E046963F.LenovoCompanion | Remove-AppxPackage
#Get-AppxPackage -allusers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage
#Get-AppxPackage -allusers Disney.37853FC22B2CE | Remove-AppxPackage
#Get-AppxPackage -allusers Microsoft.WindowsMaps | Remove-AppxPackage
#Get-AppxPackage -allusers Microsoft.Office.OneNote | Remove-AppxPackage
#Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage
Get-AppxPackage E046963F.LenovoSettingsforEnterprise | Remove-AppxPackage
Remove-AppxPackage -allusers Microsoft.BingWeather_4.53.50501.0_x64__8wekyb3d8bbwe
Get-AppxPackage -allusers SpotifyAB.SpotifyMusic | Remove-AppxPackage

# Replace UserName and Shortcut with your actual values
$path = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Skype for Business.lnk"
Remove-Item $path

$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Microsoft Search in Bing"}
$MyApp.Uninstall()

Get-Process C:\Windows\system32> Write-Output "Removing Windows 10 Mail Appx Package"
Get-AppxPackage Microsoft.windowscomminicationsapps | Remove-AppxPackage
Get-AppxPackage Microsoft.windowscomminicationsapps | Remove-AppxPackage -Allusers
if(Get-AppxPackage -Name Microsoft.windowscommunicationsapps -AllUsers){
Get-AppxPackage -Name Microsoft.windowscommunicationsapps -AllUsers | Remove-AppxPackage -AllUsers - Verbose -ErrorAction Continue
}
else{
Write-Output "Mail app is not installed for any user"
}
if(Get-ProvisionedAppxPackage -Online | Where-Object {$_.Displayname -match "Microsoft.windowscommunicationsapps"}){
Get-ProvisionedAppxPackage -Online |Where-Object {$_.DisplayName -Match "Microsoft.windowscommunicationsapps"} | Remove-AppxProvisionedPackage -Online -AllUsers -Verbose -ErrorAction Continue
}
else {
Write-Output "Mails app is not installed for the system"
}

##############################################################
# This removes any preinstalled Lenovo services/applications #
##############################################################
net stop LenovoVisionService
net stop LenovoPMService
net stop BcastDVRUserService_9da2b
net stop AxInstSV
Set-Service -Name "stisvc" -Status stopped -StartupType disabled
Set-Service -Name "AxInstSV" -Status stopped -StartupType disabled
Set-Service -Name "BcastDVRUserService_9da2b" -Status stopped -StartupType disabled
sc.exe delete LenovoVisionService
sc.exe delete LenovoSmartStandby
sc.exe delete LenovoPMService
sc.exe delete XboxNetApiSvc
sc.exe delete XblGameSave
sc.exe delete XblAuthManager
sc.exe delete XboxGipSvc
Write-Host "Removing 3D Objects icon from computer namespace..."
Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

$AppList = "E046963F.LenovoCompanion",           
           "LenovoCorporation.LenovoSettings",
           "E046963F.LenovoSettingsforEnterprise"

ForEach ($App in $AppList)
{
   $PackageFullName = (Get-AppxPackage -allusers $App).PackageFullName
   $ProPackageFullName = (Get-AppxProvisionedPackage -online | Where-Object {$_.Displayname -eq $App}).PackageName
  
   ForEach ($AppToRemove in $PackageFullName)
   {
     Write-Host "Removing Package: $AppToRemove"
     try
     {
        remove-AppxPackage -package $AppToRemove -allusers
     }
     catch
     {
        # Starting in Win10 20H1, bundle apps (like Vantage) have to be removed a different way
        $PackageBundleName = (Get-AppxPackage -packagetypefilter bundle -allusers $App).PackageFullName
        ForEach ($BundleAppToRemove in $PackageBundleName)
        {
           remove-AppxPackage -package $BundleAppToRemove -allusers
        }
     }
   }

   ForEach ($AppToRemove in $ProPackageFullName)
   {
     Write-Host "Removing Provisioned Package: $AppToRemove"
     try
     {
        Remove-AppxProvisionedPackage -online -packagename $AppToRemove
     }
     catch
     {
        # bundled/provisioned apps are already removed by "remove-AppxPackage -allusers"
     }
   }

}

####################
# Disables Cortana #
####################
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

##############################################
# Uninstall default Microsoft applications   # 
# Uncomment what you do not want to keep     #
# Comment the things you want to keep        #
##############################################

Write-Host "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppPackage
Get-AppxPackage "5A894077.McAfeeSecurity" | Remove-AppPackage
Get-AppxPackage "Disney.37853FC22B2CE" | Remove-AppPackage
Get-AppxPackage "Microsoft.GamingApp" | Remove-AppPackage
Get-AppxPackage "Facebook.InstagramBeta" | Remove-AppPackage
Get-AppxPackage "AdobeSystemsIncorporated.AdobeCreativeCloudExpress" | Remove-AppPackage
Get-AppxPackage "AmazonVideo.PrimeVideo" | Remove-AppPackage
Get-AppxPackage "BytedancePte.Ltd.TikTok" | Remove-AppPackage


Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsCamera").InstallLocation)\AppXManifest.xml"

##################################################
# Disables services you don't need               #
# Commnet the services you want to keep          #
# Uncomment the serveices you don't want to keep #
##################################################
$services = @(
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    # "RemoteRegistry"                         # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    # "WbioSrvc"                               # Windows Biometric Service (required for Fingerprint reader / facial detection)
    #"WlanSvc"                                 # WLAN AutoConfig
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    #"wscsvc"                                  # Windows Security Center Service
    #"WSearch"                                 # Windows Search
    "XblAuthManager"                           # Xbox Live Auth Manager
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service
    "ndu"                                      # Windows Network Data Usage Monitor
    # Services which cannot be disabled
    #"WdNisSvc"
)

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Uninstalling default apps"
$apps = @(
    # default Windows 10 apps
    "Microsoft.3DBuilder"
    "Microsoft.Advertising.Xaml"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.FreshPaint"
    "Microsoft.GamingServices"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MixedReality.Portal"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    "E046963F.LenovoCompanion"
    "SpotifyAB.SpotifyMusic"
    "E046963F.LenovoSettingsforEnterprise"
    "Microsoft.gethelp"
    "Microsoft.549981C3F5F10"

    #"Microsoft.MicrosoftStickyNotes"
    "Microsoft.MinecraftUWP"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    # "Microsoft.Windows.Photos"
    # "Microsoft.WindowsAlarms"
    # "Microsoft.WindowsCalculator"
    # "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.WindowsStore"   # can't be re-installed
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.Windows.CloudExperienceHost"
    "Microsoft.Windows.ContentDeliveryManager"
    "Microsoft.Windows.PeopleExperienceHost"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.GamingApp"

    # Threshold 2 apps
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"

    # Creators Update apps
    "Microsoft.Microsoft3DViewer"
    #"Microsoft.MSPaint"

    #Redstone apps
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.WindowsReadingList"

    # Redstone 5 apps
    "Microsoft.MixedReality.Portal"
    #"Microsoft.ScreenSketch"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.YourPhone"

    # non-Microsoft
    "2FE3CB00.PicsArt-PhotoStudio"
    "46928bounde.EclipseManager"
    "4DF9E0F8.Netflix"
    "613EBCEA.PolarrPhotoEditorAcademicEdition"
    "6Wunderkinder.Wunderlist"
    "7EE7776C.LinkedInforWindows"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.MarchofEmpires"
    "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
    "CAF9E577.Plex"
    "ClearChannelRadioDigital.iHeartRadio"
    "D52A8D61.FarmVille2CountryEscape"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "DolbyLaboratories.DolbyAccess"
    "DolbyLaboratories.DolbyAccess"
    "Drawboard.DrawboardPDF"
    "Facebook.Facebook"
    "Fitbit.FitbitCoach"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "KeeperSecurityInc.Keeper"
    "NORDCURRENT.COOKINGFEVER"
    "PandoraMediaInc.29680B314EFC2"
    "Playtika.CaesarsSlotsFreeCasino"
    "ShazamEntertainmentLtd.Shazam"
    "SlingTVLLC.SlingTV"
    "SpotifyAB.SpotifyMusic"
    "TheNewYorkTimes.NYTCrossword"
    "ThumbmunkeysLtd.PhototasticCollage"
    "TuneIn.TuneInRadio"
    "WinZipComputing.WinZipUniversal"
    "XINGAG.XING"
    "flaregamesGmbH.RoyalRevolt2"
    "king.com.*"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "5A894077.McAfeeSecurity"
    "Disney.37853FC22B2CE"
    "Facebook.InstagramBeta"
    "AdobeSystemsIncorporated.AdobeCreativeCloudExpress"
    "AmazonVideo.PrimeVideo"
    "BytedancePte.Ltd.TikTok"

    # apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    "Microsoft.Windows.Cortana"
    "Microsoft.WindowsFeedback"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.XboxIdentityProvider"
    "Windows.ContactSupport"

    # apps which other apps depend on
    "Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}

####################################
# Prevents Apps from re-installing #
####################################
$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)
####################################
# Prevents Apps from re-installing #
####################################
$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1


#remove vantage associated registry keys
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\E046963F.LenovoCompanion_k1h2ywk1493x8' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\ImController' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Lenovo Vantage' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Commercial Vantage' -Recurse -ErrorAction SilentlyContinue

############################
# Uninstalls Lenovo Vantage
############################
If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) 
    {
        Write-Warning "You are not running as Admin."
        Break
    }

#uninstall apps
& "$PSScriptRoot\uninstall_apps.ps1"

#get lenovo vantage service uninstall string to uninstall service
$lvs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object DisplayName -eq "Lenovo Vantage Service"
If (!([string]::IsNullOrEmpty($lvs.QuietUninstallString)))
{
   $uninstall = "cmd /c " + $lvs.QuietUninstallString
   Write-Host $uninstall
   Invoke-Expression $uninstall
}

$AppList = "E046963F.LenovoCompanion",           
           "LenovoCorporation.LenovoSettings",
           "E046963F.LenovoSettingsforEnterprise"

ForEach ($App in $AppList)
{
   $PackageFullName = (Get-AppxPackage -allusers $App).PackageFullName
   $ProPackageFullName = (Get-AppxProvisionedPackage -online | Where-Object {$_.Displayname -eq $App}).PackageName
  
   ForEach ($AppToRemove in $PackageFullName)
   {
     Write-Host "Removing Package: $AppToRemove"
     try
     {
        remove-AppxPackage -package $AppToRemove -allusers
     }
     catch
     {
        # Starting in Win10 20H1, bundle apps (like Vantage) have to be removed a different way
        $PackageBundleName = (Get-AppxPackage -packagetypefilter bundle -allusers $App).PackageFullName
        ForEach ($BundleAppToRemove in $PackageBundleName)
        {
           remove-AppxPackage -package $BundleAppToRemove -allusers
        }
     }
   }

   ForEach ($AppToRemove in $ProPackageFullName)
   {
     Write-Host "Removing Provisioned Package: $AppToRemove"
     try
     {
        Remove-AppxProvisionedPackage -online -packagename $AppToRemove
     }
     catch
     {
        # bundled/provisioned apps are already removed by "remove-AppxPackage -allusers"
     }
   }

}
#################################
#uninstall ImController service #
#################################
Invoke-Expression -Command 'cmd.exe /c "c:\windows\system32\ImController.InfInstaller.exe" -uninstall'

##########################################
#remove vantage associated registry keys #
##########################################
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\E046963F.LenovoCompanion_k1h2ywk1493x8' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\ImController' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Lenovo Vantage' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Commercial Vantage' -Recurse -ErrorAction SilentlyContinue

####################
# Disable Feedback #
####################
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

###################
# Enable Feedback #
###################
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"

# Ask for elevated permissions if required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

#Built-In apps to be removed from all users (requires elevated powershell)
$AppRemoveList = @()

$AppRemoveList += @("*LinkedInForWindows*")

$AppRemoveList += @("*BingWeather*")

$AppRemoveList += @("*DesktopAppInstaller*")

$AppRemoveList += @("*GetHelp*")

$AppRemoveList += @("*Getstarted*")

$AppRemoveList += @("*Messaging*")

$AppRemoveList += @("*Microsoft3DViewer*")

$AppRemoveList += @("*MicrosoftOfficeHub*")

$AppRemoveList += @("*MicrosoftSolitaireCollection*")

$AppRemoveList += @("*MicrosoftStickyNotes*")

$AppRemoveList += @("*MixedReality.Portal*")

$AppRemoveList += @("*Office.Desktop.Access*")

$AppRemoveList += @("*Office.Desktop.Excel*")

$AppRemoveList += @("*Office.Desktop.Outlook*")

$AppRemoveList += @("*Office.Desktop.Powerpoint*")

$AppRemoveList += @("*Office.Desktop.Publisher*")

$AppRemoveList += @("*Office.Desktop.Word*")

$AppRemoveList += @("*Office.Desktop*")

$AppRemoveList += @("*Office.onenote*")

$AppRemoveList += @("*Office.Sway*")

$AppRemoveList += @("*OneConnect*")

$AppRemoveList += @("*Print3D*")

$AppRemoveList += @("*ScreenSketch*")

$AppRemoveList += @("*Skype*")

$AppRemoveList += @("*Windowscommunicationsapps*")

$AppRemoveList += @("*WindowsFeedbackHub*")

$AppRemoveList += @("*WindowsMaps*")

$AppRemoveList += @("*WindowsAlarms*")

$AppRemoveList += @("*YourPhone*")

$AppRemoveList += @("*Advertising.xaml*")

$AppRemoveList += @("*Advertising.xaml*") #intentionally listed twice

$AppRemoveList += @("*OfficeLens*")

$AppRemoveList += @("*BingNews*")

$AppRemoveList += @("*WindowsMaps*")

$AppRemoveList += @("*NetworkSpeedTest*")

$AppRemoveList += @("*Microsoft3DViewer*")

$AppRemoveList += @("*CommsPhone*")

$AppRemoveList += @("*3DBuilder*")

$AppRemoveList += @("*CBSPreview*")

$AppRemoveList += @("*king.com.CandyCrush*")

$AppRemoveList += @("*nordcurrent*")

$AppRemoveList += @("*Facebook*")

$AppRemoveList += @("*MinecraftUWP*")

$AppRemoveList += @("*Netflix*")

$AppRemoveList += @("*RoyalRevolt2*")

$AppRemoveList += @("*bingsports*")

$AppRemoveList += @("*Lenovo*")

$AppRemoveList += @("*DellCustomerConnect*")

$AppRemoveList += @("*DellDigitalDelivery*")

$AppRemoveList += @("*DellPowerManager*")

$AppRemoveList += @("*MyDell*")

$AppRemoveList += @("*DellMobileConnect*")

$AppRemoveList += @("*DellFreeFallDataProtection*")

$AppRemoveList += @("*DropboxOEM*")

#########################

#*** Begin Processing **#

#########################

##########################
# Removing Built-In Apps #
##########################
write-host "Removing Built-In Cludge...\n"`

ForEach ($x in $AppRemoveList) {

Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $x | Remove-AppxProvisionedPackage -online

Get-AppxPackage -Allusers | Where-Object packagefullname -like $x | Remove-AppxPackage

$appPath="$Env:LOCALAPPDATA\Packages\$Appremovelist*"

Remove-Item $appPath -Recurse -Force -Erroraction SilentlyContinue

}

##########################################
#remove vantage associated registry keys #
##########################################
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\E046963F.LenovoCompanion_k1h2ywk1493x8' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\ImController' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Lenovo Vantage' -Recurse -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Commercial Vantage' -Recurse -ErrorAction SilentlyContinue

##################################################
# Set variables to indicate value and key to set #
##################################################
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc'
$Name         = 'Start'
$Value        = '2'
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) {
  New-Item -Path $RegistryPath -Force | Out-Null
}  
# Now set the value
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType "string" -Force 

#WebClient
$dc = New-Object net.webclient
$dc.UseDefaultCredentials = $true
$dc.Headers.Add("user-agent", "Inter Explorer")
$dc.Headers.Add("X-FORMS_BASED_AUTH_ACCEPTED", "f")

#temp folder
$InstallerFolder = $(Join-Path $env:ProgramData CustomScripts)
if (!(Test-Path $InstallerFolder))
{
New-Item -Path $InstallerFolder -ItemType Directory -Force -Confirm:$false
}
   #######################
	#Check Winget Install #
   #######################
	Write-Host "Checking if Winget is installed" -ForegroundColor Yellow
	$TestWinget = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq "Microsoft.DesktopAppInstaller"}
	If ([Version]$TestWinGet. Version -gt "2022.506.16.0") 
	{
		Write-Host "WinGet is Installed" -ForegroundColor Green
	}Else 
		{
		#Download WinGet MSIXBundle
		Write-Host "Not installed. Downloading WinGet..." 
		$WinGetURL = "https://aka.ms/getwinget"
		$dc.DownloadFile($WinGetURL, "$InstallerFolder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle")
		
		#Install WinGet MSIXBundle 
		Try 	{
			Write-Host "Installing MSIXBundle for App Installer..." 
			Add-AppxProvisionedPackage -Online -PackagePath "$InstallerFolder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -SkipLicense 
			Write-Host "Installed MSIXBundle for App Installer" -ForegroundColor Green
			}
		Catch {
			Write-Host "Failed to install MSIXBundle for App Installer..." -ForegroundColor Red
			} 
	
		#Remove WinGet MSIXBundle 
		#Remove-Item -Path "$InstallerFolder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Force -ErrorAction Continue
		}

$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe"
   if ($ResolveWingetPath){
         $ResolveWingetPath[-1].Path
      }
$wingetexe = $ResolveWingetPath 
  
if (Test-path $wingetexe)
{ Write-host "Found Winget"}

Set-Location "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\"
Import-Module Appx
# Add-AppxPackage https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
# Resets the source location of winget
winget source reset --force
winget source update
winget upgrade --accept-package-agreements --accept-source-agreements --all

#############################################
#Uninstalls MSO 365 en-us & Vantage Service #
#############################################
winget uninstall "Microsoft 365 - en-us"
winget uninstall "Lenovo Vantage Service"

##########################################################################################
#Launches WUAPP & Checks for Updates/Starts the downloads(doesn't automatically restart) #
##########################################################################################
# Start-Process -FilePath 'ms-settings:windowsupdate'
#Get-WindowsUpdate; Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
# Usoclient startinteractivescan; Usoclient startdownload; Usoclient startinstall

######################################################
# Restarts the device in 230 seconds to save changes #
######################################################
shutdown -r -t 30