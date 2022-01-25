########################
# Win10Tool            #
# Version 1.1.5        #
# By Jeff              #
# Use at your own risk #
########################
<#
1.1.1 - 10/10/2021
    Added WiFi Name and Password to Other Menu
1.1.2 - 10/11/2021
    Added Stop 11 to Other Menu, it stops PCs from upgrading to Windows 11
1.1.3 - 12/21/2021
    Added Enable/Disable Multicasting. To Services
1.1.4 - 01/01/2022
    Added Paging File Auto Size & Initial Size 1x RAM, Max 2x. To Other
    Added Enable/Disable IPV6 for Ethernet.  To Services
1.1.5 - 01/22/2022
    Block 60% of Malware by turing on by, Enable Virturual Machine Platform, Enable Hyper Visore platform, Core Isolation and Memrory integrity: Function Block60 added to Other

################################################################################################################################################################################################################
######## Functions to add ???

# Set power to High
& powercfg.exe -x -monitor-timeout-ac 60
& powercfg.exe -x -monitor-timeout-dc 60
& powercfg.exe -x -disk-timeout-ac 0
& powercfg.exe -x -disk-timeout-dc 0
& powercfg.exe -x -standby-timeout-ac 0
& powercfg.exe -x -standby-timeout-dc 0
& powercfg.exe -x -hibernate-timeout-ac 0
& powercfg.exe -x -hibernate-timeout-dc 0
# Disable USB Selective Suspend 
& powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
# Disable hibernation/sleep
Start-Process 'powercfg.exe' -Verb runAs -ArgumentList '/h off'
# Disable Connected Standby (CSEnabled)
Set-ItemProperty -Path "HKLM:\SYSTEM\\CurrentControlSet\Control\Power" -Name "CSEnabled" -Type DWord -Value 0

*************************

# Change Paging File Size
$computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges;
$computersys.AutomaticManagedPagefile = $False;
$computersys.Put();
$pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name like '%pagefile.sys'";
$pagefile.InitialSize = 6144;
$pagefile.MaximumSize = 8192;
$pagefile.Put();

************************

# Windows Auto-Tuning
netsh int tcp set global autotuninglevel=restricted
    # Disabled           No scale factor available Set the TCP receive window at its default value.  Good for small networks
    # Highly Restricted  0x2 (scale factor of 2)   Set the TCP receive window to grow beyond its default value, but do so very conservatively.
    # Restricted         0x4 (scale factor of 4)   Set the TCP receive window to grow beyond its default value, but limit such growth in some scenarios.  Good for large networks
    # Normal (default)   0x8 (scale factor of 8)   Set the TCP receive window to grow to accommodate almost all scenarios.
    # Experimental       0xE (scale factor of 14)  Set the TCP receive window to grow to accommodate extreme scenarios.

************************

cmd.exe /C "netsh int tcp set global chimney=disabled"
cmd.exe /C "netsh int tcp set global rss=disabled"

************************

rem DISABLE UAC

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t  REG_DWORD /d 0 /f

************************

rem FIREWALL SETTINGS

netsh advfirewall set domainprofile state off
netsh advfirewall set privateprofile state off 
netsh advfirewall set publicprofile state on
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

************************

rem POWER SETTINGS

copy "c:\...Bench PC\dentech.pow" c:\dentech.pow
cmd.exe /C "powercfg /import c:\dentech.pow"
cmd.exe /C "powercfg /setactive dentech power"

************************

rem DISABLE WINDOWS CONTROL PRINTERS

REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "LegacyDefaultPrinterMode" /t REG_DWORD /d "1" /f

************************

rem REMOTE DESKTOP SETTINGS

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

************************

rem TASK BAR NEVER COMBINE

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoTaskGrouping /t reg_dword /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoTaskGrouping /t reg_dword /d 1 /f

************************

rem TURN OFF ACTION CENTER

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisablenotificationCenter" /t reg_dword /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t reg_dword /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t reg_dword /d 1 /f

************************

rem ENABLE LINKED CONNECTIONS (FIX)

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLinkedConnections" /t reg_dword /d 1 /f



************************

# Show File Extensions in File Explorer

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

************************

# Stop the Shareing Wizard

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseSharingWizard" -Type DWord -Value 0

#>
################################################################################################################################################################################################################

#This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}
################################################################################################################################################################################################################
# Reg Edit Function
##########
Function Set-Registry
{
    <#
    .SYNOPSIS
    This function gives you the ability to create/change Windows registry keys and values. If you want to create a value but the key doesn't exist, it will create the key for you.
    .PARAMETER RegKey   (Path)  - Path of the registry key to create/change
    .PARAMETER RegValue (Name)  - Name of the registry value to create/change
    .PARAMETER RegData  (Value) - The data of the registry value
    .PARAMETER RegType  (Type)  - The type of the registry value. Allowed types: String,DWord,Binary,ExpandString,MultiString,None,QWord,Unknown. If no type is given, the function will use String as the type.
    .EXAMPLE 
    Set-Registry -RegKey HKLM:\SomeKey -RegValue SomeValue -RegData 1111 -RegType DWord
    This will create the key SomeKey in HKLM:\. There it will create a value SomeValue of the type DWord with the data 1111.
    .NOTES
    Author: Dominik Britz
    Source: https://github.com/DominikBritz
    #>
    [CmdletBinding()]
    PARAM
    (
        $RegKey,
        $RegValue,
        $RegData,
        [ValidateSet('String','DWord','Binary','ExpandString','MultiString','None','QWord','Unknown')]
        $RegType = 'String'    
    )

    If (-not $RegValue)
    {
        If (-not (Test-Path $RegKey))
        {
            $TextBoxOutput.Text += "The key $RegKey does not exist. Try to create it.`r`n"
            Try
            {
                New-Item -Path $RegKey -Force
            }
            Catch
            {
                $TextBoxOutput.Text += "$_`r`n"
            }
            $TextBoxOutput.Text += "Creation of $RegKey was successfull.`r`n"
        }        
    }

    If ($RegValue)
    {
        If (-not (Test-Path $RegKey))
        {
            $TextBoxOutput.Text += "The key $RegKey does not exist. Try to create it.`r`n"
            Try
            {
                New-Item -Path $RegKey -Force
                Set-ItemProperty -Path $RegKey -Name $RegValue -Value $RegData -Type $RegType -Force
            }
            Catch
            {
                $TextBoxOutput.Text += "$_`r`n"
            }
           $TextBoxOutput.Text += "Creation of $RegKey was successfull.`r`n"
        }
        Else 
        {
            $TextBoxOutput.Text += "The key $RegKey already exists. Try to set value.`r`n"
            Try
            {
                Set-ItemProperty -Path $RegKey -Name $RegValue -Value $RegData -Type $RegType -Force
            }
            Catch
            {
                $TextBoxOutput.Text += "$_`r`n"
            }
            $TextBoxOutput.Text += "Creation of $RegValue in $RegKey was successfull.`r`n"           
        }
    }
}

################################################################################################################################################################################################################
# Privacy Settings
##########
 
# Disable Telemetry
Function DisableTelemetry {
    $TextBoxOutput.Text += "Disabling Telemetry...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -RegValue "AllowTelemetry" -RegType DWord -RegData 0
	Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -RegValue "AllowTelemetry" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -RegValue "AllowTelemetry" -RegType DWord -RegData 0
}
 
# Enable Telemetry
Function EnableTelemetry {
    $TextBoxOutput.Text += "Enabling Telemetry...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -RegValue "AllowTelemetry" -RegType DWord -RegData 3
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -RegValue "AllowTelemetry" -RegType DWord -RegData 3
    Set-Registry -RegKey "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -RegValue "AllowTelemetry" -RegType DWord -RegData 3
}
 
# Disable Wi-Fi Sense
Function DisableWiFiSense {
    $TextBoxOutput.Text += "Disabling Wi-Fi Sense...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -RegValue "Value" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -RegValue "Value" -RegType DWord -RegData 0
}
 
# Enable Wi-Fi Sense
Function EnableWiFiSense {
    $TextBoxOutput.Text += "Enabling Wi-Fi Sense...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -RegValue "Value" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -RegValue "Value" -RegType DWord -RegData 1
}
 
# Disable SmartScreen Filter
Function DisableSmartScreen {
    $TextBoxOutput.Text += "Disabling SmartScreen Filter...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -RegValue "SmartScreenEnabled" -RegType String -RegData "Off"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -RegValue "EnableWebContentEvaluation" -RegType DWord -RegData 0
    $edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
    If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Force | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -RegValue "EnabledV9" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -RegValue "PreventOverride" -RegType DWord -RegData 0
}
 
# Enable SmartScreen Filter
Function EnableSmartScreen {
    $TextBoxOutput.Text += "Enabling SmartScreen Filter...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -RegValue "SmartScreenEnabled" -RegType String -RegData "RequireAdmin"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"
    $edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
    Remove-ItemProperty -RegKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -RegValue "EnabledV9"
    Remove-ItemProperty -RegKey "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -RegValue "PreventOverride"
}
 
# Disable Web Search in Start Menu
Function DisableWebSearch {
    $TextBoxOutput.Text += "Disabling Bing Search in Start Menu...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -RegValue "BingSearchEnabled" -RegType DWord -RegData 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -RegValue "DisableWebSearch" -RegType DWord -RegData 1
}
 
# Enable Web Search in Start Menu
Function EnableWebSearch {
    $TextBoxOutput.Text += "Enabling Bing Search in Start Menu...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
}
 
# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
    $TextBoxOutput.Text += "Disabling Application suggestions...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "ContentDeliveryAllowed" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "OemPreInstalledAppsEnabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "PreInstalledAppsEnabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "PreInstalledAppsEverEnabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SilentInstalledAppsEnabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SubscribedContent-338389Enabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SystemPaneSuggestionsEnabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SubscribedContent-338388Enabled" -RegType DWord -RegData 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -RegValue "DisableWindowsConsumerFeatures" -RegType DWord -RegData 1
}
 
# Enable Application suggestions and automatic installation
Function EnableAppSuggestions {
    $TextBoxOutput.Text += "Enabling Application suggestions...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "ContentDeliveryAllowed" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "OemPreInstalledAppsEnabled" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "PreInstalledAppsEnabled" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "PreInstalledAppsEverEnabled" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SilentInstalledAppsEnabled" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SubscribedContent-338389Enabled" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SystemPaneSuggestionsEnabled" -RegType DWord -RegData 1
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
}
 
# Disable Background application access - ie. if apps can download or update even when they aren't used
Function DisableBackgroundApps {
    $TextBoxOutput.Text += "Disabling Background application access...`r`n"
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
}
 
# Enable Background application access
Function EnableBackgroundApps {
    $TextBoxOutput.Text += "Enabling Background application access...`r`n"
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
        Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
    }
}
 
# Disable Lock screen Spotlight - New backgrounds, tips, advertisements etc.
Function DisableLockScreenSpotlight {
    $TextBoxOutput.Text += "Disabling Lock screen spotlight...`r`n"
    Set-Registry -RegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "RotatingLockScreenEnabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "RotatingLockScreenOverlayEnabled" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "SubscribedContent-338387Enabled" -RegType DWord -RegData 0
}
 
# Enable Lock screen Spotlight
Function EnableLockScreenSpotlight {
    $TextBoxOutput.Text += "Disabling Lock screen spotlight...`r`n"
    Set-Registry -RegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "RotatingLockScreenEnabled" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -RegValue "RotatingLockScreenOverlayEnabled" -RegType DWord -RegData 1
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -ErrorAction SilentlyContinue
}
 
# Disable Location Tracking
Function DisableLocationTracking {
    $TextBoxOutput.Text += "Disabling Location Tracking...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -RegValue "SensorPermissionState" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -RegValue "Status" -RegType DWord -RegData 0
}
 
# Enable Location Tracking
Function EnableLocationTracking {
    $TextBoxOutput.Text += "Enabling Location Tracking...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -RegValue "SensorPermissionState" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -RegValue "Status" -RegType DWord -RegData 1
}
 
# Disable automatic Maps updates
Function DisableMapUpdates {
    $TextBoxOutput.Text += "Disabling automatic Maps updates...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\Maps" -RegValue "AutoUpdateEnabled" -RegType DWord -RegData 0
}
 
# Enable automatic Maps updates
Function EnableMapUpdates {
    Write-Host "Enable automatic Maps updates...`r`n"
    Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue
}
 
# Disable Feedback
Function DisableFeedback {
    $TextBoxOutput.Text += "Disabling Feedback...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -RegValue "NumberOfSIUFInPeriod" -RegType DWord -RegData 0
}
 
# Enable Feedback
Function EnableFeedback {
    $TextBoxOutput.Text += "Enabling Feedback...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
}
 
# Disable Advertising ID
Function DisableAdvertisingID {
    $TextBoxOutput.Text += "Disabling Advertising ID...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -RegValue "Enabled" -RegType DWord -RegData 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -RegValue "TailoredExperiencesWithDiagnosticDataEnabled" -RegType DWord -RegData 0
}
 
# Enable Advertising ID
Function EnableAdvertisingID {
    $TextBoxOutput.Text += "Enabling Advertising ID...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -RegValue "TailoredExperiencesWithDiagnosticDataEnabled" -RegType DWord -RegData 2
}
 
# Disable Cortana
Function DisableCortana {
    $TextBoxOutput.Text += "Disabling Cortana...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -RegValue "AcceptedPrivacyPolicy" -RegType DWord -RegData 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -RegValue "RestrictImplicitTextCollection" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -RegValue "RestrictImplicitInkCollection" -RegType DWord -RegData 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -RegValue "HarvestContacts" -RegType DWord -RegData 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -RegValue "AllowCortana" -RegType DWord -RegData 0
}
 
# Enable Cortana
Function EnableCortana {
    $TextBoxOutput.Text += "Enabling Cortana...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -RegValue "RestrictImplicitTextCollection" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -RegValue "RestrictImplicitInkCollection" -RegType DWord -RegData 0
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
}
 
# Disable Error reporting
Function DisableErrorReporting {
    $TextBoxOutput.Text += "Disabling Error reporting...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -RegValue "Disabled" -RegType DWord -RegData 1
}
 
# Enable Error reporting
Function EnableErrorReporting {
    $TextBoxOutput.Text += "Enabling Error reporting...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
}
 
# Restrict Windows Update P2P only to local network
Function SetP2PUpdateLocal {
    $TextBoxOutput.Text += "Restricting Windows Update P2P only to local network...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -RegValue "DODownloadMode" -RegType DWord -RegData 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -RegValue "SystemSettingsDownloadMode" -RegType DWord -RegData 3
}
 
# Unrestrict Windows Update P2P
Function SetP2PUpdateInternet {
    $TextBoxOutput.Text += "Unrestricting Windows Update P2P to internet...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -ErrorAction SilentlyContinue
}
 
# Remove AutoLogger file and restrict directory
Function DisableAutoLogger {
    $TextBoxOutput.Text += "Removing AutoLogger file and restricting directory...`r`n"
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}
 
# Unrestrict AutoLogger directory
Function EnableAutoLogger {
    $TextBoxOutput.Text += "Unrestricting AutoLogger directory...`r`n"
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
}
 
# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
    $TextBoxOutput.Text += "Stopping and disabling Diagnostics Tracking Service...`r`n"
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
}
 
# Enable and start Diagnostics Tracking Service
Function EnableDiagTrack {
    $TextBoxOutput.Text += "Enabling and starting Diagnostics Tracking Service...`r`n"
    Set-Service "DiagTrack" -StartupType Automatic
    Start-Service "DiagTrack" -WarningAction SilentlyContinue
}
 
# Stop and disable WAP Push Service
Function DisableWAPPush {
    $TextBoxOutput.Text += "Stopping and disabling WAP Push Service...`r`n"
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
}
 
# Enable and start WAP Push Service
Function EnableWAPPush {
    $TextBoxOutput.Text += "Enabling and starting WAP Push Service...`r`n"
    Set-Service "dmwappushservice" -StartupType Automatic
    Start-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -RegValue "DelayedAutoStart" -RegType DWord -RegData 1
}

################################################################################################################################################################################################################
# Service Tweaks
##########

# Enable System Restore
Function EnableSystemRestore {
    $TextBoxOutput.Text += "Enabling System Restore...`r`n"
    Enable-ComputerRestore -Drive "C:\"
    # Set the Restere Storage Size
    vssadmin resize shadowstorage /On=%SystemDrive% /For=%SystemDrive% /Maxsize=20GB
}

# Enable Auto Maintenance
Function EnableAutoMaintenance {
    $TextBoxOutput.Text += "Enabling Auto Maintenance...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\" -RegValue "Maintenance" -RegType DWord -RegData 0
}
 
# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
    $TextBoxOutput.Text += "Lowering UAC level...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -RegValue "ConsentPromptBehaviorAdmin" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -RegValue "PromptOnSecureDesktop" -RegType DWord -RegData 0
}
 
# Raise UAC level
Function SetUACHigh {
    $TextBoxOutput.Text += "Raising UAC level...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -RegValue "ConsentPromptBehaviorAdmin" -RegType DWord -RegData 5
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -RegValue "PromptOnSecureDesktop" -RegType DWord -RegData 1
}
 
# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
    $TextBoxOutput.Text += "Enabling sharing mapped drives between users...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -RegValue "EnableLinkedConnections" -RegType DWord -RegData 1
}
 
# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
    $TextBoxOutput.Text += "Disabling sharing mapped drives between users...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}
 
# Disable implicit administrative shares
Function DisableAdminShares {
    $TextBoxOutput.Text += "Disabling implicit administrative shares...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -RegValue "AutoShareWks" -RegType DWord -RegData 0
}
 
# Enable implicit administrative shares
Function EnableAdminShares {
    $TextBoxOutput.Text += "Enabling implicit administrative shares...`r`n"
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}
 
# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
    $TextBoxOutput.Text += "Disabling SMB 1.0 protocol...`r`n"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}
 
# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
    $TextBoxOutput.Text += "Enabling SMB 1.0 protocol...`r`n"
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}
 
# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
    $TextBoxOutput.Text += "Setting current network profile to private...`r`n"
    Set-NetConnectionProfile -NetworkCategory Private
}
 
# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
    $TextBoxOutput.Text += "Setting current network profile to public...`r`n"
    Set-NetConnectionProfile -NetworkCategory Public
}
 
# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
    $TextBoxOutput.Text += "Setting unknown networks profile to private...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -RegValue "Category" -RegType DWord -RegData 1
}
 
# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
    $TextBoxOutput.Text += "Setting unknown networks profile to public...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}
 
# Enable Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function EnableCtrldFolderAccess {
    $TextBoxOutput.Text += "Enabling Controlled Folder Access...`r`n"
    Set-MpPreference -EnableControlledFolderAccess Enabled
}
 
# Disable Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function DisableCtrldFolderAccess {
    $TextBoxOutput.Text += "Disabling Controlled Folder Access...`r`n"
    Set-MpPreference -EnableControlledFolderAccess Disabled
}
 
# Disable Firewall
Function DisableFirewall {
    $TextBoxOutput.Text += "Disabling Firewall...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -RegValue "EnableFirewall" -RegType DWord -RegData 0
}
 
# Enable Firewall
Function EnableFirewall {
    $TextBoxOutput.Text += "Enabling Firewall...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
}
 
# Disable Windows Defender
Function DisableDefender {
    $TextBoxOutput.Text += "Disabling Windows Defender...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -RegValue "DisableAntiSpyware" -RegType DWord -RegData 1
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
}
 
# Enable Windows Defender
Function EnableDefender {
    $TextBoxOutput.Text += "Enabling Windows Defender...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -RegValue "SecurityHealth" -RegType ExpandString -RegData "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
}
 
# Disable Windows Defender Cloud
Function DisableDefenderCloud {
    $TextBoxOutput.Text += "Disabling Windows Defender Cloud...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -RegValue "SpynetReporting" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -RegValue "SubmitSamplesConsent" -RegType DWord -RegData 2
}
 
# Enable Windows Defender Cloud
Function EnableDefenderCloud {
    $TextBoxOutput.Text += "Enabling Windows Defender Cloud...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
}
 
# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
    $TextBoxOutput.Text += "Disabling Malicious Software Removal Tool offering...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -RegValue "DontOfferThroughWUAU" -RegType DWord -RegData 1
}
 
# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT {
    $TextBoxOutput.Text += "Enabling Malicious Software Removal Tool offering...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}
 
# Disable offering of drivers through Windows Update
Function DisableUpdateDriver {
    $TextBoxOutput.Text += "Disabling driver offering through Windows Update...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -RegValue "SearchOrderConfig" -RegType DWord -RegData 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -RegValue "ExcludeWUDriversInQualityUpdate" -RegType DWord -RegData 1
}
 
# Enable offering of drivers through Windows Update
Function EnableUpdateDriver {
    $TextBoxOutput.Text += "Enabling driver offering through Windows Update...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -RegValue "SearchOrderConfig" -RegType DWord -RegData 1
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}
 
# Disable Windows Update automatic restart
Function DisableUpdateRestart {
    $TextBoxOutput.Text += "Disabling Windows Update automatic restart...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -RegValue "NoAutoRebootWithLoggedOnUsers" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -RegValue "AUPowerManagement" -RegType DWord -RegData 0
}
 
# Enable Windows Update automatic restart
Function EnableUpdateRestart {
    $TextBoxOutput.Text += "Enabling Windows Update automatic restart...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
}
 
# Stop and disable Home Groups services - Not applicable to Server
Function DisableHomeGroups {
    $TextBoxOutput.Text += "Stopping and disabling Home Groups services...`r`n"
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
}
 
# Enable and start Home Groups services - Not applicable to Server
Function EnableHomeGroups {
    $TextBoxOutput.Text += "Starting and enabling Home Groups services...`r`n"
    Set-Service "HomeGroupListener" -StartupType Manual
    Set-Service "HomeGroupProvider" -StartupType Manual
    Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
}
 
# Disable Shared Experiences - Not applicable to Server
Function DisableSharedExperiences {
    $TextBoxOutput.Text += "Disabling Shared Experiences...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -RegValue "RomeSdkChannelUserAuthzPolicy" -RegType DWord -RegData 0
}
 
# Enable Shared Experiences - Not applicable to Server
Function EnableSharedExperiences {
    $TextBoxOutput.Text += "Enabling Shared Experiences...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -RegValue "RomeSdkChannelUserAuthzPolicy" -RegType DWord -RegData 1
}
 
# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
    $TextBoxOutput.Text += "Disabling Remote Assistance...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -RegValue "fAllowToGetHelp" -RegType DWord -RegData 0
}
 
# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
    $TextBoxOutput.Text += "Enabling Remote Assistance...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -RegValue "fAllowToGetHelp" -RegType DWord -RegData 1
}
 
# Enable Remote Desktop w/o Network Level Authentication
Function EnableRemoteDesktop {
    $TextBoxOutput.Text += "Enabling Remote Desktop w/o Network Level Authentication...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -RegValue "fDenyTSConnections" -RegType DWord -RegData 0
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -RegValue "UserAuthentication" -RegType DWord -RegData 0
}
 
# Disable Remote Desktop
Function DisableRemoteDesktop {
    $TextBoxOutput.Text += "Disabling Remote Desktop...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -RegValue "fDenyTSConnections" -RegType DWord -RegData 1
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -RegValue "UserAuthentication" -RegType DWord -RegData 1
}
 
# Disable Autoplay
Function DisableAutoplay {
    $TextBoxOutput.Text += "Disabling Autoplay...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -RegValue "DisableAutoplay" -RegType DWord -RegData 1
}
 
# Enable Autoplay
Function EnableAutoplay {
    $TextBoxOutput.Text += "Enabling Autoplay...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -RegValue "DisableAutoplay" -RegType DWord -RegData 0
}
 
# Disable Autorun for all drives
Function DisableAutorun {
    $TextBoxOutput.Text += "Disabling Autorun for all drives...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -RegValue "NoDriveTypeAutoRun" -RegType DWord -RegData 255
}
 
# Enable Autorun for removable drives
Function EnableAutorun {
    $TextBoxOutput.Text += "Enabling Autorun for all drives...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}
 
# Enable Storage Sense - automatic disk cleanup - Not applicable to Server
Function EnableStorageSense {
    $TextBoxOutput.Text += "Enabling Storage Sense...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -RegValue "01" -RegType DWord -RegData 1
}
 
# Disable Storage Sense - Not applicable to Server
Function DisableStorageSense {
    $TextBoxOutput.Text += "Disabling Storage Sense...`r`n"
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -RegValue "01" -RegType DWord -RegData 0
}
 
# Disable scheduled defragmentation task
Function DisableDefragmentation {
    $TextBoxOutput.Text += "Disabling scheduled defragmentation...`r`n"
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
 
# Enable scheduled defragmentation task
Function EnableDefragmentation {
    $TextBoxOutput.Text += "Enabling scheduled defragmentation...`r`n"
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
 
# Stop and disable Superfetch service - Not applicable to Server
Function DisableSuperfetch {
    $TextBoxOutput.Text += "Stopping and disabling Superfetch service...`r`n"
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
}
 
# Start and enable Superfetch service - Not applicable to Server
Function EnableSuperfetch {
    $TextBoxOutput.Text += "Starting and enabling Superfetch service...`r`n"
    Set-Service "SysMain" -StartupType Automatic
    Start-Service "SysMain" -WarningAction SilentlyContinue
}
 
# Stop and disable Windows Search indexing service
Function DisableIndexing {
    $TextBoxOutput.Text += "Stopping and disabling Windows Search indexing service...`r`n"
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
}
 
# Start and enable Windows Search indexing service
Function EnableIndexing {
    $TextBoxOutput.Text += "Starting and enabling Windows Search indexing service...`r`n"
    Set-Service "WSearch" -StartupType Automatic
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -RegValue "DelayedAutoStart" -RegType DWord -RegData 1
    Start-Service "WSearch" -WarningAction SilentlyContinue
}
 
# Set BIOS time to UTC
Function SetBIOSTimeUTC {
    $TextBoxOutput.Text += "Setting BIOS time to UTC...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -RegValue "RealTimeIsUniversal" -RegType DWord -RegData 1
}
 
# Set BIOS time to local time
Function SetBIOSTimeLocal {
    $TextBoxOutput.Text += "Setting BIOS time to Local time...`r`n"
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
}
 
# Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
Function EnableHibernation {
    $TextBoxOutput.Text += "Enabling Hibernation...`r`n"
    Set-Registry -RegKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -RegValue "HibernteEnabled" -RegType Dword -RegData 1
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -RegValue "ShowHibernateOption" -RegType Dword -RegData 1
}
 
# Disable Hibernation
Function DisableHibernation {
    $TextBoxOutput.Text += "Disabling Hibernation...`r`n"
    Set-Registry -RegKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -RegValue "HibernteEnabled" -RegType Dword -RegData 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -RegValue "ShowHibernateOption" -RegType Dword -RegData 0
}
 
# Disable Fast Startup
Function DisableFastStartup {
    $TextBoxOutput.Text += "Disabling Fast Startup...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -RegValue "HiberbootEnabled" -RegType DWord --RegData 0
}
 
# Enable Fast Startup
Function EnableFastStartup {
    $TextBoxOutput.Text += "Enabling Fast Startup...`r`n"
    Set-Registry -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -RegValue "HiberbootEnabled" -RegType DWord --RegData 1
}

# Disable Multicasting
Function DisableMulticasting{
    $TextBoxOutput.Text += "Disabling Multicasting...`r`n"
    Set-Registry -RegKey "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -RegValue "EnableMulticast" -RegType DWord --RegData 0
}

# Enable Multicasting
Function EnableMulticasting{
    $TextBoxOutput.Text += "Enabling Multicasting...`r`n"
    Set-Registry -RegKey "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -RegValue "EnableMulticast" -RegType DWord --RegData 1
}

# Enable IP V6 on Ethernet 
Function EnableIPV6{
    $TextBoxOutput.Text += "Enabling TCPIP V6...`r`n"
    Enable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6
}

# Disabel IP V6 on Ethernet
Function DisableIPV6{
    $TextBoxOutput.Text += "Disabling TCPIP V6...`r`n"
    Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6
}

################################################################################################################################################################################################################
# UI Tweaks
##########


# Disable Action Center
Function DisableActionCenter {
    $TextBoxOutput.Text += "Disabling Action Center...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-Registry -RegKey "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -RegValue "DisableNotificationCenter" -RegType DWord --RegData 1
    Set-Registry -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -RegValue "ToastEnabled" -RegType DWord --RegData 0
}
 
# Enable Action Center
Function EnableActionCenter {
    $TextBoxOutput.Text += "Enabling Action Center...`r`n"
    Remove-ItemProperty -RegKey "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -RegValue "DisableNotificationCenter" -ErrorAction SilentlyContinue
    Remove-ItemProperty -RegKey "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -RegValue "ToastEnabled" -ErrorAction SilentlyContinue
}
 
# Disable Lock screen
Function DisableLockScreen {
    $TextBoxOutput.Text += "Disabling Lock screen...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
    }
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -RegValue "NoLockScreen" -RegType DWord --RegData 1
}
 
# Enable Lock screen
Function EnableLockScreen {
    $TextBoxOutput.Text += "Enabling Lock screen...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}
 
# Disable Lock screen (Anniversary Update workaround) - Applicable to 1607 or newer
Function DisableLockScreenRS1 {
    $TextBoxOutput.Text += "Disabling Lock screen using scheduler workaround...`r`n"
    $service = New-Object -com Schedule.Service
    $service.Connect()
    $task = $service.NewTask(0)
    $task.Settings.DisallowStartIfOnBatteries = $false
    $trigger = $task.Triggers.Create(9)
    $trigger = $task.Triggers.Create(11)
    $trigger.StateChange = 8
    $action = $task.Actions.Create(0)
    $action.Path = "reg.exe"
    $action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
    $service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}
 
# Enable Lock screen (Anniversary Update workaround) - Applicable to 1607 or newer
Function EnableLockScreenRS1 {
    $TextBoxOutput.Text += "Enabling Lock screen (removing scheduler workaround)...`r`n"
    Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
}
 
# Hide network options from Lock Screen
Function HideNetworkFromLockScreen {
    $TextBoxOutput.Text += "Hiding network options from Lock Screen...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -RegValue "DontDisplayNetworkSelectionUI" -RegType DWord --RegData 1
}
 
# Show network options on lock screen
Function ShowNetworkOnLockScreen {
    $TextBoxOutput.Text += "Showing network options on Lock Screen...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
}
 
# Hide shutdown options from Lock Screen
Function HideShutdownFromLockScreen {
    $TextBoxOutput.Text += "Hiding shutdown options from Lock Screen...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -RegValue "ShutdownWithoutLogon" -RegType DWord --RegData 0
}
 
# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen {
    $TextBoxOutput.Text += "Showing shutdown options on Lock Screen...`r`n"
    Set-Registry -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -RegValue "ShutdownWithoutLogon" -RegType DWord --RegData 1
}
 
# Disable Sticky keys prompt
Function DisableStickyKeys {
    $TextBoxOutput.Text += "Disabling Sticky keys prompt...`r`n"
    Set-Registry -RegKey "HKCU:\Control Panel\Accessibility\StickyKeys" -RegValue "Flags" -RegType String --RegData "506"
}
 
# Enable Sticky keys prompt
Function EnableStickyKeys {
    $TextBoxOutput.Text += "Enabling Sticky keys prompt...`r`n"
    Set-Registry -RegKey "HKCU:\Control Panel\Accessibility\StickyKeys" -RegValue "Flags" -RegType String --RegData "510"
}
 
# Show Task Manager details
Function ShowTaskManagerDetails {
    $TextBoxOutput.Text += "Showing task manager details...`r`n"
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Force | Out-Null
    }
    $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    If (!($preferences)) {
        $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
        While (!($preferences)) {
            Start-Sleep -m 250
            $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
        }
        Stop-Process $taskmgr
    }
    $preferences.Preferences[28] = 0
    Set-Registry -RegKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -RegValue "Preferences" -RegType Binary --RegData $preferences.Preferences
}
 
# Hide Task Manager details
Function HideTaskManagerDetails {
    $TextBoxOutput.Text += "Hiding task manager details...`r`n"
    $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    If ($preferences) {
        $preferences.Preferences[28] = 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    }
}
 
# Show file operations details
Function ShowFileOperationsDetails {
    $TextBoxOutput.Text += "Showing file operations details...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}
 
# Hide file operations details
Function HideFileOperationsDetails {
    $TextBoxOutput.Text += "Hiding file operations details...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue
}
 
# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm {
    $TextBoxOutput.Text += "Enabling file delete confirmation dialog...`r`n"
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
}
 
# Disable file delete confirmation dialog
Function DisableFileDeleteConfirm {
    $TextBoxOutput.Text += "Disabling file delete confirmation dialog...`r`n"
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
}
 
# Hide Taskbar Search button / box
Function HideTaskbarSearchBox {
    $TextBoxOutput.Text += "Hiding Taskbar Search box / button...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}
 
# Show Taskbar Search button / box
Function ShowTaskbarSearchBox {
    $TextBoxOutput.Text += "Showing Taskbar Search box / button...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue
}
 
# Hide Task View button
Function HideTaskView {
    $TextBoxOutput.Text += "Hiding Task View button...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}
 
# Show Task View button
Function ShowTaskView {
    $TextBoxOutput.Text += "Showing Task View button...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}
 
# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
    $TextBoxOutput.Text += "Showing small icons in taskbar...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}
 
# Show large icons in taskbar
Function ShowLargeTaskbarIcons {
    $TextBoxOutput.Text += "Showing large icons in taskbar...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue
}
 
# Show titles in taskbar
Function ShowTaskbarTitles {
    $TextBoxOutput.Text += "Showing titles in taskbar...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
}
 
# Hide titles in taskbar
Function HideTaskbarTitles {
    $TextBoxOutput.Text += "Hiding titles in taskbar...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
}
 
# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
    $TextBoxOutput.Text += "Hiding People icon...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}
 
# Show Taskbar People icon
Function ShowTaskbarPeopleIcon {
    $TextBoxOutput.Text += "Showing People icon...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue
}
 
# Show all tray icons
Function ShowTrayIcons {
    $TextBoxOutput.Text += "Showing all tray icons...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
}
 
# Hide tray icons as needed
Function HideTrayIcons {
    $TextBoxOutput.Text += "Hiding tray icons...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -ErrorAction SilentlyContinue
}
 
# Show known file extensions
Function ShowKnownExtensions {
    $TextBoxOutput.Text += "Showing known file extensions...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}
 
# Hide known file extensions
Function HideKnownExtensions {
    $TextBoxOutput.Text += "Hiding known file extensions...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
}
 
# Show hidden files
Function ShowHiddenFiles {
    $TextBoxOutput.Text += "Showing hidden files...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}
 
# Hide hidden files
Function HideHiddenFiles {
    $TextBoxOutput.Text += "Hiding hidden files...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}
 
# Hide sync provider notifications
Function HideSyncNotifications {
    $TextBoxOutput.Text += "Hiding sync provider notifications...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}
 
# Show sync provider notifications
Function ShowSyncNotifications {
    $TextBoxOutput.Text += "Showing sync provider notifications...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1
}
 
# Hide recently and frequently used item shortcuts in Explorer
Function HideRecentShortcuts {
    $TextBoxOutput.Text += "Hiding recent shortcuts...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}
 
# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
    $TextBoxOutput.Text += "Showing recent shortcuts...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue
}
 
# Change default Explorer view to This PC
Function SetExplorerThisPC {
    $TextBoxOutput.Text += "Changing default Explorer view to This PC...`r`n"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}
 
# Change default Explorer view to Quick Access
Function SetExplorerQuickAccess {
    $TextBoxOutput.Text += "Changing default Explorer view to Quick Access...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue
}
 
# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
    $TextBoxOutput.Text += "Showing This PC shortcut on desktop...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}
 
# Hide This PC shortcut from desktop
Function HideThisPCFromDesktop {
    $TextBoxOutput.Text += "Hiding This PC shortcut from desktop...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
}
 
# Show User Folder shortcut on desktop
Function ShowUserFolderOnDesktop {
    $TextBoxOutput.Text += "Showing User Folder shortcut on desktop...`r`n"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}
 
# Hide User Folder shortcut from desktop
Function HideUserFolderFromDesktop {
    $TextBoxOutput.Text += "Hiding User Folder shortcut from desktop...`r`n"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
}
 
# Hide Desktop icon from This PC
Function HideDesktopFromThisPC {
    $TextBoxOutput.Text += "Hiding Desktop icon from This PC...`r`n"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Desktop icon in This PC
Function ShowDesktopInThisPC {
    $TextBoxOutput.Text += "Showing Desktop icon in This PC...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" | Out-Null
    }
}
 
# Hide Documents icon from This PC
Function HideDocumentsFromThisPC {
    $TextBoxOutput.Text += "Hiding Documents icon from This PC...`r`n"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Documents icon in This PC
Function ShowDocumentsInThisPC {
    $TextBoxOutput.Text += "Showing Documents icon in This PC...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" | Out-Null
    }
}
 
# Hide Downloads icon from This PC
Function HideDownloadsFromThisPC {
    $TextBoxOutput.Text += "Hiding Downloads icon from This PC...`r`n"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Downloads icon in This PC
Function ShowDownloadsInThisPC {
    $TextBoxOutput.Text += "Showing Downloads icon in This PC...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" | Out-Null
    }
}
 
# Hide Music icon from This PC
Function HideMusicFromThisPC {
    $TextBoxOutput.Text += "Hiding Music icon from This PC...`r`n"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Music icon in This PC
Function ShowMusicInThisPC {
    $TextBoxOutput.Text += "Showing Music icon in This PC...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" | Out-Null
    }
}
 
# Hide Pictures icon from This PC
Function HidePicturesFromThisPC {
    $TextBoxOutput.Text += "Hiding Pictures icon from This PC...`r`n"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Pictures icon in This PC
Function ShowPicturesInThisPC {
    $TextBoxOutput.Text += "Showing Pictures icon in This PC...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" | Out-Null
    }
}
 
# Hide Videos icon from This PC
Function HideVideosFromThisPC {
    $TextBoxOutput.Text += "Hiding Videos icon from This PC...`r`n"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show Videos icon in This PC
Function ShowVideosInThisPC {
    $TextBoxOutput.Text += "Showing Videos icon in This PC...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" | Out-Null
    }
}
 
# Hide 3D Objects icon from This PC
Function Hide3DObjectsFromThisPC {
    $TextBoxOutput.Text += "Hiding 3D Objects icon from This PC...`r`n"
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}
 
# Show 3D Objects icon in This PC
Function Show3DObjectsInThisPC {
    $TextBoxOutput.Text += "Showing 3D Objects icon in This PC...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
    }
}
 
# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
    $TextBoxOutput.Text += "Adjusting visual effects for performance...`r`n"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}
 
# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
    $TextBoxOutput.Text += "Adjusting visual effects for appearance...`r`n"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x9E,0x1E,0x07,0x80,0x12,0x00,0x00,0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
}
 
# Disable thumbnails, show only file extension icons
Function DisableThumbnails {
    $TextBoxOutput.Text += "Disabling thumbnails...`r`n"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
}
 
# Enable thumbnails
Function EnableThumbnails {
    $TextBoxOutput.Text += "Enabling thumbnails...`r`n"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}
 
# Disable creation of Thumbs.db thumbnail cache files
Function DisableThumbsDB {
    $TextBoxOutput.Text += "Disabling creation of Thumbs.db...`r`n"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}
 
# Enable creation of Thumbs.db thumbnail cache files
Function EnableThumbsDB {
    $TextBoxOutput.Text += "Enable creation of Thumbs.db...`r`n"
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue
}
 
# Add secondary en-US keyboard
Function AddENKeyboard {
    $TextBoxOutput.Text += "Adding secondary en-US and ru keyboard...`r`n"
    $langs = Get-WinUserLanguageList
    $langs.Add("en-US")
    $langs.Add("ru")
    Set-WinUserLanguageList $langs -Force
}
 
# Remove secondary en-US keyboard
Function RemoveENKeyboard {
    $TextBoxOutput.Text += "Removing secondary en-US keyboard...`r`n"
    $langs = Get-WinUserLanguageList
    Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force
}
 
# Enable NumLock after startup
Function EnableNumlock {
    $TextBoxOutput.Text += "Enabling NumLock after startup...`r`n"
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
}
 
# Disable NumLock after startup
Function DisableNumlock {
    $TextBoxOutput.Text += "Disabling NumLock after startup...`r`n"
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
    Add-Type -AssemblyName System.Windows.Forms
    If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
}

################################################################################################################################################################################################################
# Application Tweaks
##########
 
# Disable OneDrive
Function DisableOneDrive {
    $TextBoxOutput.Text += "Disabling OneDrive...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}
 
# Enable OneDrive
Function EnableOneDrive {
    $TextBoxOutput.Text += "Enabling OneDrive...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
}
 
# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
    $TextBoxOutput.Text += "Uninstalling OneDrive...`r`n"
    Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
    Start-Sleep -s 3
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -s 3
    Stop-Process -Name explorer -ErrorAction SilentlyContinue
    Start-Sleep -s 3
    Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}
 
# Install OneDrive - Not applicable to Server
Function InstallOneDrive {
    $TextBoxOutput.Text += "Installing OneDrive...`r`n"
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive -NoNewWindow
}
 
# Uninstall default Microsoft applications
Function UninstallMsftBloat {
    $TextBoxOutput.Text += "Uninstalling default Microsoft applications...`r`n"
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
    Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
    Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
}
 
# Install default Microsoft applications
Function InstallMsftBloat {
    $TextBoxOutput.Text += "Installing default Microsoft applications...`r`n"
    Get-AppxPackage -AllUsers "Microsoft.3DBuilder" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingFinance" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingNews" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingSports" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.BingWeather" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Getstarted" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Office.OneNote" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.People" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.SkypeApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Windows.Photos" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsAlarms" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsCamera" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.windowscommunicationsapps" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsMaps" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsPhone" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsSoundRecorder" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.ZuneMusic" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.ZuneVideo" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.AppConnector" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Office.Sway" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Messaging" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.CommsPhone" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftStickyNotes" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.OneConnect" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MinecraftUWP" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.MSPaint" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.RemoteDesktop" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Print3D" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse
 
# Uninstall default third party applications
function UninstallThirdPartyBloat {
    $TextBoxOutput.Text += "Uninstalling default third party applications...`r`n"
    Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
    Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
    Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
    Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
    Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
    Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
    Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
    Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
    Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
    Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
    Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
    Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
    Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
    Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
    Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
    Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
}
 
# Install default third party applications
Function InstallThirdPartyBloat {
    $TextBoxOutput.Text += "Installing default third party applications...`r`n"
    Get-AppxPackage -AllUsers "9E2F88E3.Twitter" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "king.com.CandyCrushSodaSaga" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "4DF9E0F8.Netflix" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Drawboard.DrawboardPDF" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "D52A8D61.FarmVille2CountryEscape" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "flaregamesGmbH.RoyalRevolt2" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "AdobeSystemsIncorporated.AdobePhotoshopExpress" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "ActiproSoftwareLLC.562882FEEB491" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "D5EA27B7.Duolingo-LearnLanguagesforFree" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Facebook.Facebook" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "46928bounde.EclipseManager" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "A278AB0D.MarchofEmpires" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "KeeperSecurityInc.Keeper" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "king.com.BubbleWitch3Saga" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "89006A2E.AutodeskSketchBook" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "CAF9E577.Plex" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "A278AB0D.DisneyMagicKingdoms" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "828B5831.HiddenCityMysteryofShadows" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
 
# Uninstall Windows Store
Function UninstallWindowsStore {
    $TextBoxOutput.Text += "Uninstalling Windows Store...`r`n"
    Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}
 
# Install Windows Store
Function InstallWindowsStore {
    $TextBoxOutput.Text += "Installing Windows Store...`r`n"
    Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
 
# Disable Xbox features
Function DisableXboxFeatures {
    $TextBoxOutput.Text += "Disabling Xbox features...`r`n"
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}
 
# Enable Xbox features
Function EnableXboxFeatures {
    $TextBoxOutput.Text += "Enabling Xbox features...`r`n"
    Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
}
 
# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash {
    $TextBoxOutput.Text += "Disabling built-in Adobe Flash in IE and Edge...`r`n"
    If (!(Test-Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons")) {
        New-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Name "Flags" -Type DWord -Value 1
}
 
# Enable built-in Adobe Flash in IE and Edge
Function EnableAdobeFlash {
    $TextBoxOutput.Text += "Enabling built-in Adobe Flash in IE and Edge...`r`n"
    Remove-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Name "Flags" -ErrorAction SilentlyContinue
}
 
# Uninstall Windows Media Player
Function UninstallMediaPlayer {
    $TextBoxOutput.Text += "Uninstalling Windows Media Player...`r`n"
    Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Windows Media Player
Function InstallMediaPlayer {
    $TextBoxOutput.Text += "Installing Windows Media Player...`r`n"
    Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
    $TextBoxOutput.Text += "Uninstalling Work Folders Client...`r`n"
    Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Work Folders Client - Not applicable to Server
Function InstallWorkFolders {
    $TextBoxOutput.Text += "Installing Work Folders Client...`r`n"
    Enable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Linux Subsystem - Applicable to 1607 or newer, not applicable to Server yet
Function InstallLinuxSubsystem {
    $TextBoxOutput.Text += "Installing Linux Subsystem...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Uninstall Linux Subsystem - Applicable to 1607 or newer, not applicable to Server yet
Function UninstallLinuxSubsystem {
    $TextBoxOutput.Text += "Uninstalling Linux Subsystem...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 0
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
 
# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
    $TextBoxOutput.Text += "Installing Hyper-V...`r`n"
    If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
        Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
    } Else {
        Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
}
 
# Uninstall Hyper-V - Not applicable to Home
Function UninstallHyperV {
    $TextBoxOutput.Text += "Uninstalling Hyper-V...`r`n"
    If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
        Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
    } Else {
        Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
}
 
# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
    $TextBoxOutput.Text += "Setting Photo Viewer association for bmp, gif, jpg, png and tif...`r`n"
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
        New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
        New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
        Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
        Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
    }
}
 
# Unset Photo Viewer association for bmp, gif, jpg, png and tif
Function UnsetPhotoViewerAssociation {
    $TextBoxOutput.Text += "Unsetting Photo Viewer association for bmp, gif, jpg, png and tif...`r`n"
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
    Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
    Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
    Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse -ErrorAction SilentlyContinue
}
 
# Add Photo Viewer to "Open with...`r`n"
Function AddPhotoViewerOpenWith {
    $TextBoxOutput.Text += "Adding Photo Viewer to `"Open with...`""
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
}
 
# Remove Photo Viewer from "Open with...`r`n"
Function RemovePhotoViewerOpenWith {
    $TextBoxOutput.Text += "Removing Photo Viewer from `"Open with...`""
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse -ErrorAction SilentlyContinue
}
 
# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
    $TextBoxOutput.Text += "Disabling search for app in store for unknown extensions...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}
 
# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore {
    $TextBoxOutput.Text += "Enabling search for app in store for unknown extensions...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
}
 
# Disable 'How do you want to open this file?' prompt
Function DisableNewAppPrompt {
    $TextBoxOutput.Text += "Disabling 'How do you want to open this file?' prompt...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}
 
# Enable 'How do you want to open this file?' prompt
Function EnableNewAppPrompt {
    $TextBoxOutput.Text += "Enabling 'How do you want to open this file?' prompt...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
}
 
# Enable F8 boot menu options
Function EnableF8BootMenu {
    $TextBoxOutput.Text += "Enabling F8 boot menu options...`r`n"
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
}
 
# Disable F8 boot menu options
Function DisableF8BootMenu {
    $TextBoxOutput.Text += "Disabling F8 boot menu options...`r`n"
    bcdedit /set `{current`} bootmenupolicy Standard | Out-Null
}
 
# Set Data Execution Prevention (DEP) policy to OptOut
Function SetDEPOptOut {
    $TextBoxOutput.Text += "Setting Data Execution Prevention (DEP) policy to OptOut...`r`n"
    bcdedit /set `{current`} nx OptOut | Out-Null
}
 
# Set Data Execution Prevention (DEP) policy to OptIn
Function SetDEPOptIn {
    $TextBoxOutput.Text += "Setting Data Execution Prevention (DEP) policy to OptIn...`r`n"
    bcdedit /set `{current`} nx OptIn | Out-Null
}

################################################################################################################################################################################################################
# Server specific Tweaks
##########
 
# Hide Server Manager after login
Function HideServerManagerOnLogin {
    $TextBoxOutput.Text += "Hiding Server Manager after login...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -Type DWord -Value 1
}
 
# Hide Server Manager after login
Function ShowServerManagerOnLogin {
    $TextBoxOutput.Text += "Showing Server Manager after login...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -ErrorAction SilentlyContinue
}
 
# Disable Shutdown Event Tracker
Function DisableShutdownTracker {
    $TextBoxOutput.Text += "Disabling Shutdown Event Tracker...`r`n"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0
}
 
# Enable Shutdown Event Tracker
Function EnableShutdownTracker {
    $TextBoxOutput.Text += "Enabling Shutdown Event Tracker...`r`n"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -ErrorAction SilentlyContinue
}
 
# Disable password complexity and maximum age requirements
Function DisablePasswordPolicy {
    $TextBoxOutput.Text += "Disabling password complexity and maximum age requirements...`r`n"
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet
    (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}
 
# Enable password complexity and maximum age requirements
Function EnablePasswordPolicy {
    $TextBoxOutput.Text += "Enabling password complexity and maximum age requirements...`r`n"
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet
    (Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}
 
# Disable Ctrl+Alt+Del requirement before login
Function DisableCtrlAltDelLogin {
    $TextBoxOutput.Text += "Disabling Ctrl+Alt+Del requirement before login...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1
}
 
# Enable Ctrl+Alt+Del requirement before login
Function EnableCtrlAltDelLogin {
    $TextBoxOutput.Text += "Enabling Ctrl+Alt+Del requirement before login...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 0
}
 
# Disable Internet Explorer Enhanced Security Configuration (IE ESC)
Function DisableIEEnhancedSecurity {
    $TextBoxOutput.Text += "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
}
 
# Enable Internet Explorer Enhanced Security Configuration (IE ESC)
Function EnableIEEnhancedSecurity {
    $TextBoxOutput.Text += "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
}

################################################################################################################################################################################################################
# Other Functions
##########

# Enable Auto Maintenance
Function EnalbeAutoMaintenance {
    $TextBoxOutput.Text += "Enabling Auto Maintenance...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\" -Name "Maintenance" -Type DWord -Value 0
}

# Disalbe Auto Maintenance
Function DisableAutoMaintenance {
    $TextBoxOutput.Text += "Disabling Auto Maintenance...`r`n"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\" -Name "Maintenance" -Type DWord -Value 1
}

# Delete Temp Files Cache and Cookies
Function DeleteTempFiles {
    $TextBoxOutput.Text += "Cleaning up Temporary files, Cache and Cookies...`r`n"
    #- Clear-GlobalWindowsCache
    Function Clear-GlobalWindowsCache {
        Remove-CacheFiles 'C:\Windows\Temp' 
        # Remove-CacheFiles "C:\`$Recycle.Bin"
        Remove-CacheFiles "C:\Windows\Prefetch"
        Remove-CacheFiles "C:\Windows\Logs\CBS"
        C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 255
        C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 4351
    }
    #- Clear-UserCacheFiles
    Function Clear-UserCacheFiles {
        Stop-BrowserSessions
        ForEach($localUser in (Get-ChildItem 'C:\users').Name)
        {
            Clear-ChromeCache $localUser
            Clear-FirefoxCacheFiles $localUser
            Clear-WindowsUserCacheFiles $localUser
            Clear-TeamsCacheFiles $localUser
        }
    }
    #- Clear-WindowsUserCacheFiles
    Function Clear-WindowsUserCacheFiles {
        param([string]$user=$env:USERNAME)
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Temp"
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Microsoft\Windows\WER"
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Microsoft\Windows\INetCache"
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Microsoft\Windows\INetCookies"
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Microsoft\Windows\IECompatCache"
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Microsoft\Windows\IECompatUaCache"
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Microsoft\Windows\IEDownloadHistory"
        Remove-CacheFiles "C:\Users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files"    
    }
    #Region HelperFunctions
    #- Stop-BrowserSessions
    Function Stop-BrowserSessions {
       $activeBrowsers = Get-Process Firefox*,Chrome*,Waterfox*,Edge*
       ForEach($browserProcess in $activeBrowsers)
       {
           try 
           {
               $browserProcess.CloseMainWindow() | Out-Null 
           } catch { }
       }
    }
    #- Get-StorageSize
    Function Get-StorageSize {
        Get-WmiObject Win32_LogicalDisk | 
        Where-Object { $_.DriveType -eq "3" } | 
        Select-Object SystemName, 
            @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
            @{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f ( $_.Size / 1gb)}},
            @{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f ( $_.Freespace / 1gb ) } },
            @{ Name = "PercentFree" ; Expression = {"{0:P1}" -f ( $_.FreeSpace / $_.Size ) } } |
        Format-Table -AutoSize | Out-String
    }
    #- Remove-CacheFiles
    Function Remove-CacheFiles {
        param([Parameter(Mandatory=$true)][string]$path)    
        BEGIN 
        {
            $originalVerbosePreference = $VerbosePreference
            $VerbosePreference = 'Continue'  
        }
        PROCESS 
        {
            if((Test-Path $path))
            {
                if([System.IO.Directory]::Exists($path))
                {
                    try 
                    {
                        if($path[-1] -eq '\')
                        {
                            [int]$pathSubString = $path.ToCharArray().Count - 1
                            $sanitizedPath = $path.SubString(0, $pathSubString)
                            Remove-Item -Path "$sanitizedPath\*" -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false
                        }
                        else 
                        {
                            Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false              
                        } 
                    } catch { }
                }
                else 
                {
                    try 
                    {
                        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue -Confirm:$false
                    } catch { }
                }
            }    
        }
        END 
        {
            $VerbosePreference = $originalVerbosePreference
        }
    }
    #Endregion HelperFunctions
    #Region Browsers
    #Region ChromiumBrowsers
    #- Clear-ChromeCache
    Function Clear-ChromeCache {
        param([string]$user=$env:USERNAME)
        if((Test-Path "C:\users\$user\AppData\Local\Google\Chrome\User Data\Default"))
        {
            $chromeAppData = "C:\Users\$user\AppData\Local\Google\Chrome\User Data\Default" 
            $possibleCachePaths = @('Cache','Cache2\entries\','Cookies','History','Top Sites','VisitedLinks','Web Data','Media Cache','Cookies-Journal','ChromeDWriteFontCache')
            ForEach($cachePath in $possibleCachePaths)
            {
                Remove-CacheFiles "$chromeAppData\$cachePath"
            }      
        } 
    }
    #- Clear-EdgeCache
    Function Clear-EdgeCache {
        param([string]$user=$env:USERNAME)
        if((Test-Path "C:\Users$user\AppData\Local\Microsoft\Edge\User Data\Default"))
        {
            $EdgeAppData = "C:\Users$user\AppData\Local\Microsoft\Edge\User Data\Default"
            $possibleCachePaths = @('Cache','Cache2\entries','Cookies','History','Top Sites','Visited Links','Web Data','Media History','Cookies-Journal')
            ForEach($cachePath in $possibleCachePaths)
            {
                Remove-CacheFiles "$EdgeAppData$cachePath"
            }
            }
    }
    #Endregion ChromiumBrowsers
    #Region FirefoxBrowsers
    #- Clear-FirefoxCacheFiles
    Function Clear-FirefoxCacheFiles {
        param([string]$user=$env:USERNAME)
        if((Test-Path "C:\users\$user\AppData\Local\Mozilla\Firefox\Profiles"))
        {
            $possibleCachePaths = @('cache','cache2\entries','thumbnails','cookies.sqlite','webappsstore.sqlite','chromeappstore.sqlite')
            $firefoxAppDataPath = (Get-ChildItem "C:\users\$user\AppData\Local\Mozilla\Firefox\Profiles" | Where-Object { $_.Name -match 'Default' }[0]).FullName 
            ForEach($cachePath in $possibleCachePaths)
            {
                Remove-CacheFiles "$firefoxAppDataPath\$cachePath"
            }
        } 
    }
    #- Clear-WaterfoxCacheFiles
    Function Clear-WaterfoxCacheFiles { 
        param([string]$user=$env:USERNAME)
        if((Test-Path "C:\users\$user\AppData\Local\Waterfox\Profiles"))
        {
            $possibleCachePaths = @('cache','cache2\entries','thumbnails','cookies.sqlite','webappsstore.sqlite','chromeappstore.sqlite')
            $waterfoxAppDataPath = (Get-ChildItem "C:\users\$user\AppData\Local\Waterfox\Profiles" | Where-Object { $_.Name -match 'Default' }[0]).FullName
            ForEach($cachePath in $possibleCachePaths)
            {
                Remove-CacheFiles "$waterfoxAppDataPath\$cachePath"
            }
        }   
    }
    #Endregion FirefoxBrowsers
    #Endregion Browsers
    #Region CommunicationPlatforms
    #- Clear-TeamsCacheFiles
    Function Clear-TeamsCacheFiles { 
        param([string]$user=$env:USERNAME)
        if((Test-Path "C:\users\$user\AppData\Roaming\Microsoft\Teams"))
        {
            $possibleCachePaths = @('cache','blob_storage','databases','gpucache','Indexeddb','Local Storage','application cache\cache')
            $teamsAppDataPath = (Get-ChildItem "C:\users\$user\AppData\Roaming\Microsoft\Teams" | Where-Object { $_.Name -match 'Default' }[0]).FullName
            ForEach($cachePath in $possibleCachePaths)
            {
                Remove-CacheFiles "$teamsAppDataPath\$cachePath"
            }
        }   
    }
    #Endregion CommunicationPlatforms
    #- MAIN
    $StartTime = (Get-Date)
    Get-StorageSize
    Clear-UserCacheFiles
    Clear-GlobalWindowsCache
    Get-StorageSize
    $EndTime = (Get-Date)
    Write-Verbose "Elapsed Time: $(($StartTime - $EndTime).totalseconds) seconds"
}

# Clean WinSXS folder (WARNING: this takes a while!)
Function CleanWinSXS {
    $TextBoxOutput.Text += "Cleaning WinSXS folder, this may take a while, please wait...`r`n"
    Dism.exe /online /Cleanup-Image /StartComponentCleanup
}

# Run Windows Disk Cleanup
Function DiskCleanup {
    $TextBoxOutput.Text += "Running Windows Disk Cleanup, this may take a while, please wait...`r`n"
    cleanmgr.exe /verylowdisk
    cleanmgr.exe /AUTOCLEAN
}

# Set to Eastern time zone
Function SetEasternTime {
	$TextBoxOutput.Text += "Setting to Eastern time zone...`r`n"
    Set-TimeZone "Eastern Standard Time"
}

# Set to Central time zone
Function SetCentralTime {
	$TextBoxOutput.Text += "Setting to Central time zone...`r`n"	
    Set-TimeZone "Central Standard Time"
}

# Set to Mountain time zone
Function SetMountainTime {
	$TextBoxOutput.Text += "Setting to Mountain time zone...`r`n"	
    Set-TimeZone "Mountain Standard Time"
}

# Set to Pacific time zone
Function SetPacificTime {
	$TextBoxOutput.Text += "Setting to Pacific time zone...`r`n"	
    Set-TimeZone "Pacific Standard Time"
}

 # Sync time to Internet 
 Function SyncTimeToInternet {
	$TextBoxOutput.Text += "Syncing Time to the Internet...`r`n"	
	net stop w32time
    w32tm /unregister
    w32tm /register
    net start w32time
    w32tm /resync
}

# SFC Scan Now
Function SFCScanNow {
    $TextBoxOutput.Text += "System File Checker is running (Please Wait)...`r`n"
    SFC /ScanNow
}

# Get WiFi Name and Passwords
Function WiFiNamePassword {
    $TextBoxOutput.Text += (netsh wlan show profiles | Select-String “\:(.+)$” | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=”$name” key=clear)}  | Select-String “Key Content\W+\:(.+)$” | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table –Wrap | out-string)
}

# Stop Windows 11 upgrade
Function Stop11 {
    $TextBoxOutput.Text += "Stopping Windows 11 from installing...`r`n"
    # Set the location to the registry
    Set-Location -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
    # Create a new Key
    Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' | New-Item -Name 'WindowsUpdate' -Force
    # Create new items with values
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name 'TargetReleaseVersion' -PropertyType DWord -Value 1
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name 'TargetReleaseVersionInfo' -PropertyType String -Value "21H1"
    # Get out of the Registry
    Pop-Location
}

# Set Paging File Size to Auto
Function SetPagingAuto {
    $TextBoxOutput.Text += "Seting Paging File to Auto...`r`n"
    $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $pagefile.AutomaticManagedPagefile = $true
    $pagefile.put() | Out-Null
}

# Set Paging File Size, Initial to the same as the physical and Max to double that
Function SetPagingManual {
    $TextBoxOutput.Text += "Seting Paging File to Manual...`r`n"
    # Remove Automatic Page File
    $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $pagefile.AutomaticManagedPagefile = $false
    $pagefile.put() | Out-Null

    # Set the Initial size to the size of the memory 
    $physicalmem = Get-WmiObject Win32_PhysicalMemory
    $pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name='c:\\pagefile.sys'"
    $pagefile.InitialSize = [int]($physicalmem.capacity*1/1024/1024)
    $pagefile.MaximumSize = [int]($physicalmem.capacity*2/1024/1024)
    $pagefile.Put() | Out-Null
}

# Block 60% of Malware by turing on by, Enable Virturual Machine Platform, Enable Hyper Visore platform, Core Isolation and Memrory integrity
Function Block60 {
    $TextBoxOutput.Text += "Blocking 60% of Malware..."

    # Enable Virturual Machine Platform
    DISM /online /enable-feature /featurename:VirtualMachinePlatform /all

    # Enable Hyper Visore platform
    DISM /Online /Enable-Feature /FeatureName:HypervisorPlatform /all

    # Core Isolation and Memrory integrity
    # Set the location to the registry
    Set-Location -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios'
    # Create a new Key
    Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios' | New-Item -Name 'HypervisorEnforcedCodeIntegrity' -Force
    # Create new items with values
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name 'Enabled' -PropertyType DWord -Value 1
    # Get out of the Registry
    Pop-Location
}

#--MENU--######################################################################################################################################################################################################
function FunctionAutoSelectSettings () {
        $CheckBoxAdvancedSectionNiNite.Visible =$false
        $CheckBoxAdvancedSectionServer.Visible =$false
        $CheckBoxAdvancedSectionApp.Visible =$false
        $CheckBoxAdvancedSectionUI.Visible =$false
        $CheckBoxAdvancedSectionServices.Visible =$false
        $CheckBoxAdvancedSectionPrivace.Visible =$false
        $CheckBoxAdvancedSectionOther.Visible =$false
        $CheckBoxClearAll.Visible =$false
        $FormBackupTool.ClientSize       = '680,120'
}
function FunctionAdvancedSelectSettings () {
        $CheckBoxAdvancedSectionNiNite.Visible =$true
        $CheckBoxAdvancedSectionServer.Visible =$true
        $CheckBoxAdvancedSectionApp.Visible =$true
        $CheckBoxAdvancedSectionUI.Visible =$true
        $CheckBoxAdvancedSectionServices.Visible =$true
        $CheckBoxAdvancedSectionPrivace.Visible =$true
        $CheckBoxAdvancedSectionOther.Visible =$true
        $CheckBoxClearAll.Visible =$true
        $FormBackupTool.ClientSize       = '680,820'
        $CheckBoxAdvancedSectionPrivace.Checked =$true
        FunctionAdvancedSectionPrivace
}

function FunctionAutoSelect () {
    If ($CheckBoxAutoSelect.Checked -eq $true) {
        $CheckBoxAdvancedSelect.Checked      =$false
        FunctionAutoSelectSettings
    }
    If ($CheckBoxAutoSelect.Checked -eq $false) {
        $CheckBoxAdvancedSelect.Checked      =$true
        FunctionAdvancedSelectSettings
    }
}
function FunctionAdvancedSelect () {
    If ($CheckBoxAdvancedSelect.Checked -eq $true) {
        $CheckBoxAutoSelect.Checked      =$false
        FunctionAdvancedSelectSettings
    }
    If ($CheckBoxAdvancedSelect.Checked -eq $false) {
        $CheckBoxAutoSelect.Checked      =$true
        FunctionAutoSelectSettings
       }
}
#---------------------------------------------------------
function FuctionQuickClean () {
    If ($CheckBoxQuickClean.Checked -eq $true) {
        $CheckBoxDeepClean.Checked      =$false
        $CheckBoxNewComputer.Checked    =$false
        $CheckBoxServer.Checked         =$false
        $CheckBoxClearAll.Checked       =$false
        # Privacy
        $CheckBoxDisableTelemetry.checked 			= $false
        $CheckBoxEnableTelemetry.checked 			= $false
    	$CheckBoxDisableWiFiSense.checked 			= $false
	    $CheckBoxEnableWiFiSense.checked 			= $false
	    $CheckBoxDisableSmartScreen.checked 		= $false
	    $CheckBoxEnableSmartScreen.checked 			= $false
	    $CheckBoxDisableWebSearch.checked 			= $false
	    $CheckBoxEnableWebSearch.checked 			= $false
	    $CheckBoxDisableAppSuggestions.checked 		= $false
	    $CheckBoxEnableAppSuggestions.checked 		= $false
	    $CheckBoxDisableBackgroundApps.checked 		= $false
	    $CheckBoxEnableBackgroundApps.checked 		= $false
	    $CheckBoxDisableLockScreenSpotlight.checked = $false
	    $CheckBoxEnableLockScreenSpotlight.checked 	= $false
	    $CheckBoxDisableLocationTracking.checked 	= $false
	    $CheckBoxEnableLocationTracking.checked 	= $false
	    $CheckBoxDisableMapUpdates.checked 			= $false
	    $CheckBoxEnableMapUpdates.checked 			= $false
	    $CheckBoxDisableFeedback.checked 			= $false
	    $CheckBoxEnableFeedback.checked 			= $false
	    $CheckBoxDisableAdvertisingID.checked 		= $false
	    $CheckBoxEnableAdvertisingID.checked 		= $false
	    $CheckBoxDisableCortana.checked 			= $false
	    $CheckBoxEnableCortana.checked 				= $false
	    $CheckBoxDisableErrorReporting.checked 		= $false
	    $CheckBoxEnableErrorReporting.checked 		= $false
	    $CheckBoxDisableAutoLogger.checked 			= $false
	    $CheckBoxEnableAutoLogger.checked 			= $false
	    $CheckBoxDisableDiagTrack.checked 			= $false
	    $CheckBoxEnableDiagTrack.checked 			= $false
	    $CheckBoxDisableWAPPush.checked 			= $false
	    $CheckBoxEnableWAPPush.checked 				= $false
	    $CheckBoxP2PUpdateLocal.checked 			= $false
	    $CheckBoxP2PUpdateInternet.checked 			= $false
	    # Services
	    $CheckBoxSetUACLow.checked 					= $false
	    $CheckBoxSetUACHigh.checked 				= $false
	    $CheckBoxEnableSharingMappedDrives.checked 	= $false
	    $CheckBoxDisableSharingMappedDrives.checked = $false
	    $CheckBoxDisableAdminShares.checked 		= $false
	    $CheckBoxEnableAdminShares.checked 			= $false
	    $CheckBoxDisableSMB1.checked 				= $false
	    $CheckBoxEnableSMB1.checked 				= $false
	    $CheckBoxCurrentNetworkPrivate.checked 		= $false
	    $CheckBoxCurrentNetworkPublic.checked 		= $false
	    $CheckBoxUnknownNetworksPrivate.checked 	= $false
	    $CheckBoxUnknownNetworksPublic.checked 		= $false
	    $CheckBoxEnableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableFirewall.checked 			= $false
	    $CheckBoxEnableFirewall.checked 			= $false
	    $CheckBoxDisableDefender.checked 			= $false
	    $CheckBoxEnableDefender.checked 			= $false
	    $CheckBoxDisableDefenderCloud.checked 		= $false
	    $CheckBoxEnableDefenderCloud.checked 		= $false
	    $CheckBoxDisableUpdateMSRT.checked 			= $false
	    $CheckBoxEnableUpdateMSRT.checked 			= $false
	    $CheckBoxDisableUpdateDriver.checked 		= $false
	    $CheckBoxEnableUpdateDriver.checked 		= $false
	    $CheckBoxDisableUpdateRestart.checked 		= $false
	    $CheckBoxEnableUpdateRestart.checked 		= $false
	    $CheckBoxDisableHomeGroups.checked 			= $false
	    $CheckBoxEnableHomeGroups.checked 			= $false
	    $CheckBoxDisableSharedExperiences.checked 	= $false
	    $CheckBoxEnableSharedExperiences.checked 	= $false
	    $CheckBoxDisableRemoteAssistance.checked 	= $false
	    $CheckBoxEnableRemoteAssistance.checked 	= $false
	    $CheckBoxDisableRemoteDesktop.checked 		= $false
	    $CheckBoxEnableRemoteDesktop.checked 		= $false
	    $CheckBoxDisableAutoplay.checked 			= $false
	    $CheckBoxEnableAutoplay.checked 			= $false
	    $CheckBoxDisableAutorun.checked 			= $false
	    $CheckBoxEnableAutorun.checked 				= $false
	    $CheckBoxDisableStorageSense.checked 		= $false
	    $CheckBoxEnableStorageSense.checked 		= $true
	    $CheckBoxDisableDefragmentation.checked 	= $false
	    $CheckBoxEnableDefragmentation.checked 		= $false
	    $CheckBoxDisableSuperfetch.checked 			= $false
	    $CheckBoxEnableSuperfetch.checked 			= $false
	    $CheckBoxDisableIndexing.checked 			= $false
	    $CheckBoxEnableIndexing.checked 			= $false
	    $CheckBoxSetBIOSTimeUTC.checked 			= $false
	    $CheckBoxSetBIOSTimeLocal.checked 			= $false
	    $CheckBoxDisableHibernation.checked 		= $false
	    $CheckBoxEnableHibernation.checked 			= $false
	    $CheckBoxDisableFastStartup.checked 		= $false
	    $CheckBoxEnableFastStartup.checked 			= $false
        $CheckBoxDisableMulticasting.Checked        = $false
        $CheckBoxEnableMulticasting.Checked         = $false
        $CheckBoxEnableIPV6.Checked                 = $false
        $CheckBoxDisableIPV6.Checked                = $false
	    # UI
	    $CheckBoxDisableActionCenter.checked 		= $false
	    $CheckBoxEnableActionCenter.checked 		= $false
	    $CheckBoxDisableLockScreen.checked 			= $false
	    $CheckBoxEnableLockScreen.checked 			= $false
	    $CheckBoxHideNetworkOnLockScreen.checked 	= $false
	    $CheckBoxShowNetworkOnLockScreen.checked 	= $false
	    $CheckBoxHideShutdownFromLockScreen.checked = $false
	    $CheckBoxShowShutdownOnLockScreen.checked 	= $false
	    $CheckBoxDisableStickyKeys.checked 			= $false
	    $CheckBoxEnableStickyKeys.checked 			= $false
	    $CheckBoxShowTaskManagerDetails.checked 	= $false
	    $CheckBoxHideTaskManagerDetails.checked 	= $false
	    $CheckBoxShowFileOperationsDetails.checked 	= $false
	    $CheckBoxHideFileOperationsDetails.checked 	= $false
	    $CheckBoxDisableFileDeleteConfirm.checked 	= $false
	    $CheckBoxEnableFileDeleteConfirm.checked 	= $false
	    $CheckBoxShowTaskbarSearchBox.checked 		= $false
	    $CheckBoxHideTaskbarSearchBox.checked 		= $false
	    $CheckBoxShowTaskView.checked 				= $false
	    $CheckBoxHideTaskView.checked 				= $false
    	$CheckBoxSmallTaskbarIcons.checked 			= $false
	    $CheckBoxLargeTaskbarIcons.checked 			= $false
	    $CheckBoxShowTaskbarTitles.checked 			= $false
	    $CheckBoxHideTaskbarTitles.checked 			= $false
	    $CheckBoxShowTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxHideTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxShowTrayIcons.checked 				= $false
	    $CheckBoxHideTrayIcons.checked 				= $false
	    $CheckBoxShowKnownExtensions.checked 		= $false
	    $CheckBoxHideKnownExtensions.checked 		= $false
	    $CheckBoxShowHiddenFiles.checked 			= $false
	    $CheckBoxHideHiddenFiles.checked 			= $false
	    $CheckBoxShowSyncNotifications.checked 		= $false
	    $CheckBoxHideSyncNotifications.checked 		= $false
	    $CheckBoxShowRecentShortcuts.checked 		= $false
	    $CheckBoxHideRecentShortcuts.checked 		= $false
	    $CheckBoxSetExplorerQuickAccess.checked 	= $false
	    $CheckBoxSetExplorerThisPC.checked 			= $false
	    $CheckBoxShowThisPCOnDesktop.checked 		= $false
	    $CheckBoxHideThisPCFromDesktop.checked 		= $false
	    $CheckBoxShowUserFolderOnDesktop.checked 	= $false
	    $CheckBoxHideUserFolderFromDesktop.checked	= $false
	    $CheckBoxShowDesktopInThisPC.checked 		= $false
	    $CheckBoxHideDesktopFromThisPC.checked 		= $false
	    $CheckBoxShowDocumentsInThisPC.checked 		= $false
	    $CheckBoxHideDocumentsFromThisPC.checked 	= $false
	    $CheckBoxShowDownloadsInThisPC.checked 		= $false
	    $CheckBoxHideDownloadsFromThisPC.checked 	= $false
	    $CheckBoxShowMusicInThisPC.checked 			= $false
	    $CheckBoxHideMusicFromThisPC.checked 		= $false
	    $CheckBoxShowPicturesInThisPC.checked 		= $false
	    $CheckBoxHidePicturesFromThisPC.checked 	= $false
	    $CheckBoxShowVideosInThisPC.checked 		= $false
	    $CheckBoxHideVideosFromThisPC.checked 		= $false
	    $CheckBoxShow3DObjectsInThisPC.checked 		= $false
    	$CheckBoxHide3DObjectsFromThisPC.checked 	= $false
    	$CheckBoxSetVisualFXPerformance.checked 	= $false
    	$CheckBoxSetVisualFXAppearance.checked 		= $false
    	$CheckBoxEnableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbsDB.checked 			= $false
	    $CheckBoxEnableThumbsDB.checked 			= $false
    	$CheckBoxAddENKeyboard.checked 				= $false
	    $CheckBoxRemoveENKeyboard.checked 			= $false
	    $CheckBoxDisableNumlock.checked 			= $false
	    $CheckBoxEnableNumlock.checked 				= $false
	    # Application
	    $CheckBoxDisableOneDrive.checked 			= $false
	    $CheckBoxEnableOneDrive.checked 			= $false
	    $CheckBoxUninstallOneDrive.checked 			= $false
	    $CheckBoxInstallOneDrive.checked 			= $false
	    $CheckBoxUninstallMsftBloat.checked 		= $false
	    $CheckBoxInstallMsftBloat.checked 			= $false
	    $CheckBoxUninstallThirdPartyBloat.checked 	= $false
	    $CheckBoxInstallThirdPartyBloat.checked 	= $false
	    $CheckBoxUninstallWindowsStore.checked 		= $false
	    $CheckBoxInstallWindowsStore.checked 		= $false
	    $CheckBoxDisableXboxFeatures.checked 		= $false
	    $CheckBoxEnableXboxFeatures.checked 		= $false
	    $CheckBoxDisableAdobeFlash.checked 			= $false
	    $CheckBoxEnableAdobeFlash.checked 			= $false
	    $CheckBoxUninstallMediaPlayer.checked 		= $false
	    $CheckBoxInstallMediaPlayer.checked 		= $false
	    $CheckBoxUninstallWorkFolders.checked 		= $false
	    $CheckBoxInstallWorkFolders.checked 		= $false
	    $CheckBoxUninstallLinuxSubsystem.checked	= $false
	    $CheckBoxInstallLinuxSubsystem.checked 		= $false
	    $CheckBoxUninstallHyperV.checked 			= $false
	    $CheckBoxInstallHyperV.checked 				= $false
	    $CheckBoxSetPhotoViewerAssociation.checked 	= $false
	    $CheckBoxUnsetPhotoViewerAssociation.checked	= $false
	    $CheckBoxAddPhotoViewerOpenWith.checked 	= $false
	    $CheckBoxRemovePhotoViewerOpenWith.checked 	= $false
	    $CheckBoxDisableSearchAppInStore.checked 	= $false
	    $CheckBoxEnableSearchAppInStore.checked 	= $false
	    $CheckBoxDisableNewAppPrompt.checked 		= $false
	    $CheckBoxEnableNewAppPrompt.checked 		= $false
	    $CheckBoxDisableF8BootMenu.checked 			= $false
	    $CheckBoxEnableF8BootMenu.checked 			= $false
	    $CheckBoxSetDEPOptIn.checked 				= $false
	    $CheckBoxSetDEPOptOut.checked 				= $false
	    # Server
	    $CheckBoxHideServerManagerOnLogin.checked 	= $false
	    $CheckBoxShowServerManagerOnLogin.checked 	= $false
	    $CheckBoxDisableShutdownTracker.checked 	= $false
	    $CheckBoxEnableShutdownTracker.checked 		= $false
	    $CheckBoxDisablePasswordPolicy.checked 		= $false
	    $CheckBoxEnablePasswordPolicy.checked 		= $false
	    $CheckBoxDisableCtrlAltDelLogin.checked 	= $false
	    $CheckBoxEnableCtrlAltDelLogin.checked 		= $false
	    $CheckBoxDisableIEEnhancedSecurity.checked 	= $false
	    $CheckBoxEnableIEEnhancedSecurity.checked 	= $false
	    # Other
        $CheckBoxDisableAutoMaintenance.checked     = $false
        $CheckBoxEnableAutoMaintenance.checked      = $false
        $CheckBoxDeleteTempFiles.checked            = $true
        $CheckBoxCleanWinSXS.checked                = $false
        $CheckBoxDiskCleanup.checked                = $false
        $CheckBoxSetEasternTime.checked             = $flase
        $CheckBoxSetCentralTime.checked             = $flase
        $CheckBoxSetMountainTime.checked            = $flase
        $CheckBoxSetPacificTime.checked             = $flase
        $CheckBoxSyncTimeToInternet.checked         = $flase
        $CheckBoxWiFiNamePassword.checked           = $flase
        $CheckBoxStop11.checked                     = $false
        $CheckBoxSetPagingAuto.checked              = $false
        $CheckBoxSetPagingManual.checked            = $false
        $CheckBoxBlock60.checked                    = $false
	    # NiNite
        $CheckBoxFoxitReader.checked                = $flase
        $CheckBoxSumatraPDF.checked                 = $flase
        $CheckBoxCutePDF.checked                    = $flase
        $CheckBoxLebreOffice.checked                = $flase
        $CheckBoxOpenOffice.checked                 = $flase
        $CheckBoxFireFox.checked                    = $flase
        $CheckBoxChrome.checked                     = $flase
        $CheckBoxOpera.checked                      = $flase
        $CheckBoxSFCScanNow.checked                 = $false
        $CheckBoxFileZilla.checked                  = $flase
        $CheckBoxNotepad.checked                    = $flase
        $CheckBox7Zip.checked                       = $flase
        $CheckBoxPuTTY.checked                      = $flase
        $CheckBoxVisualStudioCode.checked           = $flase
        $CheckBoxWinRAR.checked                     = $flase
        $CheckBoxTeamViewer.checked                 = $flase
        $CheckBoxImgBurn.checked                    = $flase
        $CheckBoxWinDirStat.checked                 = $flase
        $CheckBoxVLC.checked                        = $flase
        $CheckBoxAudacity.checked                   = $flase
        $CheckBoxSpotify.checked                    = $flase
        $CheckBoxZoom.checked                       = $flase
        $CheckBoxDiscord.checked                    = $flase
        $CheckBoxSkype.checked                      = $flase
        $CheckBoxMailwarebytes.checked              = $flase
        $CheckBoxAvast.checked                      = $flase
        $CheckBoxKeePass.checked                    = $flase
    }
}
function FunctionDeepClean () {
    If ($CheckBoxDeepClean.Checked -eq $true) {
        $CheckBoxQuickClean.Checked     =$false
        $CheckBoxNewComputer.Checked    =$false
        $CheckBoxClearAll.Checked       =$false
        $CheckBoxServer.Checked         =$false
        # Privacy
        $CheckBoxDisableTelemetry.checked 			= $true
        $CheckBoxEnableTelemetry.checked 			= $false
    	$CheckBoxDisableWiFiSense.checked 			= $true
	    $CheckBoxEnableWiFiSense.checked 			= $false
	    $CheckBoxDisableSmartScreen.checked 		= $true
	    $CheckBoxEnableSmartScreen.checked 			= $false
	    $CheckBoxDisableWebSearch.checked 			= $true
	    $CheckBoxEnableWebSearch.checked 			= $false
	    $CheckBoxDisableAppSuggestions.checked 		= $true
	    $CheckBoxEnableAppSuggestions.checked 		= $false
	    $CheckBoxDisableBackgroundApps.checked 		= $true
	    $CheckBoxEnableBackgroundApps.checked 		= $false
	    $CheckBoxDisableLockScreenSpotlight.checked = $true
	    $CheckBoxEnableLockScreenSpotlight.checked 	= $false
	    $CheckBoxDisableLocationTracking.checked 	= $true
	    $CheckBoxEnableLocationTracking.checked 	= $false
	    $CheckBoxDisableMapUpdates.checked 			= $true
	    $CheckBoxEnableMapUpdates.checked 			= $false
	    $CheckBoxDisableFeedback.checked 			= $true
	    $CheckBoxEnableFeedback.checked 			= $false
	    $CheckBoxDisableAdvertisingID.checked 		= $true
	    $CheckBoxEnableAdvertisingID.checked 		= $false
	    $CheckBoxDisableCortana.checked 			= $true
	    $CheckBoxEnableCortana.checked 				= $false
	    $CheckBoxDisableErrorReporting.checked 		= $true
	    $CheckBoxEnableErrorReporting.checked 		= $false
	    $CheckBoxDisableAutoLogger.checked 			= $true
	    $CheckBoxEnableAutoLogger.checked 			= $false
	    $CheckBoxDisableDiagTrack.checked 			= $true
	    $CheckBoxEnableDiagTrack.checked 			= $false
	    $CheckBoxDisableWAPPush.checked 			= $true
	    $CheckBoxEnableWAPPush.checked 				= $false
	    $CheckBoxP2PUpdateLocal.checked 			= $true
	    $CheckBoxP2PUpdateInternet.checked 			= $false
	    # Services
	    $CheckBoxSetUACLow.checked 					= $false
	    $CheckBoxSetUACHigh.checked 				= $false
	    $CheckBoxEnableSharingMappedDrives.checked 	= $false
	    $CheckBoxDisableSharingMappedDrives.checked = $false
	    $CheckBoxDisableAdminShares.checked 		= $true
	    $CheckBoxEnableAdminShares.checked 			= $false
	    $CheckBoxDisableSMB1.checked 				= $true
	    $CheckBoxEnableSMB1.checked 				= $false
	    $CheckBoxCurrentNetworkPrivate.checked 		= $true
	    $CheckBoxCurrentNetworkPublic.checked 		= $false
	    $CheckBoxUnknownNetworksPrivate.checked 	= $false
	    $CheckBoxUnknownNetworksPublic.checked 		= $false
	    $CheckBoxEnableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableCtrldFolderAccess.checked 	= $true
	    $CheckBoxDisableFirewall.checked 			= $false
	    $CheckBoxEnableFirewall.checked 			= $false
	    $CheckBoxDisableDefender.checked 			= $false
	    $CheckBoxEnableDefender.checked 			= $false
	    $CheckBoxDisableDefenderCloud.checked 		= $false
	    $CheckBoxEnableDefenderCloud.checked 		= $false
	    $CheckBoxDisableUpdateMSRT.checked 			= $false
	    $CheckBoxEnableUpdateMSRT.checked 			= $false
	    $CheckBoxDisableUpdateDriver.checked 		= $false
	    $CheckBoxEnableUpdateDriver.checked 		= $false
	    $CheckBoxDisableUpdateRestart.checked 		= $false
	    $CheckBoxEnableUpdateRestart.checked 		= $false
	    $CheckBoxDisableHomeGroups.checked 			= $false
	    $CheckBoxEnableHomeGroups.checked 			= $false
	    $CheckBoxDisableSharedExperiences.checked 	= $false
	    $CheckBoxEnableSharedExperiences.checked 	= $false
	    $CheckBoxDisableRemoteAssistance.checked 	= $false
	    $CheckBoxEnableRemoteAssistance.checked 	= $false
	    $CheckBoxDisableRemoteDesktop.checked 		= $false
	    $CheckBoxEnableRemoteDesktop.checked 		= $false
	    $CheckBoxDisableAutoplay.checked 			= $false
	    $CheckBoxEnableAutoplay.checked 			= $false
	    $CheckBoxDisableAutorun.checked 			= $false
	    $CheckBoxEnableAutorun.checked 				= $false
	    $CheckBoxDisableStorageSense.checked 		= $false
	    $CheckBoxEnableStorageSense.checked 		= $true
	    $CheckBoxDisableDefragmentation.checked 	= $false
	    $CheckBoxEnableDefragmentation.checked 		= $true
	    $CheckBoxDisableSuperfetch.checked 			= $false
	    $CheckBoxEnableSuperfetch.checked 			= $false
	    $CheckBoxDisableIndexing.checked 			= $false
	    $CheckBoxEnableIndexing.checked 			= $false
	    $CheckBoxSetBIOSTimeUTC.checked 			= $false
	    $CheckBoxSetBIOSTimeLocal.checked 			= $false
	    $CheckBoxDisableHibernation.checked 		= $false
	    $CheckBoxEnableHibernation.checked 			= $false
	    $CheckBoxDisableFastStartup.checked 		= $false
	    $CheckBoxEnableFastStartup.checked 			= $true
        $CheckBoxDisableMulticasting.Checked        = $false
        $CheckBoxEnableMulticasting.Checked         = $false
        $CheckBoxEnableIPV6.Checked                 = $false
        $CheckBoxDisableIPV6.Checked                = $false
	    # UI
	    $CheckBoxDisableActionCenter.checked 		= $false
	    $CheckBoxEnableActionCenter.checked 		= $false
	    $CheckBoxDisableLockScreen.checked 			= $false
	    $CheckBoxEnableLockScreen.checked 			= $false
	    $CheckBoxHideNetworkOnLockScreen.checked 	= $false
	    $CheckBoxShowNetworkOnLockScreen.checked 	= $false
	    $CheckBoxHideShutdownFromLockScreen.checked = $false
	    $CheckBoxShowShutdownOnLockScreen.checked 	= $false
	    $CheckBoxDisableStickyKeys.checked 			= $false
	    $CheckBoxEnableStickyKeys.checked 			= $false
	    $CheckBoxShowTaskManagerDetails.checked 	= $false
	    $CheckBoxHideTaskManagerDetails.checked 	= $false
	    $CheckBoxShowFileOperationsDetails.checked 	= $false
	    $CheckBoxHideFileOperationsDetails.checked 	= $false
	    $CheckBoxDisableFileDeleteConfirm.checked 	= $false
	    $CheckBoxEnableFileDeleteConfirm.checked 	= $false
	    $CheckBoxShowTaskbarSearchBox.checked 		= $false
	    $CheckBoxHideTaskbarSearchBox.checked 		= $false
	    $CheckBoxShowTaskView.checked 				= $false
	    $CheckBoxHideTaskView.checked 				= $false
    	$CheckBoxSmallTaskbarIcons.checked 			= $false
	    $CheckBoxLargeTaskbarIcons.checked 			= $false
	    $CheckBoxShowTaskbarTitles.checked 			= $false
	    $CheckBoxHideTaskbarTitles.checked 			= $false
	    $CheckBoxShowTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxHideTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxShowTrayIcons.checked 				= $false
	    $CheckBoxHideTrayIcons.checked 				= $false
	    $CheckBoxShowKnownExtensions.checked 		= $false
	    $CheckBoxHideKnownExtensions.checked 		= $false
	    $CheckBoxShowHiddenFiles.checked 			= $false
	    $CheckBoxHideHiddenFiles.checked 			= $false
	    $CheckBoxShowSyncNotifications.checked 		= $false
	    $CheckBoxHideSyncNotifications.checked 		= $false
	    $CheckBoxShowRecentShortcuts.checked 		= $false
	    $CheckBoxHideRecentShortcuts.checked 		= $false
	    $CheckBoxSetExplorerQuickAccess.checked 	= $false
	    $CheckBoxSetExplorerThisPC.checked 			= $false
	    $CheckBoxShowThisPCOnDesktop.checked 		= $false
	    $CheckBoxHideThisPCFromDesktop.checked 		= $false
	    $CheckBoxShowUserFolderOnDesktop.checked 	= $false
	    $CheckBoxHideUserFolderFromDesktop.checked	= $false
	    $CheckBoxShowDesktopInThisPC.checked 		= $false
	    $CheckBoxHideDesktopFromThisPC.checked 		= $false
	    $CheckBoxShowDocumentsInThisPC.checked 		= $false
	    $CheckBoxHideDocumentsFromThisPC.checked 	= $false
	    $CheckBoxShowDownloadsInThisPC.checked 		= $false
	    $CheckBoxHideDownloadsFromThisPC.checked 	= $false
	    $CheckBoxShowMusicInThisPC.checked 			= $false
	    $CheckBoxHideMusicFromThisPC.checked 		= $false
	    $CheckBoxShowPicturesInThisPC.checked 		= $false
	    $CheckBoxHidePicturesFromThisPC.checked 	= $false
	    $CheckBoxShowVideosInThisPC.checked 		= $false
	    $CheckBoxHideVideosFromThisPC.checked 		= $false
	    $CheckBoxShow3DObjectsInThisPC.checked 		= $false
    	$CheckBoxHide3DObjectsFromThisPC.checked 	= $false
    	$CheckBoxSetVisualFXPerformance.checked 	= $true
    	$CheckBoxSetVisualFXAppearance.checked 		= $false
    	$CheckBoxEnableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbsDB.checked 			= $false
	    $CheckBoxEnableThumbsDB.checked 			= $false
    	$CheckBoxAddENKeyboard.checked 				= $false
	    $CheckBoxRemoveENKeyboard.checked 			= $false
	    $CheckBoxDisableNumlock.checked 			= $false
	    $CheckBoxEnableNumlock.checked 				= $false
	    # Application
	    $CheckBoxDisableOneDrive.checked 			= $true
	    $CheckBoxEnableOneDrive.checked 			= $false
	    $CheckBoxUninstallOneDrive.checked 			= $false
	    $CheckBoxInstallOneDrive.checked 			= $false
	    $CheckBoxUninstallMsftBloat.checked 		= $true
	    $CheckBoxInstallMsftBloat.checked 			= $false
	    $CheckBoxUninstallThirdPartyBloat.checked 	= $true
	    $CheckBoxInstallThirdPartyBloat.checked 	= $false
	    $CheckBoxUninstallWindowsStore.checked 		= $true
	    $CheckBoxInstallWindowsStore.checked 		= $false
	    $CheckBoxDisableXboxFeatures.checked 		= $true
	    $CheckBoxEnableXboxFeatures.checked 		= $false
	    $CheckBoxDisableAdobeFlash.checked 			= $true
	    $CheckBoxEnableAdobeFlash.checked 			= $false
	    $CheckBoxUninstallMediaPlayer.checked 		= $true
	    $CheckBoxInstallMediaPlayer.checked 		= $false
	    $CheckBoxUninstallWorkFolders.checked 		= $true
	    $CheckBoxInstallWorkFolders.checked 		= $false
	    $CheckBoxUninstallLinuxSubsystem.checked	= $true
	    $CheckBoxInstallLinuxSubsystem.checked 		= $false
	    $CheckBoxUninstallHyperV.checked 			= $true
	    $CheckBoxInstallHyperV.checked 				= $false
	    $CheckBoxSetPhotoViewerAssociation.checked 	= $false
	    $CheckBoxUnsetPhotoViewerAssociation.checked	= $false
	    $CheckBoxAddPhotoViewerOpenWith.checked 	= $false
	    $CheckBoxRemovePhotoViewerOpenWith.checked 	= $false
	    $CheckBoxDisableSearchAppInStore.checked 	= $true
	    $CheckBoxEnableSearchAppInStore.checked 	= $false
	    $CheckBoxDisableNewAppPrompt.checked 		= $false
	    $CheckBoxEnableNewAppPrompt.checked 		= $false
	    $CheckBoxDisableF8BootMenu.checked 			= $false
	    $CheckBoxEnableF8BootMenu.checked 			= $false
	    $CheckBoxSetDEPOptIn.checked 				= $false
	    $CheckBoxSetDEPOptOut.checked 				= $false
	    # Server
	    $CheckBoxHideServerManagerOnLogin.checked 	= $false
	    $CheckBoxShowServerManagerOnLogin.checked 	= $false
	    $CheckBoxDisableShutdownTracker.checked 	= $false
	    $CheckBoxEnableShutdownTracker.checked 		= $false
	    $CheckBoxDisablePasswordPolicy.checked 		= $false
	    $CheckBoxEnablePasswordPolicy.checked 		= $false
	    $CheckBoxDisableCtrlAltDelLogin.checked 	= $false
	    $CheckBoxEnableCtrlAltDelLogin.checked 		= $false
	    $CheckBoxDisableIEEnhancedSecurity.checked 	= $false
	    $CheckBoxEnableIEEnhancedSecurity.checked 	= $false
	    # Other
        $CheckBoxDisableAutoMaintenance.checked     = $false
        $CheckBoxEnableAutoMaintenance.checked      = $true
        $CheckBoxDeleteTempFiles.checked            = $true
        $CheckBoxCleanWinSXS.checked                = $true
        $CheckBoxDiskCleanup.checked                = $true
        $CheckBoxSetEasternTime.checked             = $flase
        $CheckBoxSetCentralTime.checked             = $flase
        $CheckBoxSetMountainTime.checked            = $flase
        $CheckBoxSetPacificTime.checked             = $flase
        $CheckBoxSyncTimeToInternet.checked         = $true
        $CheckBoxSFCScanNow.checked                 = $true
        $CheckBoxWiFiNamePassword.checked           = $flase
        $CheckBoxStop11.checked                     = $false
        $CheckBoxSetPagingAuto.checked              = $false
        $CheckBoxSetPagingManual.checked            = $true
        $CheckBoxBlock60.checked                    = $false
	    # NiNite
        $CheckBoxFoxitReader.checked                = $flase
        $CheckBoxSumatraPDF.checked                 = $flase
        $CheckBoxCutePDF.checked                    = $flase
        $CheckBoxLebreOffice.checked                = $flase
        $CheckBoxOpenOffice.checked                 = $flase
        $CheckBoxFireFox.checked                    = $flase
        $CheckBoxChrome.checked                     = $flase
        $CheckBoxOpera.checked                      = $flase
        $CheckBoxFileZilla.checked                  = $flase
        $CheckBoxNotepad.checked                    = $flase
        $CheckBox7Zip.checked                       = $flase
        $CheckBoxPuTTY.checked                      = $flase
        $CheckBoxVisualStudioCode.checked           = $flase
        $CheckBoxWinRAR.checked                     = $flase
        $CheckBoxTeamViewer.checked                 = $flase
        $CheckBoxImgBurn.checked                    = $flase
        $CheckBoxWinDirStat.checked                 = $flase
        $CheckBoxVLC.checked                        = $flase
        $CheckBoxAudacity.checked                   = $flase
        $CheckBoxSpotify.checked                    = $flase
        $CheckBoxZoom.checked                       = $flase
        $CheckBoxDiscord.checked                    = $flase
        $CheckBoxSkype.checked                      = $flase
        $CheckBoxMailwarebytes.checked              = $flase
        $CheckBoxAvast.checked                      = $flase
        $CheckBoxKeePass.checked                    = $flase
    }
}
function FunctionNewComputer () {
    If ($CheckBoxNewComputer.Checked -eq $true) {
        $CheckBoxQuickClean.Checked     =$false
        $CheckBoxDeepClean.Checked      =$false
        $CheckBoxClearAll.Checked       =$false
        $CheckBoxServer.Checked         =$false
        # Privacy
        $CheckBoxDisableTelemetry.checked 			= $true
        $CheckBoxEnableTelemetry.checked 			= $false
    	$CheckBoxDisableWiFiSense.checked 			= $true
	    $CheckBoxEnableWiFiSense.checked 			= $false
	    $CheckBoxDisableSmartScreen.checked 		= $true
	    $CheckBoxEnableSmartScreen.checked 			= $false
	    $CheckBoxDisableWebSearch.checked 			= $true
	    $CheckBoxEnableWebSearch.checked 			= $false
	    $CheckBoxDisableAppSuggestions.checked 		= $true
	    $CheckBoxEnableAppSuggestions.checked 		= $false
	    $CheckBoxDisableBackgroundApps.checked 		= $true
	    $CheckBoxEnableBackgroundApps.checked 		= $false
	    $CheckBoxDisableLockScreenSpotlight.checked = $true
	    $CheckBoxEnableLockScreenSpotlight.checked 	= $false
	    $CheckBoxDisableLocationTracking.checked 	= $true
	    $CheckBoxEnableLocationTracking.checked 	= $false
	    $CheckBoxDisableMapUpdates.checked 			= $true
	    $CheckBoxEnableMapUpdates.checked 			= $false
	    $CheckBoxDisableFeedback.checked 			= $true
	    $CheckBoxEnableFeedback.checked 			= $false
	    $CheckBoxDisableAdvertisingID.checked 		= $true
	    $CheckBoxEnableAdvertisingID.checked 		= $false
	    $CheckBoxDisableCortana.checked 			= $true
	    $CheckBoxEnableCortana.checked 				= $false
	    $CheckBoxDisableErrorReporting.checked 		= $true
	    $CheckBoxEnableErrorReporting.checked 		= $false
	    $CheckBoxDisableAutoLogger.checked 			= $true
	    $CheckBoxEnableAutoLogger.checked 			= $false
	    $CheckBoxDisableDiagTrack.checked 			= $true
	    $CheckBoxEnableDiagTrack.checked 			= $false
	    $CheckBoxDisableWAPPush.checked 			= $true
	    $CheckBoxEnableWAPPush.checked 				= $false
	    $CheckBoxP2PUpdateLocal.checked 			= $true
	    $CheckBoxP2PUpdateInternet.checked 			= $false
	    # Services
	    $CheckBoxSetUACLow.checked 					= $false
	    $CheckBoxSetUACHigh.checked 				= $true
	    $CheckBoxEnableSharingMappedDrives.checked 	= $false
	    $CheckBoxDisableSharingMappedDrives.checked = $true
	    $CheckBoxDisableAdminShares.checked 		= $true
	    $CheckBoxEnableAdminShares.checked 			= $false
	    $CheckBoxDisableSMB1.checked 				= $true
	    $CheckBoxEnableSMB1.checked 				= $false
	    $CheckBoxCurrentNetworkPrivate.checked 		= $true
	    $CheckBoxCurrentNetworkPublic.checked 		= $false
	    $CheckBoxUnknownNetworksPrivate.checked 	= $true
	    $CheckBoxUnknownNetworksPublic.checked 		= $false
	    $CheckBoxEnableCtrldFolderAccess.checked 	= $true
	    $CheckBoxDisableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableFirewall.checked 			= $false
	    $CheckBoxEnableFirewall.checked 			= $true
	    $CheckBoxDisableDefender.checked 			= $false
	    $CheckBoxEnableDefender.checked 			= $true
	    $CheckBoxDisableDefenderCloud.checked 		= $false
	    $CheckBoxEnableDefenderCloud.checked 		= $true
	    $CheckBoxDisableUpdateMSRT.checked 			= $false
	    $CheckBoxEnableUpdateMSRT.checked 			= $true
	    $CheckBoxDisableUpdateDriver.checked 		= $false
	    $CheckBoxEnableUpdateDriver.checked 		= $true
	    $CheckBoxDisableUpdateRestart.checked 		= $true
	    $CheckBoxEnableUpdateRestart.checked 		= $false
	    $CheckBoxDisableHomeGroups.checked 			= $true
	    $CheckBoxEnableHomeGroups.checked 			= $false
	    $CheckBoxDisableSharedExperiences.checked 	= $true
	    $CheckBoxEnableSharedExperiences.checked 	= $false
	    $CheckBoxDisableRemoteAssistance.checked 	= $true
	    $CheckBoxEnableRemoteAssistance.checked 	= $false
	    $CheckBoxDisableRemoteDesktop.checked 		= $true
	    $CheckBoxEnableRemoteDesktop.checked 		= $false
	    $CheckBoxDisableAutoplay.checked 			= $true
	    $CheckBoxEnableAutoplay.checked 			= $false
	    $CheckBoxDisableAutorun.checked 			= $true
	    $CheckBoxEnableAutorun.checked 				= $false
	    $CheckBoxDisableStorageSense.checked 		= $false
	    $CheckBoxEnableStorageSense.checked 		= $true
	    $CheckBoxDisableDefragmentation.checked 	= $false
	    $CheckBoxEnableDefragmentation.checked 		= $true
	    $CheckBoxDisableSuperfetch.checked 			= $true
	    $CheckBoxEnableSuperfetch.checked 			= $false
	    $CheckBoxDisableIndexing.checked 			= $false
	    $CheckBoxEnableIndexing.checked 			= $true
	    $CheckBoxSetBIOSTimeUTC.checked 			= $true
	    $CheckBoxSetBIOSTimeLocal.checked 			= $false
	    $CheckBoxDisableHibernation.checked 		= $true
	    $CheckBoxEnableHibernation.checked 			= $false
	    $CheckBoxDisableFastStartup.checked 		= $false
	    $CheckBoxEnableFastStartup.checked 			= $true
        $CheckBoxDisableMulticasting.Checked        = $true
        $CheckBoxEnableMulticasting.Checked         = $false
        $CheckBoxEnableIPV6.Checked                 = $false
        $CheckBoxDisableIPV6.Checked                = $true
	    # UI
	    $CheckBoxDisableActionCenter.checked 		= $false
	    $CheckBoxEnableActionCenter.checked 		= $true
	    $CheckBoxDisableLockScreen.checked 			= $false
	    $CheckBoxEnableLockScreen.checked 			= $true
	    $CheckBoxHideNetworkOnLockScreen.checked 	= $false
	    $CheckBoxShowNetworkOnLockScreen.checked 	= $true
	    $CheckBoxHideShutdownFromLockScreen.checked = $false
	    $CheckBoxShowShutdownOnLockScreen.checked 	= $true
	    $CheckBoxDisableStickyKeys.checked 			= $true
	    $CheckBoxEnableStickyKeys.checked 			= $false
	    $CheckBoxShowTaskManagerDetails.checked 	= $true
	    $CheckBoxHideTaskManagerDetails.checked 	= $false
	    $CheckBoxShowFileOperationsDetails.checked 	= $true
	    $CheckBoxHideFileOperationsDetails.checked 	= $false
	    $CheckBoxDisableFileDeleteConfirm.checked 	= $true
	    $CheckBoxEnableFileDeleteConfirm.checked 	= $false
	    $CheckBoxShowTaskbarSearchBox.checked 		= $true
	    $CheckBoxHideTaskbarSearchBox.checked 		= $false
	    $CheckBoxShowTaskView.checked 				= $true
	    $CheckBoxHideTaskView.checked 				= $false
    	$CheckBoxSmallTaskbarIcons.checked 			= $true
	    $CheckBoxLargeTaskbarIcons.checked 			= $false
	    $CheckBoxShowTaskbarTitles.checked 			= $true
	    $CheckBoxHideTaskbarTitles.checked 			= $false
	    $CheckBoxShowTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxHideTaskbarPeopleIcon.checked 		= $true
	    $CheckBoxShowTrayIcons.checked 				= $true
	    $CheckBoxHideTrayIcons.checked 				= $false
	    $CheckBoxShowKnownExtensions.checked 		= $true
	    $CheckBoxHideKnownExtensions.checked 		= $false
	    $CheckBoxShowHiddenFiles.checked 			= $false
	    $CheckBoxHideHiddenFiles.checked 			= $true
	    $CheckBoxShowSyncNotifications.checked 		= $false
	    $CheckBoxHideSyncNotifications.checked 		= $true
	    $CheckBoxShowRecentShortcuts.checked 		= $true
	    $CheckBoxHideRecentShortcuts.checked 		= $false
	    $CheckBoxSetExplorerQuickAccess.checked 	= $true
	    $CheckBoxSetExplorerThisPC.checked 			= $false
	    $CheckBoxShowThisPCOnDesktop.checked 		= $true
	    $CheckBoxHideThisPCFromDesktop.checked 		= $false
	    $CheckBoxShowUserFolderOnDesktop.checked 	= $true
	    $CheckBoxHideUserFolderFromDesktop.checked	= $false
	    $CheckBoxShowDesktopInThisPC.checked 		= $true
	    $CheckBoxHideDesktopFromThisPC.checked 		= $false
	    $CheckBoxShowDocumentsInThisPC.checked 		= $true
	    $CheckBoxHideDocumentsFromThisPC.checked 	= $false
	    $CheckBoxShowDownloadsInThisPC.checked 		= $true
	    $CheckBoxHideDownloadsFromThisPC.checked 	= $false
	    $CheckBoxShowMusicInThisPC.checked 			= $true
	    $CheckBoxHideMusicFromThisPC.checked 		= $false
	    $CheckBoxShowPicturesInThisPC.checked 		= $true
	    $CheckBoxHidePicturesFromThisPC.checked 	= $false
	    $CheckBoxShowVideosInThisPC.checked 		= $true
	    $CheckBoxHideVideosFromThisPC.checked 		= $false
	    $CheckBoxShow3DObjectsInThisPC.checked 		= $false
    	$CheckBoxHide3DObjectsFromThisPC.checked 	= $true
    	$CheckBoxSetVisualFXPerformance.checked 	= $false
    	$CheckBoxSetVisualFXAppearance.checked 		= $true
    	$CheckBoxEnableThumbnails.checked 			= $true
    	$CheckBoxDisableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbsDB.checked 			= $true
	    $CheckBoxEnableThumbsDB.checked 			= $false
    	$CheckBoxAddENKeyboard.checked 				= $true
	    $CheckBoxRemoveENKeyboard.checked 			= $false
	    $CheckBoxDisableNumlock.checked 			= $false
	    $CheckBoxEnableNumlock.checked 				= $true
	    # Application
	    $CheckBoxDisableOneDrive.checked 			= $true
	    $CheckBoxEnableOneDrive.checked 			= $false
	    $CheckBoxUninstallOneDrive.checked 			= $true
	    $CheckBoxInstallOneDrive.checked 			= $false
	    $CheckBoxUninstallMsftBloat.checked 		= $true
	    $CheckBoxInstallMsftBloat.checked 			= $false
	    $CheckBoxUninstallThirdPartyBloat.checked 	= $true
	    $CheckBoxInstallThirdPartyBloat.checked 	= $false
	    $CheckBoxUninstallWindowsStore.checked 		= $true
	    $CheckBoxInstallWindowsStore.checked 		= $false
	    $CheckBoxDisableXboxFeatures.checked 		= $true
	    $CheckBoxEnableXboxFeatures.checked 		= $false
	    $CheckBoxDisableAdobeFlash.checked 			= $true
	    $CheckBoxEnableAdobeFlash.checked 			= $false
	    $CheckBoxUninstallMediaPlayer.checked 		= $true
	    $CheckBoxInstallMediaPlayer.checked 		= $false
	    $CheckBoxUninstallWorkFolders.checked 		= $true
	    $CheckBoxInstallWorkFolders.checked 		= $false
	    $CheckBoxUninstallLinuxSubsystem.checked	= $true
	    $CheckBoxInstallLinuxSubsystem.checked 		= $false
	    $CheckBoxUninstallHyperV.checked 			= $true
	    $CheckBoxInstallHyperV.checked 				= $false
	    $CheckBoxSetPhotoViewerAssociation.checked 	= $true
	    $CheckBoxUnsetPhotoViewerAssociation.checked	= $false
	    $CheckBoxAddPhotoViewerOpenWith.checked 	= $true
	    $CheckBoxRemovePhotoViewerOpenWith.checked 	= $false
	    $CheckBoxDisableSearchAppInStore.checked 	= $true
	    $CheckBoxEnableSearchAppInStore.checked 	= $false
	    $CheckBoxDisableNewAppPrompt.checked 		= $true
	    $CheckBoxEnableNewAppPrompt.checked 		= $false
	    $CheckBoxDisableF8BootMenu.checked 			= $false
	    $CheckBoxEnableF8BootMenu.checked 			= $true
	    $CheckBoxSetDEPOptIn.checked 				= $true
	    $CheckBoxSetDEPOptOut.checked 				= $false
	    # Server
	    $CheckBoxHideServerManagerOnLogin.checked 	= $false
	    $CheckBoxShowServerManagerOnLogin.checked 	= $false
	    $CheckBoxDisableShutdownTracker.checked 	= $false
	    $CheckBoxEnableShutdownTracker.checked 		= $false
	    $CheckBoxDisablePasswordPolicy.checked 		= $false
	    $CheckBoxEnablePasswordPolicy.checked 		= $false
	    $CheckBoxDisableCtrlAltDelLogin.checked 	= $false
	    $CheckBoxEnableCtrlAltDelLogin.checked 		= $false
	    $CheckBoxDisableIEEnhancedSecurity.checked 	= $false
	    $CheckBoxEnableIEEnhancedSecurity.checked 	= $false
	    # Other
        $CheckBoxDisableAutoMaintenance.checked     = $false
        $CheckBoxEnableAutoMaintenance.checked      = $true
        $CheckBoxDeleteTempFiles.checked            = $false
        $CheckBoxCleanWinSXS.checked                = $false
        $CheckBoxDiskCleanup.checked                = $false
        $CheckBoxSetEasternTime.checked             = $true
        $CheckBoxSetCentralTime.checked             = $flase
        $CheckBoxSetMountainTime.checked            = $flase
        $CheckBoxSetPacificTime.checked             = $flase
        $CheckBoxSyncTimeToInternet.checked         = $true
        $CheckBoxSFCScanNow.checked                 = $false
        $CheckBoxWiFiNamePassword.checked           = $flase
        $CheckBoxStop11.checked                     = $false
        $CheckBoxSetPagingAuto.checked              = $false
        $CheckBoxSetPagingManual.checked            = $false
        $CheckBoxBlock60.checked                    = $true
	    # NiNite
        $CheckBoxFoxitReader.checked                = $flase
        $CheckBoxSumatraPDF.checked                 = $flase
        $CheckBoxCutePDF.checked                    = $flase
        $CheckBoxLebreOffice.checked                = $flase
        $CheckBoxOpenOffice.checked                 = $flase
        $CheckBoxFireFox.checked                    = $flase
        $CheckBoxChrome.checked                     = $true
        $CheckBoxOpera.checked                      = $flase
        $CheckBoxFileZilla.checked                  = $flase
        $CheckBoxNotepad.checked                    = $flase
        $CheckBox7Zip.checked                       = $true
        $CheckBoxPuTTY.checked                      = $flase
        $CheckBoxVisualStudioCode.checked           = $flase
        $CheckBoxWinRAR.checked                     = $flase
        $CheckBoxTeamViewer.checked                 = $flase
        $CheckBoxImgBurn.checked                    = $flase
        $CheckBoxWinDirStat.checked                 = $flase
        $CheckBoxVLC.checked                        = $flase
        $CheckBoxAudacity.checked                   = $flase
        $CheckBoxSpotify.checked                    = $flase
        $CheckBoxZoom.checked                       = $flase
        $CheckBoxDiscord.checked                    = $flase
        $CheckBoxSkype.checked                      = $flase
        $CheckBoxMailwarebytes.checked              = $flase
        $CheckBoxAvast.checked                      = $flase
        $CheckBoxKeePass.checked                    = $flase
    }
}
function FunctionServer () {
    If ($CheckBoxServer.Checked -eq $true)     {
        $CheckBoxQuickClean.Checked     =$false
        $CheckBoxDeepClean.Checked      =$false
        $CheckBoxNewComputer.Checked    =$false
        $CheckBoxClearAll.Checked       =$false
                # Privacy
        $CheckBoxDisableTelemetry.checked 			= $false
        $CheckBoxEnableTelemetry.checked 			= $false
    	$CheckBoxDisableWiFiSense.checked 			= $false
	    $CheckBoxEnableWiFiSense.checked 			= $false
	    $CheckBoxDisableSmartScreen.checked 		= $false
	    $CheckBoxEnableSmartScreen.checked 			= $false
	    $CheckBoxDisableWebSearch.checked 			= $false
	    $CheckBoxEnableWebSearch.checked 			= $false
	    $CheckBoxDisableAppSuggestions.checked 		= $false
	    $CheckBoxEnableAppSuggestions.checked 		= $false
	    $CheckBoxDisableBackgroundApps.checked 		= $false
	    $CheckBoxEnableBackgroundApps.checked 		= $false
	    $CheckBoxDisableLockScreenSpotlight.checked = $false
	    $CheckBoxEnableLockScreenSpotlight.checked 	= $false
	    $CheckBoxDisableLocationTracking.checked 	= $false
	    $CheckBoxEnableLocationTracking.checked 	= $false
	    $CheckBoxDisableMapUpdates.checked 			= $false
	    $CheckBoxEnableMapUpdates.checked 			= $false
	    $CheckBoxDisableFeedback.checked 			= $false
	    $CheckBoxEnableFeedback.checked 			= $false
	    $CheckBoxDisableAdvertisingID.checked 		= $false
	    $CheckBoxEnableAdvertisingID.checked 		= $false
	    $CheckBoxDisableCortana.checked 			= $false
	    $CheckBoxEnableCortana.checked 				= $false
	    $CheckBoxDisableErrorReporting.checked 		= $false
	    $CheckBoxEnableErrorReporting.checked 		= $false
	    $CheckBoxDisableAutoLogger.checked 			= $false
	    $CheckBoxEnableAutoLogger.checked 			= $false
	    $CheckBoxDisableDiagTrack.checked 			= $false
	    $CheckBoxEnableDiagTrack.checked 			= $false
	    $CheckBoxDisableWAPPush.checked 			= $false
	    $CheckBoxEnableWAPPush.checked 				= $false
	    $CheckBoxP2PUpdateLocal.checked 			= $false
	    $CheckBoxP2PUpdateInternet.checked 			= $false
	    # Services
	    $CheckBoxSetUACLow.checked 					= $false
	    $CheckBoxSetUACHigh.checked 				= $false
	    $CheckBoxEnableSharingMappedDrives.checked 	= $false
	    $CheckBoxDisableSharingMappedDrives.checked = $false
	    $CheckBoxDisableAdminShares.checked 		= $false
	    $CheckBoxEnableAdminShares.checked 			= $false
	    $CheckBoxDisableSMB1.checked 				= $false
	    $CheckBoxEnableSMB1.checked 				= $false
	    $CheckBoxCurrentNetworkPrivate.checked 		= $false
	    $CheckBoxCurrentNetworkPublic.checked 		= $false
	    $CheckBoxUnknownNetworksPrivate.checked 	= $false
	    $CheckBoxUnknownNetworksPublic.checked 		= $false
	    $CheckBoxEnableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableFirewall.checked 			= $false
	    $CheckBoxEnableFirewall.checked 			= $false
	    $CheckBoxDisableDefender.checked 			= $false
	    $CheckBoxEnableDefender.checked 			= $false
	    $CheckBoxDisableDefenderCloud.checked 		= $false
	    $CheckBoxEnableDefenderCloud.checked 		= $false
	    $CheckBoxDisableUpdateMSRT.checked 			= $false
	    $CheckBoxEnableUpdateMSRT.checked 			= $false
	    $CheckBoxDisableUpdateDriver.checked 		= $false
	    $CheckBoxEnableUpdateDriver.checked 		= $false
	    $CheckBoxDisableUpdateRestart.checked 		= $false
	    $CheckBoxEnableUpdateRestart.checked 		= $false
	    $CheckBoxDisableHomeGroups.checked 			= $false
	    $CheckBoxEnableHomeGroups.checked 			= $false
	    $CheckBoxDisableSharedExperiences.checked 	= $false
	    $CheckBoxEnableSharedExperiences.checked 	= $false
	    $CheckBoxDisableRemoteAssistance.checked 	= $false
	    $CheckBoxEnableRemoteAssistance.checked 	= $false
	    $CheckBoxDisableRemoteDesktop.checked 		= $false
	    $CheckBoxEnableRemoteDesktop.checked 		= $false
	    $CheckBoxDisableAutoplay.checked 			= $false
	    $CheckBoxEnableAutoplay.checked 			= $false
	    $CheckBoxDisableAutorun.checked 			= $false
	    $CheckBoxEnableAutorun.checked 				= $false
	    $CheckBoxDisableStorageSense.checked 		= $false
	    $CheckBoxEnableStorageSense.checked 		= $false
	    $CheckBoxDisableDefragmentation.checked 	= $false
	    $CheckBoxEnableDefragmentation.checked 		= $false
	    $CheckBoxDisableSuperfetch.checked 			= $false
	    $CheckBoxEnableSuperfetch.checked 			= $false
	    $CheckBoxDisableIndexing.checked 			= $false
	    $CheckBoxEnableIndexing.checked 			= $false
	    $CheckBoxSetBIOSTimeUTC.checked 			= $false
	    $CheckBoxSetBIOSTimeLocal.checked 			= $false
	    $CheckBoxDisableHibernation.checked 		= $false
	    $CheckBoxEnableHibernation.checked 			= $false
	    $CheckBoxDisableFastStartup.checked 		= $false
	    $CheckBoxEnableFastStartup.checked 			= $false
        $CheckBoxDisableMulticasting.Checked        = $false
        $CheckBoxEnableMulticasting.Checked         = $false
        $CheckBoxEnableIPV6.Checked                 = $false
        $CheckBoxDisableIPV6.Checked                = $false
	    # UI
	    $CheckBoxDisableActionCenter.checked 		= $false
	    $CheckBoxEnableActionCenter.checked 		= $false
	    $CheckBoxDisableLockScreen.checked 			= $false
	    $CheckBoxEnableLockScreen.checked 			= $false
	    $CheckBoxHideNetworkOnLockScreen.checked 	= $false
	    $CheckBoxShowNetworkOnLockScreen.checked 	= $false
	    $CheckBoxHideShutdownFromLockScreen.checked = $false
	    $CheckBoxShowShutdownOnLockScreen.checked 	= $false
	    $CheckBoxDisableStickyKeys.checked 			= $false
	    $CheckBoxEnableStickyKeys.checked 			= $false
	    $CheckBoxShowTaskManagerDetails.checked 	= $false
	    $CheckBoxHideTaskManagerDetails.checked 	= $false
	    $CheckBoxShowFileOperationsDetails.checked 	= $false
	    $CheckBoxHideFileOperationsDetails.checked 	= $false
	    $CheckBoxDisableFileDeleteConfirm.checked 	= $false
	    $CheckBoxEnableFileDeleteConfirm.checked 	= $false
	    $CheckBoxShowTaskbarSearchBox.checked 		= $false
	    $CheckBoxHideTaskbarSearchBox.checked 		= $false
	    $CheckBoxShowTaskView.checked 				= $false
	    $CheckBoxHideTaskView.checked 				= $false
    	$CheckBoxSmallTaskbarIcons.checked 			= $false
	    $CheckBoxLargeTaskbarIcons.checked 			= $false
	    $CheckBoxShowTaskbarTitles.checked 			= $false
	    $CheckBoxHideTaskbarTitles.checked 			= $false
	    $CheckBoxShowTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxHideTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxShowTrayIcons.checked 				= $false
	    $CheckBoxHideTrayIcons.checked 				= $false
	    $CheckBoxShowKnownExtensions.checked 		= $false
	    $CheckBoxHideKnownExtensions.checked 		= $false
	    $CheckBoxShowHiddenFiles.checked 			= $false
	    $CheckBoxHideHiddenFiles.checked 			= $false
	    $CheckBoxShowSyncNotifications.checked 		= $false
	    $CheckBoxHideSyncNotifications.checked 		= $false
	    $CheckBoxShowRecentShortcuts.checked 		= $false
	    $CheckBoxHideRecentShortcuts.checked 		= $false
	    $CheckBoxSetExplorerQuickAccess.checked 	= $false
	    $CheckBoxSetExplorerThisPC.checked 			= $false
	    $CheckBoxShowThisPCOnDesktop.checked 		= $false
	    $CheckBoxHideThisPCFromDesktop.checked 		= $false
	    $CheckBoxShowUserFolderOnDesktop.checked 	= $false
	    $CheckBoxHideUserFolderFromDesktop.checked	= $false
	    $CheckBoxShowDesktopInThisPC.checked 		= $false
	    $CheckBoxHideDesktopFromThisPC.checked 		= $false
	    $CheckBoxShowDocumentsInThisPC.checked 		= $false
	    $CheckBoxHideDocumentsFromThisPC.checked 	= $false
	    $CheckBoxShowDownloadsInThisPC.checked 		= $false
	    $CheckBoxHideDownloadsFromThisPC.checked 	= $false
	    $CheckBoxShowMusicInThisPC.checked 			= $false
	    $CheckBoxHideMusicFromThisPC.checked 		= $false
	    $CheckBoxShowPicturesInThisPC.checked 		= $false
	    $CheckBoxHidePicturesFromThisPC.checked 	= $false
	    $CheckBoxShowVideosInThisPC.checked 		= $false
	    $CheckBoxHideVideosFromThisPC.checked 		= $false
	    $CheckBoxShow3DObjectsInThisPC.checked 		= $false
    	$CheckBoxHide3DObjectsFromThisPC.checked 	= $false
    	$CheckBoxSetVisualFXPerformance.checked 	= $false
    	$CheckBoxSetVisualFXAppearance.checked 		= $false
    	$CheckBoxEnableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbsDB.checked 			= $false
	    $CheckBoxEnableThumbsDB.checked 			= $false
    	$CheckBoxAddENKeyboard.checked 				= $false
	    $CheckBoxRemoveENKeyboard.checked 			= $false
	    $CheckBoxDisableNumlock.checked 			= $false
	    $CheckBoxEnableNumlock.checked 				= $false
	    # Application
	    $CheckBoxDisableOneDrive.checked 			= $false
	    $CheckBoxEnableOneDrive.checked 			= $false
	    $CheckBoxUninstallOneDrive.checked 			= $false
	    $CheckBoxInstallOneDrive.checked 			= $false
	    $CheckBoxUninstallMsftBloat.checked 		= $false
	    $CheckBoxInstallMsftBloat.checked 			= $false
	    $CheckBoxUninstallThirdPartyBloat.checked 	= $false
	    $CheckBoxInstallThirdPartyBloat.checked 	= $false
	    $CheckBoxUninstallWindowsStore.checked 		= $false
	    $CheckBoxInstallWindowsStore.checked 		= $false
	    $CheckBoxDisableXboxFeatures.checked 		= $false
	    $CheckBoxEnableXboxFeatures.checked 		= $false
	    $CheckBoxDisableAdobeFlash.checked 			= $false
	    $CheckBoxEnableAdobeFlash.checked 			= $false
	    $CheckBoxUninstallMediaPlayer.checked 		= $false
	    $CheckBoxInstallMediaPlayer.checked 		= $false
	    $CheckBoxUninstallWorkFolders.checked 		= $false
	    $CheckBoxInstallWorkFolders.checked 		= $false
	    $CheckBoxUninstallLinuxSubsystem.checked	= $false
	    $CheckBoxInstallLinuxSubsystem.checked 		= $false
	    $CheckBoxUninstallHyperV.checked 			= $false
	    $CheckBoxInstallHyperV.checked 				= $false
	    $CheckBoxSetPhotoViewerAssociation.checked 	= $false
	    $CheckBoxUnsetPhotoViewerAssociation.checked	= $false
	    $CheckBoxAddPhotoViewerOpenWith.checked 	= $false
	    $CheckBoxRemovePhotoViewerOpenWith.checked 	= $false
	    $CheckBoxDisableSearchAppInStore.checked 	= $false
	    $CheckBoxEnableSearchAppInStore.checked 	= $false
	    $CheckBoxDisableNewAppPrompt.checked 		= $false
	    $CheckBoxEnableNewAppPrompt.checked 		= $false
	    $CheckBoxDisableF8BootMenu.checked 			= $false
	    $CheckBoxEnableF8BootMenu.checked 			= $false
	    $CheckBoxSetDEPOptIn.checked 				= $false
	    $CheckBoxSetDEPOptOut.checked 				= $false
	    # Server
	    $CheckBoxHideServerManagerOnLogin.checked 	= $false
	    $CheckBoxShowServerManagerOnLogin.checked 	= $true
	    $CheckBoxDisableShutdownTracker.checked 	= $false
	    $CheckBoxEnableShutdownTracker.checked 		= $true
	    $CheckBoxDisablePasswordPolicy.checked 		= $false
	    $CheckBoxEnablePasswordPolicy.checked 		= $true
	    $CheckBoxDisableCtrlAltDelLogin.checked 	= $false
	    $CheckBoxEnableCtrlAltDelLogin.checked 		= $true
	    $CheckBoxDisableIEEnhancedSecurity.checked 	= $false
	    $CheckBoxEnableIEEnhancedSecurity.checked 	= $true
	    # Other
        $CheckBoxDisableAutoMaintenance.checked     = $false
        $CheckBoxEnableAutoMaintenance.checked      = $false
        $CheckBoxDeleteTempFiles.checked            = $false
        $CheckBoxCleanWinSXS.checked                = $false
        $CheckBoxDiskCleanup.checked                = $false
        $CheckBoxSetEasternTime.checked             = $flase
        $CheckBoxSetCentralTime.checked             = $flase
        $CheckBoxSetMountainTime.checked            = $flase
        $CheckBoxSetPacificTime.checked             = $flase
        $CheckBoxSyncTimeToInternet.checked         = $flase
        $CheckBoxSFCScanNow.checked                 = $false
        $CheckBoxWiFiNamePassword.checked           = $flase
        $CheckBoxStop11.checked                     = $false
        $CheckBoxSetPagingAuto.checked              = $false
        $CheckBoxSetPagingManual.checked            = $false
        $CheckBoxBlock60.checked                    = $false
	    # NiNite
        $CheckBoxFoxitReader.checked                = $flase
        $CheckBoxSumatraPDF.checked                 = $flase
        $CheckBoxCutePDF.checked                    = $flase
        $CheckBoxLebreOffice.checked                = $flase
        $CheckBoxOpenOffice.checked                 = $flase
        $CheckBoxFireFox.checked                    = $flase
        $CheckBoxChrome.checked                     = $flase
        $CheckBoxOpera.checked                      = $flase
        $CheckBoxFileZilla.checked                  = $flase
        $CheckBoxNotepad.checked                    = $flase
        $CheckBox7Zip.checked                       = $flase
        $CheckBoxPuTTY.checked                      = $flase
        $CheckBoxVisualStudioCode.checked           = $flase
        $CheckBoxWinRAR.checked                     = $flase
        $CheckBoxTeamViewer.checked                 = $flase
        $CheckBoxImgBurn.checked                    = $flase
        $CheckBoxWinDirStat.checked                 = $flase
        $CheckBoxVLC.checked                        = $flase
        $CheckBoxAudacity.checked                   = $flase
        $CheckBoxSpotify.checked                    = $flase
        $CheckBoxZoom.checked                       = $flase
        $CheckBoxDiscord.checked                    = $flase
        $CheckBoxSkype.checked                      = $flase
        $CheckBoxMailwarebytes.checked              = $flase
        $CheckBoxAvast.checked                      = $flase
        $CheckBoxKeePass.checked                    = $flase
    }
}
function FunctionClearAll () {
    If ($CheckBoxClearAll.Checked -eq $true) {
        $CheckBoxQuickClean.Checked     =$false
        $CheckBoxDeepClean.Checked      =$false
        $CheckBoxNewComputer.Checked    =$false
        $CheckBoxServer.Checked         =$false
        # Privacy
        $CheckBoxDisableTelemetry.checked 			= $false
        $CheckBoxEnableTelemetry.checked 			= $false
    	$CheckBoxDisableWiFiSense.checked 			= $false
	    $CheckBoxEnableWiFiSense.checked 			= $false
	    $CheckBoxDisableSmartScreen.checked 		= $false
	    $CheckBoxEnableSmartScreen.checked 			= $false
	    $CheckBoxDisableWebSearch.checked 			= $false
	    $CheckBoxEnableWebSearch.checked 			= $false
	    $CheckBoxDisableAppSuggestions.checked 		= $false
	    $CheckBoxEnableAppSuggestions.checked 		= $false
	    $CheckBoxDisableBackgroundApps.checked 		= $false
	    $CheckBoxEnableBackgroundApps.checked 		= $false
	    $CheckBoxDisableLockScreenSpotlight.checked = $false
	    $CheckBoxEnableLockScreenSpotlight.checked 	= $false
	    $CheckBoxDisableLocationTracking.checked 	= $false
	    $CheckBoxEnableLocationTracking.checked 	= $false
	    $CheckBoxDisableMapUpdates.checked 			= $false
	    $CheckBoxEnableMapUpdates.checked 			= $false
	    $CheckBoxDisableFeedback.checked 			= $false
	    $CheckBoxEnableFeedback.checked 			= $false
	    $CheckBoxDisableAdvertisingID.checked 		= $false
	    $CheckBoxEnableAdvertisingID.checked 		= $false
	    $CheckBoxDisableCortana.checked 			= $false
	    $CheckBoxEnableCortana.checked 				= $false
	    $CheckBoxDisableErrorReporting.checked 		= $false
	    $CheckBoxEnableErrorReporting.checked 		= $false
	    $CheckBoxDisableAutoLogger.checked 			= $false
	    $CheckBoxEnableAutoLogger.checked 			= $false
	    $CheckBoxDisableDiagTrack.checked 			= $false
	    $CheckBoxEnableDiagTrack.checked 			= $false
	    $CheckBoxDisableWAPPush.checked 			= $false
	    $CheckBoxEnableWAPPush.checked 				= $false
	    $CheckBoxP2PUpdateLocal.checked 			= $false
	    $CheckBoxP2PUpdateInternet.checked 			= $false
	    # Services
	    $CheckBoxSetUACLow.checked 					= $false
	    $CheckBoxSetUACHigh.checked 				= $false
	    $CheckBoxEnableSharingMappedDrives.checked 	= $false
	    $CheckBoxDisableSharingMappedDrives.checked = $false
	    $CheckBoxDisableAdminShares.checked 		= $false
	    $CheckBoxEnableAdminShares.checked 			= $false
	    $CheckBoxDisableSMB1.checked 				= $false
	    $CheckBoxEnableSMB1.checked 				= $false
	    $CheckBoxCurrentNetworkPrivate.checked 		= $false
	    $CheckBoxCurrentNetworkPublic.checked 		= $false
	    $CheckBoxUnknownNetworksPrivate.checked 	= $false
	    $CheckBoxUnknownNetworksPublic.checked 		= $false
	    $CheckBoxEnableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableCtrldFolderAccess.checked 	= $false
	    $CheckBoxDisableFirewall.checked 			= $false
	    $CheckBoxEnableFirewall.checked 			= $false
	    $CheckBoxDisableDefender.checked 			= $false
	    $CheckBoxEnableDefender.checked 			= $false
	    $CheckBoxDisableDefenderCloud.checked 		= $false
	    $CheckBoxEnableDefenderCloud.checked 		= $false
	    $CheckBoxDisableUpdateMSRT.checked 			= $false
	    $CheckBoxEnableUpdateMSRT.checked 			= $false
	    $CheckBoxDisableUpdateDriver.checked 		= $false
	    $CheckBoxEnableUpdateDriver.checked 		= $false
	    $CheckBoxDisableUpdateRestart.checked 		= $false
	    $CheckBoxEnableUpdateRestart.checked 		= $false
	    $CheckBoxDisableHomeGroups.checked 			= $false
	    $CheckBoxEnableHomeGroups.checked 			= $false
	    $CheckBoxDisableSharedExperiences.checked 	= $false
	    $CheckBoxEnableSharedExperiences.checked 	= $false
	    $CheckBoxDisableRemoteAssistance.checked 	= $false
	    $CheckBoxEnableRemoteAssistance.checked 	= $false
	    $CheckBoxDisableRemoteDesktop.checked 		= $false
	    $CheckBoxEnableRemoteDesktop.checked 		= $false
	    $CheckBoxDisableAutoplay.checked 			= $false
	    $CheckBoxEnableAutoplay.checked 			= $false
	    $CheckBoxDisableAutorun.checked 			= $false
	    $CheckBoxEnableAutorun.checked 				= $false
	    $CheckBoxDisableStorageSense.checked 		= $false
	    $CheckBoxEnableStorageSense.checked 		= $false
	    $CheckBoxDisableDefragmentation.checked 	= $false
	    $CheckBoxEnableDefragmentation.checked 		= $false
	    $CheckBoxDisableSuperfetch.checked 			= $false
	    $CheckBoxEnableSuperfetch.checked 			= $false
	    $CheckBoxDisableIndexing.checked 			= $false
	    $CheckBoxEnableIndexing.checked 			= $false
	    $CheckBoxSetBIOSTimeUTC.checked 			= $false
	    $CheckBoxSetBIOSTimeLocal.checked 			= $false
	    $CheckBoxDisableHibernation.checked 		= $false
	    $CheckBoxEnableHibernation.checked 			= $false
	    $CheckBoxDisableFastStartup.checked 		= $false
	    $CheckBoxEnableFastStartup.checked 			= $false
        $CheckBoxDisableMulticasting.Checked        = $false
        $CheckBoxEnableMulticasting.Checked         = $false
        $CheckBoxEnableIPV6.Checked                 = $false
        $CheckBoxDisableIPV6.Checked                = $false
	    # UI
	    $CheckBoxDisableActionCenter.checked 		= $false
	    $CheckBoxEnableActionCenter.checked 		= $false
	    $CheckBoxDisableLockScreen.checked 			= $false
	    $CheckBoxEnableLockScreen.checked 			= $false
	    $CheckBoxHideNetworkOnLockScreen.checked 	= $false
	    $CheckBoxShowNetworkOnLockScreen.checked 	= $false
	    $CheckBoxHideShutdownFromLockScreen.checked = $false
	    $CheckBoxShowShutdownOnLockScreen.checked 	= $false
	    $CheckBoxDisableStickyKeys.checked 			= $false
	    $CheckBoxEnableStickyKeys.checked 			= $false
	    $CheckBoxShowTaskManagerDetails.checked 	= $false
	    $CheckBoxHideTaskManagerDetails.checked 	= $false
	    $CheckBoxShowFileOperationsDetails.checked 	= $false
	    $CheckBoxHideFileOperationsDetails.checked 	= $false
	    $CheckBoxDisableFileDeleteConfirm.checked 	= $false
	    $CheckBoxEnableFileDeleteConfirm.checked 	= $false
	    $CheckBoxShowTaskbarSearchBox.checked 		= $false
	    $CheckBoxHideTaskbarSearchBox.checked 		= $false
	    $CheckBoxShowTaskView.checked 				= $false
	    $CheckBoxHideTaskView.checked 				= $false
    	$CheckBoxSmallTaskbarIcons.checked 			= $false
	    $CheckBoxLargeTaskbarIcons.checked 			= $false
	    $CheckBoxShowTaskbarTitles.checked 			= $false
	    $CheckBoxHideTaskbarTitles.checked 			= $false
	    $CheckBoxShowTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxHideTaskbarPeopleIcon.checked 		= $false
	    $CheckBoxShowTrayIcons.checked 				= $false
	    $CheckBoxHideTrayIcons.checked 				= $false
	    $CheckBoxShowKnownExtensions.checked 		= $false
	    $CheckBoxHideKnownExtensions.checked 		= $false
	    $CheckBoxShowHiddenFiles.checked 			= $false
	    $CheckBoxHideHiddenFiles.checked 			= $false
	    $CheckBoxShowSyncNotifications.checked 		= $false
	    $CheckBoxHideSyncNotifications.checked 		= $false
	    $CheckBoxShowRecentShortcuts.checked 		= $false
	    $CheckBoxHideRecentShortcuts.checked 		= $false
	    $CheckBoxSetExplorerQuickAccess.checked 	= $false
	    $CheckBoxSetExplorerThisPC.checked 			= $false
	    $CheckBoxShowThisPCOnDesktop.checked 		= $false
	    $CheckBoxHideThisPCFromDesktop.checked 		= $false
	    $CheckBoxShowUserFolderOnDesktop.checked 	= $false
	    $CheckBoxHideUserFolderFromDesktop.checked	= $false
	    $CheckBoxShowDesktopInThisPC.checked 		= $false
	    $CheckBoxHideDesktopFromThisPC.checked 		= $false
	    $CheckBoxShowDocumentsInThisPC.checked 		= $false
	    $CheckBoxHideDocumentsFromThisPC.checked 	= $false
	    $CheckBoxShowDownloadsInThisPC.checked 		= $false
	    $CheckBoxHideDownloadsFromThisPC.checked 	= $false
	    $CheckBoxShowMusicInThisPC.checked 			= $false
	    $CheckBoxHideMusicFromThisPC.checked 		= $false
	    $CheckBoxShowPicturesInThisPC.checked 		= $false
	    $CheckBoxHidePicturesFromThisPC.checked 	= $false
	    $CheckBoxShowVideosInThisPC.checked 		= $false
	    $CheckBoxHideVideosFromThisPC.checked 		= $false
	    $CheckBoxShow3DObjectsInThisPC.checked 		= $false
    	$CheckBoxHide3DObjectsFromThisPC.checked 	= $false
    	$CheckBoxSetVisualFXPerformance.checked 	= $false
    	$CheckBoxSetVisualFXAppearance.checked 		= $false
    	$CheckBoxEnableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbnails.checked 			= $false
    	$CheckBoxDisableThumbsDB.checked 			= $false
	    $CheckBoxEnableThumbsDB.checked 			= $false
    	$CheckBoxAddENKeyboard.checked 				= $false
	    $CheckBoxRemoveENKeyboard.checked 			= $false
	    $CheckBoxDisableNumlock.checked 			= $false
	    $CheckBoxEnableNumlock.checked 				= $false
	    # Application
	    $CheckBoxDisableOneDrive.checked 			= $false
	    $CheckBoxEnableOneDrive.checked 			= $false
	    $CheckBoxUninstallOneDrive.checked 			= $false
	    $CheckBoxInstallOneDrive.checked 			= $false
	    $CheckBoxUninstallMsftBloat.checked 		= $false
	    $CheckBoxInstallMsftBloat.checked 			= $false
	    $CheckBoxUninstallThirdPartyBloat.checked 	= $false
	    $CheckBoxInstallThirdPartyBloat.checked 	= $false
	    $CheckBoxUninstallWindowsStore.checked 		= $false
	    $CheckBoxInstallWindowsStore.checked 		= $false
	    $CheckBoxDisableXboxFeatures.checked 		= $false
	    $CheckBoxEnableXboxFeatures.checked 		= $false
	    $CheckBoxDisableAdobeFlash.checked 			= $false
	    $CheckBoxEnableAdobeFlash.checked 			= $false
	    $CheckBoxUninstallMediaPlayer.checked 		= $false
	    $CheckBoxInstallMediaPlayer.checked 		= $false
	    $CheckBoxUninstallWorkFolders.checked 		= $false
	    $CheckBoxInstallWorkFolders.checked 		= $false
	    $CheckBoxUninstallLinuxSubsystem.checked	= $false
	    $CheckBoxInstallLinuxSubsystem.checked 		= $false
	    $CheckBoxUninstallHyperV.checked 			= $false
	    $CheckBoxInstallHyperV.checked 				= $false
	    $CheckBoxSetPhotoViewerAssociation.checked 	= $false
	    $CheckBoxUnsetPhotoViewerAssociation.checked	= $false
	    $CheckBoxAddPhotoViewerOpenWith.checked 	= $false
	    $CheckBoxRemovePhotoViewerOpenWith.checked 	= $false
	    $CheckBoxDisableSearchAppInStore.checked 	= $false
	    $CheckBoxEnableSearchAppInStore.checked 	= $false
	    $CheckBoxDisableNewAppPrompt.checked 		= $false
	    $CheckBoxEnableNewAppPrompt.checked 		= $false
	    $CheckBoxDisableF8BootMenu.checked 			= $false
	    $CheckBoxEnableF8BootMenu.checked 			= $false
	    $CheckBoxSetDEPOptIn.checked 				= $false
	    $CheckBoxSetDEPOptOut.checked 				= $false
	    # Server
	    $CheckBoxHideServerManagerOnLogin.checked 	= $false
	    $CheckBoxShowServerManagerOnLogin.checked 	= $false
	    $CheckBoxDisableShutdownTracker.checked 	= $false
	    $CheckBoxEnableShutdownTracker.checked 		= $false
	    $CheckBoxDisablePasswordPolicy.checked 		= $false
	    $CheckBoxEnablePasswordPolicy.checked 		= $false
	    $CheckBoxDisableCtrlAltDelLogin.checked 	= $false
	    $CheckBoxEnableCtrlAltDelLogin.checked 		= $false
	    $CheckBoxDisableIEEnhancedSecurity.checked 	= $false
	    $CheckBoxEnableIEEnhancedSecurity.checked 	= $false
	    # Other
        $CheckBoxDisableAutoMaintenance.checked     = $false
        $CheckBoxEnableAutoMaintenance.checked      = $false
        $CheckBoxDeleteTempFiles.checked            = $false
        $CheckBoxCleanWinSXS.checked                = $false
        $CheckBoxDiskCleanup.checked                = $false
        $CheckBoxSetEasternTime.checked             = $flase
        $CheckBoxSetCentralTime.checked             = $flase
        $CheckBoxSetMountainTime.checked            = $flase
        $CheckBoxSetPacificTime.checked             = $flase
        $CheckBoxSyncTimeToInternet.checked         = $flase
        $CheckBoxSFCScanNow.checked                 = $false
        $CheckBoxWiFiNamePassword.checked           = $flase
        $CheckBoxStop11.checked                     = $false
        $CheckBoxSetPagingAuto.checked              = $false
        $CheckBoxSetPagingManual.checked            = $false
        $CheckBoxBlock60.checked                    = $false
	    # NiNite
        $CheckBoxFoxitReader.checked                = $flase
        $CheckBoxSumatraPDF.checked                 = $flase
        $CheckBoxCutePDF.checked                    = $flase
        $CheckBoxLebreOffice.checked                = $flase
        $CheckBoxOpenOffice.checked                 = $flase
        $CheckBoxFireFox.checked                    = $flase
        $CheckBoxChrome.checked                     = $flase
        $CheckBoxOpera.checked                      = $flase
        $CheckBoxFileZilla.checked                  = $flase
        $CheckBoxNotepad.checked                    = $flase
        $CheckBox7Zip.checked                       = $flase
        $CheckBoxPuTTY.checked                      = $flase
        $CheckBoxVisualStudioCode.checked           = $flase
        $CheckBoxWinRAR.checked                     = $flase
        $CheckBoxTeamViewer.checked                 = $flase
        $CheckBoxImgBurn.checked                    = $flase
        $CheckBoxWinDirStat.checked                 = $flase
        $CheckBoxVLC.checked                        = $flase
        $CheckBoxAudacity.checked                   = $flase
        $CheckBoxSpotify.checked                    = $flase
        $CheckBoxZoom.checked                       = $flase
        $CheckBoxDiscord.checked                    = $flase
        $CheckBoxSkype.checked                      = $flase
        $CheckBoxMailwarebytes.checked              = $flase
        $CheckBoxAvast.checked                      = $flase
        $CheckBoxKeePass.checked                    = $flase
    }
}
#---------------------------------------------------------
function FunctionStart () {
    FunctionPrivacyHide
    FunctionServiceHide
    FunctionUIHide
    FunctionApplicationHide
    FunctionServerHide
    FunctionOtherHide
    FunctionNiNiteHide
    $FormBackupTool.ClientSize       = '680,820'
    $TextBoxOutput.Visible = $true
    $TimeNow = Get-Date
    $TimeNow = $TimeNow.ToUniversalTime().ToString("HH:mm:ss")
    $TextBoxOutput.Text = "Start Time $($TimeNow) Please Wait`r`n" 
    # Privacy
    if ($CheckBoxDisableTelemetry.checked -eq $true) {DisableTelemetry}
    if ($CheckBoxEnableTelemetry.checked -eq $true) {EnableTelemetry}
	if ($CheckBoxDisableWiFiSense.checked -eq $true) {DisableWiFiSense}
	if ($CheckBoxEnableWiFiSense.checked -eq $true) {EnableWiFiSense}
	if ($CheckBoxDisableSmartScreen.checked -eq $true) {DisableSmartScreen}
	if ($CheckBoxEnableSmartScreen.checked -eq $true) {EnableSmartScreen}
	if ($CheckBoxDisableWebSearch.checked -eq $true) {DisableWebSearch}
	if ($CheckBoxEnableWebSearch.checked -eq $true) {EnableWebSearch}
	if ($CheckBoxDisableAppSuggestions.checked -eq $true) {DisableAppSuggestions}
	if ($CheckBoxEnableAppSuggestions.checked -eq $true) {EnableAppSuggestions}
	if ($CheckBoxDisableBackgroundApps.checked -eq $true) {DisableBackgroundApps}
	if ($CheckBoxEnableBackgroundApps.checked -eq $true) {EnableBackgroundApps}
	if ($CheckBoxDisableLockScreenSpotlight.checked -eq $true) {DisableLockScreenSpotlight}
	if ($CheckBoxEnableLockScreenSpotlight.checked -eq $true) {EnableLockScreenSpotlight}
	if ($CheckBoxDisableLocationTracking.checked -eq $true) {DisableLocationTracking}
	if ($CheckBoxEnableLocationTracking.checked -eq $true) {EnableLocationTracking}
	if ($CheckBoxDisableMapUpdates.checked -eq $true) {DisableMapUpdates}
	if ($CheckBoxEnableMapUpdates.checked -eq $true) {EnableMapUpdates}
	if ($CheckBoxDisableFeedback.checked -eq $true) {DisableFeedback}
	if ($CheckBoxEnableFeedback.checked -eq $true) {EnableFeedback}
	if ($CheckBoxDisableAdvertisingID.checked -eq $true) {DisableAdvertisingID}
	if ($CheckBoxEnableAdvertisingID.checked -eq $true) {EnableAdvertisingID}
	if ($CheckBoxDisableCortana.checked -eq $true) {DisableCortana}
	if ($CheckBoxEnableCortana.checked -eq $true) {EnableCortana}
	if ($CheckBoxDisableErrorReporting.checked -eq $true) {DisableErrorReporting}
	if ($CheckBoxEnableErrorReporting.checked -eq $true) {EnableErrorReporting}
	if ($CheckBoxDisableAutoLogger.checked -eq $true) {DisableAutoLogger}
	if ($CheckBoxEnableAutoLogger.checked -eq $true) {EnableAutoLogger}
	if ($CheckBoxDisableDiagTrack.checked -eq $true) {DisableDiagTrack}
	if ($CheckBoxEnableDiagTrack.checked -eq $true) {EnableDiagTrack}
	if ($CheckBoxDisableWAPPush.checked -eq $true) {DisableWAPPush}
	if ($CheckBoxEnableWAPPush.checked -eq $true) {EnableWAPPush}
	if ($CheckBoxP2PUpdateLocal.checked -eq $true) {SetP2PUpdateLocal}
	if ($CheckBoxP2PUpdateInternet.checked -eq $true) {SetP2PUpdateInternet}
	# Services
	if ($CheckBoxSetUACLow.checked -eq $true) {SetUACLow}
	if ($CheckBoxSetUACHigh.checked -eq $true) {SetUACHigh}
	if ($CheckBoxEnableSharingMappedDrives.checked -eq $true) {EnableSharingMappedDrives}
	if ($CheckBoxDisableSharingMappedDrives.checked -eq $true) {DisableSharingMappedDrives}
	if ($CheckBoxDisableAdminShares.checked -eq $true) {DisableAdminShares}
	if ($CheckBoxEnableAdminShares.checked -eq $true) {EnableAdminShares}
	if ($CheckBoxDisableSMB1.checked -eq $true) {DisableSMB1}
	if ($CheckBoxEnableSMB1.checked -eq $true) {EnableSMB1}
	if ($CheckBoxCurrentNetworkPrivate.checked -eq $true) {SetCurrentNetworkPrivate}
	if ($CheckBoxCurrentNetworkPublic.checked -eq $true) {SetCurrentNetworkPublic}
	if ($CheckBoxUnknownNetworksPrivate.checked -eq $true) {SetUnknownNetworksPrivate}
	if ($CheckBoxUnknownNetworksPublic.checked -eq $true) {SetUnknownNetworksPublic}
	if ($CheckBoxEnableCtrldFolderAccess.checked -eq $true) {EnableCtrldFolderAccess}
	if ($CheckBoxDisableCtrldFolderAccess.checked -eq $true) {DisableCtrldFolderAccess}
	if ($CheckBoxDisableFirewall.checked -eq $true) {DisableFirewall}
	if ($CheckBoxEnableFirewall.checked -eq $true) {EnableFirewall}
	if ($CheckBoxDisableDefender.checked -eq $true) {DisableDefender}
	if ($CheckBoxEnableDefender.checked -eq $true) {EnableDefender}
	if ($CheckBoxDisableDefenderCloud.checked -eq $true) {DisableDefenderCloud}
	if ($CheckBoxEnableDefenderCloud.checked -eq $true) {EnableDefenderCloud}
	if ($CheckBoxDisableUpdateMSRT.checked -eq $true) {DisableUpdateMSRT}
	if ($CheckBoxEnableUpdateMSRT.checked -eq $true) {EnableUpdateMSRT}
	if ($CheckBoxDisableUpdateDriver.checked -eq $true) {DisableUpdateDriver}
	if ($CheckBoxEnableUpdateDriver.checked -eq $true) {EnableUpdateDriver}
	if ($CheckBoxDisableUpdateRestart.checked -eq $true) {DisableUpdateRestart}
	if ($CheckBoxEnableUpdateRestart.checked -eq $true) {EnableUpdateRestart}
	if ($CheckBoxDisableHomeGroups.checked -eq $true) {DisableHomeGroups}
	if ($CheckBoxEnableHomeGroups.checked -eq $true) {EnableHomeGroups}
	if ($CheckBoxDisableSharedExperiences.checked -eq $true) {DisableSharedExperiences}
	if ($CheckBoxEnableSharedExperiences.checked -eq $true) {EnableSharedExperiences}
	if ($CheckBoxDisableRemoteAssistance.checked -eq $true) {DisableRemoteAssistance}
	if ($CheckBoxEnableRemoteAssistance.checked -eq $true) {EnableRemoteAssistance}
	if ($CheckBoxDisableRemoteDesktop.checked -eq $true) {DisableRemoteDesktop}
	if ($CheckBoxEnableRemoteDesktop.checked -eq $true) {EnableRemoteDesktop}
	if ($CheckBoxDisableAutoplay.checked -eq $true) {DisableAutoplay}
	if ($CheckBoxEnableAutoplay.checked -eq $true) {EnableAutoplay}
	if ($CheckBoxDisableAutorun.checked -eq $true) {DisableAutorun}
	if ($CheckBoxEnableAutorun.checked -eq $true) {EnableAutorun}
	if ($CheckBoxDisableStorageSense.checked -eq $true) {DisableStorageSense}
	if ($CheckBoxEnableStorageSense.checked -eq $true) {EnableStorageSense}
	if ($CheckBoxDisableDefragmentation.checked -eq $true) {DisableDefragmentation}
	if ($CheckBoxEnableDefragmentation.checked -eq $true) {EnableDefragmentation}
	if ($CheckBoxDisableSuperfetch.checked -eq $true) {DisableSuperfetch}
	if ($CheckBoxEnableSuperfetch.checked -eq $true) {EnableSuperfetch}
	if ($CheckBoxDisableIndexing.checked -eq $true) {DisableIndexing}
	if ($CheckBoxEnableIndexing.checked -eq $true) {EnableIndexing}
	if ($CheckBoxSetBIOSTimeUTC.checked -eq $true) {SetBIOSTimeUTC}
	if ($CheckBoxSetBIOSTimeLocal.checked -eq $true) {SetBIOSTimeLocal}
	if ($CheckBoxDisableHibernation.checked -eq $true) {DisableHibernation}
	if ($CheckBoxEnableHibernation.checked -eq $true) {EnableHibernation}
	if ($CheckBoxDisableFastStartup.checked -eq $true) {DisableFastStartup}
	if ($CheckBoxEnableFastStartup.checked -eq $true) {EnableFastStartup}
    if ($CheckBoxDisableMulticasting.Checked -eq $true) {DisableMulticasting}
    if ($CheckBoxEnableMulticasting.Checked -eq $true) {EnableMulticasting}
    if ($CheckBoxEnableIPV6.Checked -eq $true) {EnableIPV6}
    if ($CheckBoxDisableIPV6.Checked -eq $true) {DisableIPV6}
	# UI
	if ($CheckBoxDisableActionCenter.checked -eq $true) {DisableActionCenter}
	if ($CheckBoxEnableActionCenter.checked -eq $true) {EnableActionCenter}
	if ($CheckBoxDisableLockScreen.checked -eq $true) {DisableLockScreen}
	if ($CheckBoxEnableLockScreen.checked -eq $true) {EnableLockScreen}
	if ($CheckBoxHideNetworkOnLockScreen.checked -eq $true) {HideNetworkFromLockScreen}
	if ($CheckBoxShowNetworkOnLockScreen.checked -eq $true) {ShowNetworkOnLockScreen}
	if ($CheckBoxHideShutdownFromLockScreen.checked -eq $true) {HideShutdownFromLockScreen}
	if ($CheckBoxShowShutdownOnLockScreen.checked -eq $true) {ShowShutdownOnLockScreen}
	if ($CheckBoxDisableStickyKeys.checked -eq $true) {DisableStickyKeys}
	if ($CheckBoxEnableStickyKeys.checked -eq $true) {EnableStickyKeys}
	if ($CheckBoxShowTaskManagerDetails.checked -eq $true) {ShowTaskManagerDetails}
	if ($CheckBoxHideTaskManagerDetails.checked -eq $true) {HideTaskManagerDetails}
	if ($CheckBoxShowFileOperationsDetails.checked -eq $true) {ShowFileOperationsDetails}
	if ($CheckBoxHideFileOperationsDetails.checked -eq $true) {HideFileOperationsDetails}
	if ($CheckBoxDisableFileDeleteConfirm.checked -eq $true) {DisableFileDeleteConfirm}
	if ($CheckBoxEnableFileDeleteConfirm.checked -eq $true) {EnableFileDeleteConfirm}
	if ($CheckBoxShowTaskbarSearchBox.checked -eq $true) {ShowTaskbarSearchBox}
	if ($CheckBoxHideTaskbarSearchBox.checked -eq $true) {HideTaskbarSearchBox}
	if ($CheckBoxShowTaskView.checked -eq $true) {ShowTaskView}
	if ($CheckBoxHideTaskView.checked -eq $true) {HideTaskView}
	if ($CheckBoxSmallTaskbarIcons.checked -eq $true) {ShowSmallTaskbarIcons}
	if ($CheckBoxLargeTaskbarIcons.checked -eq $true) {ShowLargeTaskbarIcons}
	if ($CheckBoxShowTaskbarTitles.checked -eq $true) {ShowTaskbarTitles}
	if ($CheckBoxHideTaskbarTitles.checked -eq $true) {HideTaskbarTitles}
	if ($CheckBoxShowTaskbarPeopleIcon.checked -eq $true) {ShowTaskbarPeopleIcon}
	if ($CheckBoxHideTaskbarPeopleIcon.checked -eq $true) {HideTaskbarPeopleIcon}
	if ($CheckBoxShowTrayIcons.checked -eq $true) {ShowTrayIcons}
	if ($CheckBoxHideTrayIcons.checked -eq $true) {HideTrayIcons}
	if ($CheckBoxShowKnownExtensions.checked -eq $true) {ShowKnownExtensions}
	if ($CheckBoxHideKnownExtensions.checked -eq $true) {HideKnownExtensions}
	if ($CheckBoxShowHiddenFiles.checked -eq $true) {ShowHiddenFiles}
	if ($CheckBoxHideHiddenFiles.checked -eq $true) {HideHiddenFiles}
	if ($CheckBoxShowSyncNotifications.checked -eq $true) {ShowSyncNotifications}
	if ($CheckBoxHideSyncNotifications.checked -eq $true) {HideSyncNotifications}
	if ($CheckBoxShowRecentShortcuts.checked -eq $true) {ShowRecentShortcuts}
	if ($CheckBoxHideRecentShortcuts.checked -eq $true) {HideRecentShortcuts}
	if ($CheckBoxSetExplorerQuickAccess.checked -eq $true) {SetExplorerQuickAccess}
	if ($CheckBoxSetExplorerThisPC.checked -eq $true) {SetExplorerThisPC}
	if ($CheckBoxShowThisPCOnDesktop.checked -eq $true) {ShowThisPCOnDesktop}
	if ($CheckBoxHideThisPCFromDesktop.checked -eq $true) {HideThisPCFromDesktop}
	if ($CheckBoxShowUserFolderOnDesktop.checked -eq $true) {ShowUserFolderOnDesktop}
	if ($CheckBoxHideUserFolderFromDesktop.checked -eq $true) {HideUserFolderFromDesktop}
	if ($CheckBoxShowDesktopInThisPC.checked -eq $true) {ShowDesktopInThisPC}
	if ($CheckBoxHideDesktopFromThisPC.checked -eq $true) {HideDesktopFromThisPC}
	if ($CheckBoxShowDocumentsInThisPC.checked -eq $true) {ShowDocumentsInThisPC}
	if ($CheckBoxHideDocumentsFromThisPC.checked -eq $true) {HideDocumentsFromThisPC}
	if ($CheckBoxShowDownloadsInThisPC.checked -eq $true) {ShowDownloadsInThisPC}
	if ($CheckBoxHideDownloadsFromThisPC.checked -eq $true) {HideDownloadsFromThisPC}
	if ($CheckBoxShowMusicInThisPC.checked -eq $true) {ShowMusicInThisPC}
	if ($CheckBoxHideMusicFromThisPC.checked -eq $true) {HideMusicFromThisPC}
	if ($CheckBoxShowPicturesInThisPC.checked -eq $true) {ShowPicturesInThisPC}
	if ($CheckBoxHidePicturesFromThisPC.checked -eq $true) {HidePicturesFromThisPC}
	if ($CheckBoxShowVideosInThisPC.checked -eq $true) {ShowVideosInThisPC}
	if ($CheckBoxHideVideosFromThisPC.checked -eq $true) {HideVideosFromThisPC}
	if ($CheckBoxShow3DObjectsInThisPC.checked -eq $true) {Show3DObjectsInThisPC}
	if ($CheckBoxHide3DObjectsFromThisPC.checked -eq $true) {Hide3DObjectsFromThisPC}
	if ($CheckBoxSetVisualFXPerformance.checked -eq $true) {SetVisualFXPerformance}
	if ($CheckBoxSetVisualFXAppearance.checked -eq $true) {SetVisualFXAppearance}
	if ($CheckBoxEnableThumbnails.checked -eq $true) {EnableThumbnails}
	if ($CheckBoxDisableThumbnails.checked -eq $true) {DisableThumbnails}
	if ($CheckBoxDisableThumbsDB.checked -eq $true) {DisableThumbsDB}
	if ($CheckBoxEnableThumbsDB.checked -eq $true) {EnableThumbsDB}
	if ($CheckBoxAddENKeyboard.checked -eq $true) {AddENKeyboard}
	if ($CheckBoxRemoveENKeyboard.checked -eq $true) {RemoveENKeyboard}
	if ($CheckBoxDisableNumlock.checked -eq $true) {DisableNumlock}
	if ($CheckBoxEnableNumlock.checked -eq $true) {EnableNumlock}
	# Application
	if ($CheckBoxDisableOneDrive.checked -eq $true) {DisableOneDrive}
	if ($CheckBoxEnableOneDrive.checked -eq $true) {EnableOneDrive}
	if ($CheckBoxUninstallOneDrive.checked -eq $true) {UninstallOneDrive}
	if ($CheckBoxInstallOneDrive.checked -eq $true) {InstallOneDrive}
	if ($CheckBoxUninstallMsftBloat.checked -eq $true) {UninstallMsftBloat}
	if ($CheckBoxInstallMsftBloat.checked -eq $true) {InstallMsftBloat}
	if ($CheckBoxUninstallThirdPartyBloat.checked -eq $true) {UninstallThirdPartyBloat}
	if ($CheckBoxInstallThirdPartyBloat.checked -eq $true) {InstallThirdPartyBloat}
	if ($CheckBoxUninstallWindowsStore.checked -eq $true) {UninstallWindowsStore}
	if ($CheckBoxInstallWindowsStore.checked -eq $true) {InstallWindowsStore}
	if ($CheckBoxDisableXboxFeatures.checked -eq $true) {DisableXboxFeatures}
	if ($CheckBoxEnableXboxFeatures.checked -eq $true) {EnableXboxFeatures}
	if ($CheckBoxDisableAdobeFlash.checked -eq $true) {DisableAdobeFlash}
	if ($CheckBoxEnableAdobeFlash.checked -eq $true) {EnableAdobeFlash}
	if ($CheckBoxUninstallMediaPlayer.checked -eq $true) {UninstallMediaPlayer}
	if ($CheckBoxInstallMediaPlayer.checked -eq $true) {InstallMediaPlayer}
	if ($CheckBoxUninstallWorkFolders.checked -eq $true) {UninstallWorkFolders}
	if ($CheckBoxInstallWorkFolders.checked -eq $true) {InstallWorkFolders}
	if ($CheckBoxUninstallLinuxSubsystem.checked -eq $true) {UninstallLinuxSubsystem}
	if ($CheckBoxInstallLinuxSubsystem.checked -eq $true) {InstallLinuxSubsystem}
	if ($CheckBoxUninstallHyperV.checked -eq $true) {UninstallHyperV}
	if ($CheckBoxInstallHyperV.checked -eq $true) {InstallHyperV}
	if ($CheckBoxSetPhotoViewerAssociation.checked -eq $true) {SetPhotoViewerAssociation}
	if ($CheckBoxUnsetPhotoViewerAssociation.checked -eq $true) {UnsetPhotoViewerAssociation}
	if ($CheckBoxAddPhotoViewerOpenWith.checked -eq $true) {AddPhotoViewerOpenWith}
	if ($CheckBoxRemovePhotoViewerOpenWith.checked -eq $true) {RemovePhotoViewerOpenWith}
	if ($CheckBoxDisableSearchAppInStore.checked -eq $true) {DisableSearchAppInStore}
	if ($CheckBoxEnableSearchAppInStore.checked -eq $true) {EnableSearchAppInStore}
	if ($CheckBoxDisableNewAppPrompt.checked -eq $true) {DisableNewAppPrompt}
	if ($CheckBoxEnableNewAppPrompt.checked -eq $true) {EnableNewAppPrompt}
	if ($CheckBoxDisableF8BootMenu.checked -eq $true) {DisableF8BootMenu}
	if ($CheckBoxEnableF8BootMenu.checked -eq $true) {EnableF8BootMenu}
	if ($CheckBoxSetDEPOptIn.checked -eq $true) {SetDEPOptIn}
	if ($CheckBoxSetDEPOptOut.checked -eq $true) {SetDEPOptOut}
	# Server
	if ($CheckBoxHideServerManagerOnLogin.checked -eq $true) {HideServerManagerOnLogin}
	if ($CheckBoxShowServerManagerOnLogin.checked -eq $true) {ShowServerManagerOnLogin}
	if ($CheckBoxDisableShutdownTracker.checked -eq $true) {DisableShutdownTracker}
	if ($CheckBoxEnableShutdownTracker.checked -eq $true) {EnableShutdownTracker}
	if ($CheckBoxDisablePasswordPolicy.checked -eq $true) {DisablePasswordPolicy}
	if ($CheckBoxEnablePasswordPolicy.checked -eq $true) {EnablePasswordPolicy}
	if ($CheckBoxDisableCtrlAltDelLogin.checked -eq $true) {DisableCtrlAltDelLogin}
	if ($CheckBoxEnableCtrlAltDelLogin.checked -eq $true) {EnableCtrlAltDelLogin}
	if ($CheckBoxDisableIEEnhancedSecurity.checked -eq $true) {DisableIEEnhancedSecurity}
	if ($CheckBoxEnableIEEnhancedSecurity.checked -eq $true) {EnableIEEnhancedSecurity}
	# Other
    if ($CheckBoxDisableAutoMaintenance.checked -eq $true) {DisableAutoMaintenance}
    if ($CheckBoxEnableAutoMaintenance.checked -eq $true) {EnalbeAutoMaintenance}
    if ($CheckBoxDeleteTempFiles.checked -eq $true) {DeleteTempFiles}
    if ($CheckBoxCleanWinSXS.checked -eq $true) {CleanWinSXS}
    if ($CheckBoxDiskCleanup.checked -eq $true) {DiskCleanup}
    if ($CheckBoxSetEasternTime.checked -eq $true) {SetEasternTime}
    if ($CheckBoxSetCentralTime.checked -eq $true) {SetCentralTime}
    if ($CheckBoxSetMountainTime.checked -eq $true) {SetMountainTime}
    if ($CheckBoxSetPacificTime.checked -eq $true) {SetPacificTime}
    if ($CheckBoxSyncTimeToInternet.checked -eq $true) {SyncTimeToInternet}
    if ($CheckBoxSFCScanNow.checked -eq $true) {SFCScanNow}
    if ($CheckBoxWiFiNamePassword.checked -eq $true) {WiFiNamePassword}
    if ($CheckBoxStop11.checked -eq $true) {Stop11}
    if ($CheckBoxSetPagingAuto.checked -eq $true) {SetPagingAuto}
    if ($CheckBoxSetPagingManual.checked -eq $true) {SetPagingManual}
    if ($CheckBoxBlock60.checked -eq $true) {Block60}

	# NiNite
    $GoNiNite = $false
    $StringNiNite = $null
    if ($CheckBoxFoxitReader.checked -eq $true) {
        $GoNiNite = $true
        $StringNiNite += "foxit-"
    }
    if ($CheckBoxSumatraPDF.checked -eq $true) {
        $GoNiNite = $true
        $StringNiNite += "sumatrapdf-"
    }
    if ($CheckBoxCutePDF.checked -eq $true) {
        $GoNiNite = $true
        $StringNiNite += "cutepdf-"
    }
    if ($CheckBoxLebreOffice.checked -eq $true) {
        $GoNiNite = $true
        $StringNiNite += "libreoffice-" 
    }
    if ($CheckBoxOpenOffice.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "openoffice-" 
    }
    if ($CheckBoxFireFox.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "firefox-" 
    }
    if ($CheckBoxChrome.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "chrome-" 
    }
    if ($CheckBoxOpera.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "operaChromium-" 
    }
    if ($CheckBoxFileZilla.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "filezilla-" 
    }
    if ($CheckBoxNotepad.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "notepadplusplus-" 
    }
    if ($CheckBox7Zip.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "7zip-" 
    }
    if ($CheckBoxPuTTY.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "putty-" 
    }
    if ($CheckBoxVisualStudioCode.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "vscode-" 
    }
    if ($CheckBoxWinRAR.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "winrar-" 
    }
    if ($CheckBoxTeamViewer.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "teamviewer12-" 
    }
    if ($CheckBoxImgBurn.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "imgburn-" 
    }
    if ($CheckBoxWinDirStat.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "windirstat-" 
    }
    if ($CheckBoxVLC.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "vlc-" 
    }
    if ($CheckBoxAudacity.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "audacity-" 
    }
    if ($CheckBoxSpotify.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "spotify-" 
    }
    if ($CheckBoxZoom.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "zoom-" 
    }
    if ($CheckBoxDiscord.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "discord-" 
    }
    if ($CheckBoxSkype.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "skype-" 
    }
    if ($CheckBoxMailwarebytes.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "malwarebytes-" 
    }
    if ($CheckBoxAvast.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "avast-" 
    }
    if ($CheckBoxKeePass.checked -eq $True) {
        $GoNiNite = $true
        $StringNiNite += "keepass2-" 
    }
  
    if ($GoNiNite -eq $true) {
        $StringNiNite = $StringNiNite -replace ".$"

        $TextBoxOutput.Text += "Installing NiNite Apps $StringNiNite (Click CLOSE when it's finished)...`r`n"
        $ofs = '-'
        $niniteurl = "https://ninite.com/$StringNiNite/ninite.exe"
        $output = "C:\Ninite.exe"

        Invoke-WebRequest -Uri $niniteurl -OutFile $output
        & $output | Out-Null
    }

    $TimeNow = Get-Date
    $TimeNow = $TimeNow.ToUniversalTime().ToString("HH:mm:ss")
    $TextBoxOutput.Text += "Finish Time $($TimeNow) " 
    $TextBoxOutput.Text += "You should reboot now!"
}

# End




#---------------------------------------------------------
function FunctionAdvancedSectionPrivace () {
    If ($CheckBoxAdvancedSectionPrivace.Checked -eq $true) {
        $CheckBoxAdvancedSectionNiNite.Checked   =$false
        $CheckBoxAdvancedSectionServer.Checked   =$false
        $CheckBoxAdvancedSectionApp.Checked      =$false
        $CheckBoxAdvancedSectionUI.Checked       =$false
        $CheckBoxAdvancedSectionServices.Checked =$false  
        $CheckBoxAdvancedSectionOther.Checked    =$false
        FunctionPrivacyShow
        FunctionServiceHide
        FunctionUIHide
        FunctionApplicationHide
        FunctionServerHide
        FunctionOtherHide
        FunctionNiNiteHide
    }
}
function FunctionAdvancedSectionUI () {
    If ($CheckBoxAdvancedSectionUI.Checked -eq $true) {
        $CheckBoxAdvancedSectionNiNite.Checked   =$false
        $CheckBoxAdvancedSectionServer.Checked   =$false
        $CheckBoxAdvancedSectionApp.Checked      =$false
        $CheckBoxAdvancedSectionServices.Checked =$false
        $CheckBoxAdvancedSectionPrivace.Checked  =$false
        $CheckBoxAdvancedSectionOther.Checked    =$false
        FunctionPrivacyHide
        FunctionServiceHide
        FunctionUIShow
        FunctionApplicationHide
        FunctionServerHide
        FunctionOtherHide
        FunctionNiNiteHide
    }
}
function FunctionAdvancedSectionServices () {
    If ($CheckBoxAdvancedSectionServices.Checked -eq $true) {
        $CheckBoxAdvancedSectionNiNite.Checked   =$false
        $CheckBoxAdvancedSectionServer.Checked   =$false
        $CheckBoxAdvancedSectionApp.Checked      =$false
        $CheckBoxAdvancedSectionUI.Checked       =$false
        $CheckBoxAdvancedSectionPrivace.Checked  =$false
        $CheckBoxAdvancedSectionOther.Checked    =$false
        FunctionPrivacyHide
        FunctionServiceShow
        FunctionUIHide
        FunctionApplicationHide
        FunctionServerHide
        FunctionOtherHide
        FunctionNiNiteHide
    }
}
function FunctionAdvancedSectionApp () {
    If ($CheckBoxAdvancedSectionApp.Checked -eq $true) {
        $CheckBoxAdvancedSectionNiNite.Checked   =$false
        $CheckBoxAdvancedSectionServer.Checked   =$false
        $CheckBoxAdvancedSectionServices.Checked =$false
        $CheckBoxAdvancedSectionUI.Checked       =$false
        $CheckBoxAdvancedSectionPrivace.Checked  =$false
        $CheckBoxAdvancedSectionOther.Checked    =$false
        FunctionPrivacyHide
        FunctionServiceHide
        FunctionUIHide
        FunctionApplicationShow
        FunctionServerHide
        FunctionOtherHide
        FunctionNiNiteHide
    }
}
function FunctionAdvancedSectionServer () {
    If ($CheckBoxAdvancedSectionServer.Checked -eq $true) {
        $CheckBoxAdvancedSectionNiNite.Checked   =$false
        $CheckBoxAdvancedSectionApp.Checked      =$false
        $CheckBoxAdvancedSectionServices.Checked =$false
        $CheckBoxAdvancedSectionUI.Checked       =$false
        $CheckBoxAdvancedSectionPrivace.Checked  =$false
        $CheckBoxAdvancedSectionOther.Checked    =$false
        FunctionPrivacyHide
        FunctionServiceHide
        FunctionUIHide
        FunctionApplicationHide
        FunctionServerShow
        FunctionOtherHide
        FunctionNiNiteHide
    }
}
function FunctionAdvancedSectionOther () {
    If ($CheckBoxAdvancedSectionOther.Checked -eq $true) {
        $CheckBoxAdvancedSectionNiNite.Checked   =$false
        $CheckBoxAdvancedSectionApp.Checked      =$false
        $CheckBoxAdvancedSectionServices.Checked =$false
        $CheckBoxAdvancedSectionUI.Checked       =$false
        $CheckBoxAdvancedSectionPrivace.Checked  =$false
        $CheckBoxAdvancedSectionServer.Checked   =$false
        FunctionPrivacyHide
        FunctionServiceHide
        FunctionUIHide
        FunctionApplicationHide
        FunctionServerHide
        FunctionOtherShow
        FunctionNiNiteHide
    }
}
function FunctionAdvancedSectionNiNite () {
    If ($CheckBoxAdvancedSectionNiNite.Checked -eq $true) {
        $CheckBoxAdvancedSectionServer.Checked   =$false
        $CheckBoxAdvancedSectionApp.Checked      =$false
        $CheckBoxAdvancedSectionServices.Checked =$false
        $CheckBoxAdvancedSectionUI.Checked       =$false
        $CheckBoxAdvancedSectionPrivace.Checked  =$false
        $CheckBoxAdvancedSectionOther.Checked   =$false
        FunctionPrivacyHide
        FunctionServiceHide
        FunctionUIHide
        FunctionApplicationHide
        FunctionServerHide
        FunctionOtherHide
        FunctionNiNiteShow
    }
}
function FunctionPrivacyShow () {
        $CheckBoxDisableTelemetry.Visible =$true
        $CheckBoxEnableTelemetry.Visible =$true
        $CheckBoxDisableWiFiSense.Visible =$true
        $CheckBoxEnableWiFiSense.Visible =$true
        $CheckBoxDisableSmartScreen.Visible =$true
        $CheckBoxEnableSmartScreen.Visible =$true
        $CheckBoxDisableWebSearch.Visible =$true
        $CheckBoxEnableWebSearch.Visible =$true
        $CheckBoxDisableAppSuggestions.Visible =$true
        $CheckBoxEnableAppSuggestions.Visible =$true
        $CheckBoxDisableBackgroundApps.Visible =$true
        $CheckBoxEnableBackgroundApps.Visible =$true
        $CheckBoxDisableLockScreenSpotlight.Visible =$true
        $CheckBoxEnableLockScreenSpotlight.Visible =$true
        $CheckBoxDisableLocationTracking.Visible =$true
        $CheckBoxEnableLocationTracking.Visible =$true
        $CheckBoxDisableMapUpdates.Visible =$true
        $CheckBoxEnableMapUpdates.Visible =$true
        $CheckBoxDisableFeedback.Visible =$true
        $CheckBoxEnableFeedback.Visible =$true
        $CheckBoxDisableAdvertisingID.Visible =$true
        $CheckBoxEnableAdvertisingID.Visible =$true
        $CheckBoxDisableCortana.Visible =$true
        $CheckBoxEnableCortana.Visible =$true
        $CheckBoxDisableErrorReporting.Visible =$true
        $CheckBoxEnableErrorReporting.Visible =$true
        $CheckBoxDisableAutoLogger.Visible =$true
        $CheckBoxEnableAutoLogger.Visible =$true
        $CheckBoxDisableDiagTrack.Visible =$true
        $CheckBoxEnableDiagTrack.Visible =$true
        $CheckBoxDisableWAPPush.Visible =$true
        $CheckBoxEnableWAPPush.Visible =$true
        $CheckBoxP2PUpdateLocal.Visible =$true
        $CheckBoxP2PUpdateInternet.Visible =$true
}
function FunctionPrivacyHide () {
        $CheckBoxDisableTelemetry.Visible =$false
        $CheckBoxEnableTelemetry.Visible =$false
        $CheckBoxDisableWiFiSense.Visible =$false
        $CheckBoxEnableWiFiSense.Visible =$false
        $CheckBoxDisableSmartScreen.Visible =$false
        $CheckBoxEnableSmartScreen.Visible =$false
        $CheckBoxDisableWebSearch.Visible =$false
        $CheckBoxEnableWebSearch.Visible =$false
        $CheckBoxDisableAppSuggestions.Visible =$false
        $CheckBoxEnableAppSuggestions.Visible =$false
        $CheckBoxDisableBackgroundApps.Visible =$false
        $CheckBoxEnableBackgroundApps.Visible =$false
        $CheckBoxDisableLockScreenSpotlight.Visible =$false
        $CheckBoxEnableLockScreenSpotlight.Visible =$false
        $CheckBoxDisableLocationTracking.Visible =$false
        $CheckBoxEnableLocationTracking.Visible =$false
        $CheckBoxDisableMapUpdates.Visible =$false
        $CheckBoxEnableMapUpdates.Visible =$false
        $CheckBoxDisableFeedback.Visible =$false
        $CheckBoxEnableFeedback.Visible =$false
        $CheckBoxDisableAdvertisingID.Visible =$false
        $CheckBoxEnableAdvertisingID.Visible =$false
        $CheckBoxDisableCortana.Visible =$false
        $CheckBoxEnableCortana.Visible =$false
        $CheckBoxDisableErrorReporting.Visible =$false
        $CheckBoxEnableErrorReporting.Visible =$false
        $CheckBoxDisableAutoLogger.Visible =$false
        $CheckBoxEnableAutoLogger.Visible =$false
        $CheckBoxDisableDiagTrack.Visible =$false
        $CheckBoxEnableDiagTrack.Visible =$false
        $CheckBoxDisableWAPPush.Visible =$false
        $CheckBoxEnableWAPPush.Visible =$false
        $CheckBoxP2PUpdateLocal.Visible =$false
        $CheckBoxP2PUpdateInternet.Visible =$false
}
function FunctionServiceShow () {
        $CheckBoxSetUACLow.Visible =$true
        $CheckBoxSetUACHigh.Visible =$true
        $CheckBoxEnableSharingMappedDrives.Visible =$true
        $CheckBoxDisableSharingMappedDrives.Visible =$true
        $CheckBoxDisableAdminShares.Visible =$true
        $CheckBoxEnableAdminShares.Visible =$true
        $CheckBoxDisableSMB1.Visible =$true
        $CheckBoxEnableSMB1.Visible =$true
        $CheckBoxCurrentNetworkPrivate.Visible =$true
        $CheckBoxCurrentNetworkPublic.Visible =$true
        $CheckBoxUnknownNetworksPrivate.Visible =$true
        $CheckBoxUnknownNetworksPublic.Visible =$true
        $CheckBoxEnableCtrldFolderAccess.Visible =$true
        $CheckBoxDisableCtrldFolderAccess.Visible =$true
        $CheckBoxDisableFirewall.Visible =$true
        $CheckBoxEnableFirewall.Visible =$true
        $CheckBoxDisableDefender.Visible =$true
        $CheckBoxEnableDefender.Visible =$true
        $CheckBoxDisableDefenderCloud.Visible =$true
        $CheckBoxEnableDefenderCloud.Visible =$true
        $CheckBoxDisableUpdateMSRT.Visible =$true
        $CheckBoxEnableUpdateMSRT.Visible =$true
        $CheckBoxDisableUpdateDriver.Visible =$true
        $CheckBoxEnableUpdateDriver.Visible =$true
        $CheckBoxDisableUpdateRestart.Visible =$true
        $CheckBoxEnableUpdateRestart.Visible =$true
        $CheckBoxDisableHomeGroups.Visible =$true
        $CheckBoxEnableHomeGroups.Visible =$true
        $CheckBoxDisableSharedExperiences.Visible =$true
        $CheckBoxEnableSharedExperiences.Visible =$true
        $CheckBoxDisableRemoteAssistance.Visible =$true
        $CheckBoxEnableRemoteAssistance.Visible =$true
        $CheckBoxDisableRemoteDesktop.Visible =$true
        $CheckBoxEnableRemoteDesktop.Visible =$true
        $CheckBoxDisableAutoplay.Visible =$true
        $CheckBoxEnableAutoplay.Visible =$true
        $CheckBoxDisableAutorun.Visible =$true
        $CheckBoxEnableAutorun.Visible =$true
        $CheckBoxDisableStorageSense.Visible =$true
        $CheckBoxEnableStorageSense.Visible =$true
        $CheckBoxDisableDefragmentation.Visible =$true
        $CheckBoxEnableDefragmentation.Visible =$true
        $CheckBoxDisableSuperfetch.Visible =$true
        $CheckBoxEnableSuperfetch.Visible =$true
        $CheckBoxDisableIndexing.Visible =$true
        $CheckBoxEnableIndexing.Visible =$true
        $CheckBoxSetBIOSTimeUTC.Visible =$true
        $CheckBoxSetBIOSTimeLocal.Visible =$true
        $CheckBoxDisableHibernation.Visible =$true
        $CheckBoxEnableHibernation.Visible =$true
        $CheckBoxDisableFastStartup.Visible =$true
        $CheckBoxEnableFastStartup.Visible =$true
        $CheckBoxEnableMulticasting.Visible =$true
        $CheckBoxDisableMulticasting.Visible =$true
        $CheckBoxEnableIPV6.Visible =$true
        $CheckBoxDisableIPV6.Visible =$true
}
function FunctionServiceHide () {
        $CheckBoxSetUACLow.Visible =$false
        $CheckBoxSetUACHigh.Visible =$false
        $CheckBoxEnableSharingMappedDrives.Visible =$false
        $CheckBoxDisableSharingMappedDrives.Visible =$false
        $CheckBoxDisableAdminShares.Visible =$false
        $CheckBoxEnableAdminShares.Visible =$false
        $CheckBoxDisableSMB1.Visible =$false
        $CheckBoxEnableSMB1.Visible =$false
        $CheckBoxCurrentNetworkPrivate.Visible =$false
        $CheckBoxCurrentNetworkPublic.Visible =$false
        $CheckBoxUnknownNetworksPrivate.Visible =$false
        $CheckBoxUnknownNetworksPublic.Visible =$false
        $CheckBoxEnableCtrldFolderAccess.Visible =$false
        $CheckBoxDisableCtrldFolderAccess.Visible =$false
        $CheckBoxDisableFirewall.Visible =$false
        $CheckBoxEnableFirewall.Visible =$false
        $CheckBoxDisableDefender.Visible =$false
        $CheckBoxEnableDefender.Visible =$false
        $CheckBoxDisableDefenderCloud.Visible =$false
        $CheckBoxEnableDefenderCloud.Visible =$false
        $CheckBoxDisableUpdateMSRT.Visible =$false
        $CheckBoxEnableUpdateMSRT.Visible =$false
        $CheckBoxDisableUpdateDriver.Visible =$false
        $CheckBoxEnableUpdateDriver.Visible =$false
        $CheckBoxDisableUpdateRestart.Visible =$false
        $CheckBoxEnableUpdateRestart.Visible =$false
        $CheckBoxDisableHomeGroups.Visible =$false
        $CheckBoxEnableHomeGroups.Visible =$false
        $CheckBoxDisableSharedExperiences.Visible =$false
        $CheckBoxEnableSharedExperiences.Visible =$false
        $CheckBoxDisableRemoteAssistance.Visible =$false
        $CheckBoxEnableRemoteAssistance.Visible =$false
        $CheckBoxDisableRemoteDesktop.Visible =$false
        $CheckBoxEnableRemoteDesktop.Visible =$false
        $CheckBoxDisableAutoplay.Visible =$false
        $CheckBoxEnableAutoplay.Visible =$false
        $CheckBoxDisableAutorun.Visible =$false
        $CheckBoxEnableAutorun.Visible =$false
        $CheckBoxDisableStorageSense.Visible =$false
        $CheckBoxEnableStorageSense.Visible =$false
        $CheckBoxDisableDefragmentation.Visible =$false
        $CheckBoxEnableDefragmentation.Visible =$false
        $CheckBoxDisableSuperfetch.Visible =$false
        $CheckBoxEnableSuperfetch.Visible =$false
        $CheckBoxDisableIndexing.Visible =$false
        $CheckBoxEnableIndexing.Visible =$false
        $CheckBoxSetBIOSTimeUTC.Visible =$false
        $CheckBoxSetBIOSTimeLocal.Visible =$false
        $CheckBoxDisableHibernation.Visible =$false
        $CheckBoxEnableHibernation.Visible =$false
        $CheckBoxDisableFastStartup.Visible =$false
        $CheckBoxEnableFastStartup.Visible =$false
        $CheckBoxEnableMulticasting.Visible =$false
        $CheckBoxDisableMulticasting.Visible =$false
        $CheckBoxEnableIPV6.Visible =$false
        $CheckBoxDisableIPV6.Visible =$false
}
function FunctionUIShow () {
        $CheckBoxDisableActionCenter.Visible =$true
        $CheckBoxEnableActionCenter.Visible =$true
        $CheckBoxDisableLockScreen.Visible =$true
        $CheckBoxEnableLockScreen.Visible =$true
        $CheckBoxHideNetworkOnLockScreen.Visible =$true
        $CheckBoxShowNetworkOnLockScreen.Visible =$true
        $CheckBoxHideShutdownFromLockScreen.Visible =$true
        $CheckBoxShowShutdownOnLockScreen.Visible =$true
        $CheckBoxDisableStickyKeys.Visible =$true
        $CheckBoxEnableStickyKeys.Visible =$true
        $CheckBoxShowTaskManagerDetails.Visible =$true
        $CheckBoxHideTaskManagerDetails.Visible =$true
        $CheckBoxShowFileOperationsDetails.Visible =$true
        $CheckBoxHideFileOperationsDetails.Visible =$true
        $CheckBoxDisableFileDeleteConfirm.Visible =$true
        $CheckBoxEnableFileDeleteConfirm.Visible =$true
        $CheckBoxShowTaskbarSearchBox.Visible =$true
        $CheckBoxHideTaskbarSearchBox.Visible =$true
        $CheckBoxShowTaskView.Visible =$true
        $CheckBoxHideTaskView.Visible =$true
        $CheckBoxSmallTaskbarIcons.Visible =$true
        $CheckBoxLargeTaskbarIcons.Visible =$true
        $CheckBoxShowTaskbarTitles.Visible =$true
        $CheckBoxHideTaskbarTitles.Visible =$true
        $CheckBoxShowTaskbarPeopleIcon.Visible =$true
        $CheckBoxHideTaskbarPeopleIcon.Visible =$true
        $CheckBoxShowTrayIcons.Visible =$true
        $CheckBoxHideTrayIcons.Visible =$true
        $CheckBoxShowKnownExtensions.Visible =$true
        $CheckBoxHideKnownExtensions.Visible =$true
        $CheckBoxShowHiddenFiles.Visible =$true
        $CheckBoxHideHiddenFiles.Visible =$true
        $CheckBoxShowSyncNotifications.Visible =$true
        $CheckBoxHideSyncNotifications.Visible =$true
        $CheckBoxShowRecentShortcuts.Visible =$true
        $CheckBoxHideRecentShortcuts.Visible =$true
        $CheckBoxSetExplorerQuickAccess.Visible =$true
        $CheckBoxSetExplorerThisPC.Visible =$true
        $CheckBoxShowThisPCOnDesktop.Visible =$true
        $CheckBoxHideThisPCFromDesktop.Visible =$true
        $CheckBoxShowUserFolderOnDesktop.Visible =$true
        $CheckBoxHideUserFolderFromDesktop.Visible =$true
        $CheckBoxShowDesktopInThisPC.Visible =$true
        $CheckBoxHideDesktopFromThisPC.Visible =$true
        $CheckBoxShowDocumentsInThisPC.Visible =$true
        $CheckBoxHideDocumentsFromThisPC.Visible =$true
        $CheckBoxShowDownloadsInThisPC.Visible =$true
        $CheckBoxHideDownloadsFromThisPC.Visible =$true
        $CheckBoxShowMusicInThisPC.Visible =$true
        $CheckBoxHideMusicFromThisPC.Visible =$true
        $CheckBoxShowPicturesInThisPC.Visible =$true
        $CheckBoxHidePicturesFromThisPC.Visible =$true
        $CheckBoxShowVideosInThisPC.Visible =$true
        $CheckBoxHideVideosFromThisPC.Visible =$true
        $CheckBoxShow3DObjectsInThisPC.Visible =$true
        $CheckBoxHide3DObjectsFromThisPC.Visible =$true
        $CheckBoxSetVisualFXPerformance.Visible =$true
        $CheckBoxSetVisualFXAppearance.Visible =$true
        $CheckBoxEnableThumbnails.Visible =$true
        $CheckBoxDisableThumbnails.Visible =$true
        $CheckBoxDisableThumbsDB.Visible =$true
        $CheckBoxEnableThumbsDB.Visible =$true
        $CheckBoxAddENKeyboard.Visible =$true
        $CheckBoxRemoveENKeyboard.Visible =$true
        $CheckBoxDisableNumlock.Visible =$true
        $CheckBoxEnableNumlock.Visible =$true
}
function FunctionUIHide () {
        $CheckBoxDisableActionCenter.Visible =$false
        $CheckBoxEnableActionCenter.Visible =$false
        $CheckBoxDisableLockScreen.Visible =$false
        $CheckBoxEnableLockScreen.Visible =$false
        $CheckBoxHideNetworkOnLockScreen.Visible =$false
        $CheckBoxShowNetworkOnLockScreen.Visible =$false
        $CheckBoxHideShutdownFromLockScreen.Visible =$false
        $CheckBoxShowShutdownOnLockScreen.Visible =$false
        $CheckBoxDisableStickyKeys.Visible =$false
        $CheckBoxEnableStickyKeys.Visible =$false
        $CheckBoxShowTaskManagerDetails.Visible =$false
        $CheckBoxHideTaskManagerDetails.Visible =$false
        $CheckBoxShowFileOperationsDetails.Visible =$false
        $CheckBoxHideFileOperationsDetails.Visible =$false
        $CheckBoxDisableFileDeleteConfirm.Visible =$false
        $CheckBoxEnableFileDeleteConfirm.Visible =$false
        $CheckBoxShowTaskbarSearchBox.Visible =$false
        $CheckBoxHideTaskbarSearchBox.Visible =$false
        $CheckBoxShowTaskView.Visible =$false
        $CheckBoxHideTaskView.Visible =$false
        $CheckBoxSmallTaskbarIcons.Visible =$false
        $CheckBoxLargeTaskbarIcons.Visible =$false
        $CheckBoxShowTaskbarTitles.Visible =$false
        $CheckBoxHideTaskbarTitles.Visible =$false
        $CheckBoxShowTaskbarPeopleIcon.Visible =$false
        $CheckBoxHideTaskbarPeopleIcon.Visible =$false
        $CheckBoxShowTrayIcons.Visible =$false
        $CheckBoxHideTrayIcons.Visible =$false
        $CheckBoxShowKnownExtensions.Visible =$false
        $CheckBoxHideKnownExtensions.Visible =$false
        $CheckBoxShowHiddenFiles.Visible =$false
        $CheckBoxHideHiddenFiles.Visible =$false
        $CheckBoxShowSyncNotifications.Visible =$false
        $CheckBoxHideSyncNotifications.Visible =$false
        $CheckBoxShowRecentShortcuts.Visible =$false
        $CheckBoxHideRecentShortcuts.Visible =$false
        $CheckBoxSetExplorerQuickAccess.Visible =$false
        $CheckBoxSetExplorerThisPC.Visible =$false
        $CheckBoxShowThisPCOnDesktop.Visible =$false
        $CheckBoxHideThisPCFromDesktop.Visible =$false
        $CheckBoxShowUserFolderOnDesktop.Visible =$false
        $CheckBoxHideUserFolderFromDesktop.Visible =$false
        $CheckBoxShowDesktopInThisPC.Visible =$false
        $CheckBoxHideDesktopFromThisPC.Visible =$false
        $CheckBoxShowDocumentsInThisPC.Visible =$false
        $CheckBoxHideDocumentsFromThisPC.Visible =$false
        $CheckBoxShowDownloadsInThisPC.Visible =$false
        $CheckBoxHideDownloadsFromThisPC.Visible =$false
        $CheckBoxShowMusicInThisPC.Visible =$false
        $CheckBoxHideMusicFromThisPC.Visible =$false
        $CheckBoxShowPicturesInThisPC.Visible =$false
        $CheckBoxHidePicturesFromThisPC.Visible =$false
        $CheckBoxShowVideosInThisPC.Visible =$false
        $CheckBoxHideVideosFromThisPC.Visible =$false
        $CheckBoxShow3DObjectsInThisPC.Visible =$false
        $CheckBoxHide3DObjectsFromThisPC.Visible =$false
        $CheckBoxSetVisualFXPerformance.Visible =$false
        $CheckBoxSetVisualFXAppearance.Visible =$false
        $CheckBoxEnableThumbnails.Visible =$false
        $CheckBoxDisableThumbnails.Visible =$false
        $CheckBoxDisableThumbsDB.Visible =$false
        $CheckBoxEnableThumbsDB.Visible =$false
        $CheckBoxAddENKeyboard.Visible =$false
        $CheckBoxRemoveENKeyboard.Visible =$false
        $CheckBoxDisableNumlock.Visible =$false
        $CheckBoxEnableNumlock.Visible =$false
}
function FunctionApplicationShow () {
        $CheckBoxDisableOneDrive.Visible =$true
        $CheckBoxEnableOneDrive.Visible =$true
        $CheckBoxUninstallOneDrive.Visible =$true
        $CheckBoxInstallOneDrive.Visible =$true
        $CheckBoxUninstallMsftBloat.Visible =$true
        $CheckBoxInstallMsftBloat.Visible =$true
        $CheckBoxUninstallThirdPartyBloat.Visible =$true
        $CheckBoxInstallThirdPartyBloat.Visible =$true
        $CheckBoxUninstallWindowsStore.Visible =$true
        $CheckBoxInstallWindowsStore.Visible =$true
        $CheckBoxDisableXboxFeatures.Visible =$true
        $CheckBoxEnableXboxFeatures.Visible =$true
        $CheckBoxDisableAdobeFlash.Visible =$true
        $CheckBoxEnableAdobeFlash.Visible =$true
        $CheckBoxUninstallMediaPlayer.Visible =$true
        $CheckBoxInstallMediaPlayer.Visible =$true
        $CheckBoxUninstallWorkFolders.Visible =$true
        $CheckBoxInstallWorkFolders.Visible =$true
        $CheckBoxUninstallLinuxSubsystem.Visible =$true
        $CheckBoxInstallLinuxSubsystem.Visible =$true
        $CheckBoxUninstallHyperV.Visible =$true
        $CheckBoxInstallHyperV.Visible =$true
        $CheckBoxSetPhotoViewerAssociation.Visible =$true
        $CheckBoxUnsetPhotoViewerAssociation.Visible =$true
        $CheckBoxAddPhotoViewerOpenWith.Visible =$true
        $CheckBoxRemovePhotoViewerOpenWith.Visible =$true
        $CheckBoxDisableSearchAppInStore.Visible =$true
        $CheckBoxEnableSearchAppInStore.Visible =$true
        $CheckBoxDisableNewAppPrompt.Visible =$true
        $CheckBoxEnableNewAppPrompt.Visible =$true
        $CheckBoxDisableF8BootMenu.Visible =$true
        $CheckBoxEnableF8BootMenu.Visible =$true
        $CheckBoxSetDEPOptIn.Visible =$true
        $CheckBoxSetDEPOptOut.Visible =$true
}
function FunctionApplicationHide () {
        $CheckBoxDisableOneDrive.Visible =$false
        $CheckBoxEnableOneDrive.Visible =$false
        $CheckBoxUninstallOneDrive.Visible =$false
        $CheckBoxInstallOneDrive.Visible =$false
        $CheckBoxUninstallMsftBloat.Visible =$false
        $CheckBoxInstallMsftBloat.Visible =$false
        $CheckBoxUninstallThirdPartyBloat.Visible =$false
        $CheckBoxInstallThirdPartyBloat.Visible =$false
        $CheckBoxUninstallWindowsStore.Visible =$false
        $CheckBoxInstallWindowsStore.Visible =$false
        $CheckBoxDisableXboxFeatures.Visible =$false
        $CheckBoxEnableXboxFeatures.Visible =$false
        $CheckBoxDisableAdobeFlash.Visible =$false
        $CheckBoxEnableAdobeFlash.Visible =$false
        $CheckBoxUninstallMediaPlayer.Visible =$false
        $CheckBoxInstallMediaPlayer.Visible =$false
        $CheckBoxUninstallWorkFolders.Visible =$false
        $CheckBoxInstallWorkFolders.Visible =$false
        $CheckBoxUninstallLinuxSubsystem.Visible =$false
        $CheckBoxInstallLinuxSubsystem.Visible =$false
        $CheckBoxUninstallHyperV.Visible =$false
        $CheckBoxInstallHyperV.Visible =$false
        $CheckBoxSetPhotoViewerAssociation.Visible =$false
        $CheckBoxUnsetPhotoViewerAssociation.Visible =$false
        $CheckBoxAddPhotoViewerOpenWith.Visible =$false
        $CheckBoxRemovePhotoViewerOpenWith.Visible =$false
        $CheckBoxDisableSearchAppInStore.Visible =$false
        $CheckBoxEnableSearchAppInStore.Visible =$false
        $CheckBoxDisableNewAppPrompt.Visible =$false
        $CheckBoxEnableNewAppPrompt.Visible =$false
        $CheckBoxDisableF8BootMenu.Visible =$false
        $CheckBoxEnableF8BootMenu.Visible =$false
        $CheckBoxSetDEPOptIn.Visible =$false
        $CheckBoxSetDEPOptOut.Visible =$false
}
function FunctionServerShow () {
        $CheckBoxHideServerManagerOnLogin.Visible =$true
        $CheckBoxShowServerManagerOnLogin.Visible =$true
        $CheckBoxDisableShutdownTracker.Visible =$true
        $CheckBoxEnableShutdownTracker.Visible =$true
        $CheckBoxDisablePasswordPolicy.Visible =$true
        $CheckBoxEnablePasswordPolicy.Visible =$true
        $CheckBoxDisableCtrlAltDelLogin.Visible =$true
        $CheckBoxEnableCtrlAltDelLogin.Visible =$true
        $CheckBoxDisableIEEnhancedSecurity.Visible =$true
        $CheckBoxEnableIEEnhancedSecurity.Visible =$true
}
function FunctionServerHide () {
        $CheckBoxHideServerManagerOnLogin.Visible =$false
        $CheckBoxShowServerManagerOnLogin.Visible =$false
        $CheckBoxDisableShutdownTracker.Visible =$false
        $CheckBoxEnableShutdownTracker.Visible =$false
        $CheckBoxDisablePasswordPolicy.Visible =$false
        $CheckBoxEnablePasswordPolicy.Visible =$false
        $CheckBoxDisableCtrlAltDelLogin.Visible =$false
        $CheckBoxEnableCtrlAltDelLogin.Visible =$false
        $CheckBoxDisableIEEnhancedSecurity.Visible =$false
        $CheckBoxEnableIEEnhancedSecurity.Visible =$false
}
function FunctionOtherShow () {
        $CheckBoxDisableAutoMaintenance.Visible =$true
        $CheckBoxEnableAutoMaintenance.Visible =$true
        $CheckBoxDeleteTempFiles.Visible = $true
        $CheckBoxCleanWinSXS.Visible = $true
        $CheckBoxDiskCleanup.Visible = $true
        $CheckBoxSetEasternTime.Visible = $true
        $CheckBoxSetCentralTime.Visible = $true
        $CheckBoxSetMountainTime.Visible = $true
        $CheckBoxSetPacificTime.Visible = $true
        $CheckBoxSyncTimeToInternet.Visible = $true
        $CheckBoxSFCScanNow.Visible = $true
        $CheckBoxWiFiNamePassword.Visible = $true
        $CheckBoxStop11.Visible = $true
        $CheckBoxSetPagingAuto.Visible = $true
        $CheckBoxSetPagingManual.Visible = $true
        $CheckBoxBlock60.Visible = $true
}
function FunctionOtherHide () {
        $CheckBoxDisableAutoMaintenance.Visible =$false
        $CheckBoxEnableAutoMaintenance.Visible =$false
        $CheckBoxDeleteTempFiles.Visible = $false
        $CheckBoxCleanWinSXS.Visible = $false
        $CheckBoxDiskCleanup.Visible = $false
        $CheckBoxSetEasternTime.Visible =$false
        $CheckBoxSetCentralTime.Visible =$false
        $CheckBoxSetMountainTime.Visible = $false
        $CheckBoxSetPacificTime.Visible =$false
        $CheckBoxSyncTimeToInternet.Visible =$false
        $CheckBoxSFCScanNow.Visible =$false
        $CheckBoxWiFiNamePassword.Visible = $false
        $CheckBoxStop11.Visible = $false
        $CheckBoxSetPagingAuto.Visible = $false
        $CheckBoxSetPagingManual.Visible = $false
        $CheckBoxBlock60.Visible = $false
}
function FunctionNiNiteShow () {
        $LabelDocuments.Visible =$true
        $CheckBoxFoxitReader.Visible =$true
        $CheckBoxSumatraPDF.Visible =$true
        $CheckBoxCutePDF.Visible =$true
        $CheckBoxLebreOffice.Visible =$true
        $CheckBoxOpenOffice.Visible =$true
        $LabelWebBrowsers.Visible =$true
        $CheckBoxFireFox.Visible =$true
        $CheckBoxChrome.Visible =$true
        $CheckBoxOpera.Visible =$true
        $LabelTools.Visible =$true
        $CheckBoxFileZilla.Visible =$true
        $CheckBoxNotepad.Visible =$true
        $CheckBox7Zip.Visible =$true
        $CheckBoxPuTTY.Visible =$true
        $CheckBoxVisualStudioCode.Visible =$true
        $CheckBoxWinRAR.Visible =$true
        $CheckBoxTeamViewer.Visible =$true
        $CheckBoxImgBurn.Visible =$true
        $CheckBoxWinDirStat.Visible =$true
        $LabelMedia.Visible =$true
        $CheckBoxVLC.Visible =$true
        $CheckBoxAudacity.Visible =$true
        $CheckBoxSpotify.Visible =$true
        $LabelMessaging.Visible =$true
        $CheckBoxZoom.Visible =$true
        $CheckBoxDiscord.Visible =$true
        $CheckBoxSkype.Visible =$true
        $LabelSecurity.Visible =$true
        $CheckBoxMailwarebytes.Visible =$true
        $CheckBoxAvast.Visible =$true
        $CheckBoxKeePass.Visible =$true
    
}
function FunctionNiNiteHide () {
        $LabelDocuments.Visible =$false
        $CheckBoxFoxitReader.Visible =$false
        $CheckBoxSumatraPDF.Visible =$false
        $CheckBoxCutePDF.Visible =$false
        $CheckBoxLebreOffice.Visible =$false
        $CheckBoxOpenOffice.Visible =$false
        $LabelWebBrowsers.Visible =$false
        $CheckBoxFireFox.Visible =$false
        $CheckBoxChrome.Visible =$false
        $CheckBoxOpera.Visible =$false
        $LabelTools.Visible =$false
        $CheckBoxFileZilla.Visible =$false
        $CheckBoxNotepad.Visible =$false
        $CheckBox7Zip.Visible =$false
        $CheckBoxPuTTY.Visible =$false
        $CheckBoxVisualStudioCode.Visible =$false
        $CheckBoxWinRAR.Visible =$false
        $CheckBoxTeamViewer.Visible =$false
        $CheckBoxImgBurn.Visible =$false
        $CheckBoxWinDirStat.Visible =$false
        $LabelMedia.Visible =$false
        $CheckBoxVLC.Visible =$false
        $CheckBoxAudacity.Visible =$false
        $CheckBoxSpotify.Visible =$false
        $LabelMessaging.Visible =$false
        $CheckBoxZoom.Visible =$false
        $CheckBoxDiscord.Visible =$false
        $CheckBoxSkype.Visible =$false
        $LabelSecurity.Visible =$false
        $CheckBoxMailwarebytes.Visible =$false
        $CheckBoxAvast.Visible =$false
        $CheckBoxKeePass.Visible =$false
}
#---------------------------------------------------------
function FunctionDisableTelemetry () {
    If ($CheckBoxDisableTelemetry.Checked -eq $true) {
        $CheckBoxEnableTelemetry.Checked =$false
    }
}
function FunctionEnableTelemetry () {
    If ($CheckBoxEnableTelemetry.Checked -eq $true) {
        $CheckBoxDisableTelemetry.Checked =$false
    }
}
function FunctionDisableWiFiSense () {
    If ($CheckBoxDisableWiFiSense.Checked -eq $true) {
        $CheckBoxEnableWiFiSense.Checked =$false
    }
}
function FunctionEnableWiFiSense () {
    If ($CheckBoxEnableWiFiSense.Checked -eq $true) {
        $CheckBoxDisableWiFiSense.Checked =$false
    }
}
function FunctionDisableSmartScreen () {    
    If ($CheckBoxDisableSmartScreen.Checked -eq $true) {
        $CheckBoxEnableSmartScreen.Checked =$false
    }
}
function FunctionEnableSmartScreen () {
    If ($CheckBoxEnableSmartScreen.Checked -eq $true) {
        $CheckBoxDisableSmartScreen.Checked =$false
    }
}
function FunctionDisableWebSearch () {
    If ($CheckBoxDisableWebSearch.Checked -eq $true) {
        $CheckBoxEnableWebSearch.Checked =$false
    }
}
function FunctionEnableWebSearch () {
    If ($CheckBoxEnableWebSearch.Checked -eq $true) {
        $CheckBoxDisableWebSearch.Checked =$false
    }
}
function FunctionDisableAppSuggestions () {
    If ($CheckBoxDisableAppSuggestions.Checked -eq $true) {
        $CheckBoxEnableAppSuggestions.Checked =$false
    }
}
function FunctionEnableAppSuggestions () {
    If ($CheckBoxEnableAppSuggestions.Checked -eq $true) {
        $CheckBoxDisableAppSuggestions.Checked =$false
    }
}
function FunctionDisableBackgroundApps () {
    If ($CheckBoxDisableBackgroundApps.Checked -eq $true) {
        $CheckBoxEnableBackgroundApps.Checked =$false
    }
}
function FunctionEnableBackgroundApps () {
    If ($CheckBoxEnableBackgroundApps.Checked -eq $true) {
        $CheckBoxDisableBackgroundApps.Checked =$false
    }
}
function FunctionDisableLockScreenSpotlight () {
    If ($CheckBoxDisableLockScreenSpotlight.Checked -eq $true) {
        $CheckBoxEnableLockScreenSpotlight.Checked =$false
    }
}
function FunctionEnableLockScreenSpotlight () {
    If ($CheckBoxEnableLockScreenSpotlight.Checked -eq $true) {
        $CheckBoxDisableLockScreenSpotlight.Checked =$false
    }
}
function FunctionDisableLocationTracking () {
    If ($CheckBoxDisableLocationTracking.Checked -eq $true) {
        $CheckBoxEnableLocationTracking.Checked =$false
    }
}
function FunctionEnableLocationTracking () {
    If ($CheckBoxEnableLocationTracking.Checked -eq $true) {
        $CheckBoxDisableLocationTracking.Checked =$false
    }
}
function FunctionDisableMapUpdates () {
    If ($CheckBoxDisableMapUpdates.Checked -eq $true) {
        $CheckBoxEnableMapUpdates.Checked =$false
    }
}
function FunctionEnableMapUpdates () {
    If ($CheckBoxEnableMapUpdates.Checked -eq $true) {
        $CheckBoxDisableMapUpdates.Checked =$false
    }
}
function FunctionDisableFeedback () {
    If ($CheckBoxDisableFeedback.Checked -eq $true) {
        $CheckBoxEnableFeedback.Checked =$false
    }
}
function FunctionEnableFeedback () {
    If ($CheckBoxEnableFeedback.Checked -eq $true) {
        $CheckBoxDisableFeedback.Checked =$false
    }
}
function FunctionDisableAdvertisingID () {
    If ($CheckBoxDisableAdvertisingID.Checked -eq $true) {
        $CheckBoxEnableAdvertisingID.Checked =$false
    }
}
function FunctionEnableAdvertisingID () {
    If ($CheckBoxEnableAdvertisingID.Checked -eq $true) {
        $CheckBoxDisableAdvertisingID.Checked =$false
    }
}
function FunctionDisableCortana () {
    If ($CheckBoxDisableCortana.Checked -eq $true) {
        $CheckBoxEnableCortana.Checked =$false
    }
}
function FunctionEnableCortana () {
    If ($CheckBoxEnableCortana.Checked -eq $true) {
        $CheckBoxDisableCortana.Checked =$false
    }
}
function FunctionDisableErrorReporting () {
    If ($CheckBoxDisableErrorReporting.Checked -eq $true) {
        $CheckBoxEnableErrorReporting.Checked =$false
    }
}
function FunctionEnableErrorReporting () {
    If ($CheckBoxEnableErrorReporting.Checked -eq $true) {
        $CheckBoxDisableErrorReporting.Checked =$false
    }
}
function FunctionDisableAutoLogger () {
    If ($CheckBoxDisableAutoLogger.Checked -eq $true) {
        $CheckBoxEnableAutoLogger.Checked =$false
    }
}
function FunctionEnableAutoLogger () {
    If ($CheckBoxEnableAutoLogger.Checked -eq $true) {
        $CheckBoxDisableAutoLogger.Checked =$false
    }
}
function FunctionDisableDiagTrack () {
    If ($CheckBoxDisableDiagTrack.Checked -eq $true) {
        $CheckBoxEnableDiagTrack.Checked =$false
    }
}
function FunctionEnableDiagTrack () {
    If ($CheckBoxEnableDiagTrack.Checked -eq $true) {
        $CheckBoxDisableDiagTrack.Checked =$false
    }
}
function FunctionDisableWAPPush () {
    If ($CheckBoxDisableWAPPush.Checked -eq $true) {
        $CheckBoxEnableWAPPush.Checked =$false
    }
}
function FunctionEnableWAPPush () {
    If ($CheckBoxEnableWAPPush.Checked -eq $true) {
        $CheckBoxDisableWAPPush.Checked =$false
    }
}
function FunctionP2PUpdateLocal () {
    If ($CheckBoxP2PUpdateLocal.Checked -eq $true) {
        $CheckBoxP2PUpdateInternet.Checked =$false
    }
}
function FunctionP2PUpdateInternet () {
    If ($CheckBoxP2PUpdateInternet.Checked -eq $true) {
        $CheckBoxP2PUpdateLocal.Checked =$false
    }
}
function FunctionSetUACLow () {
    If ($CheckBoxSetUACLow.Checked -eq $true) {
        $CheckBoxSetUACHigh.Checked =$false
    }
}
function FunctionSetUACHigh () {
    If ($CheckBoxSetUACHigh.Checked -eq $true) {
        $CheckBoxSetUACLow.Checked =$false
    }
}
function FunctionDisableSharingMappedDrives () {
    If ($CheckBoxDisableSharingMappedDrives.Checked -eq $true) {
        $CheckBoxEnableSharingMappedDrives.Checked =$false
    }
}
function FunctionEnableSharingMappedDrives () {
    If ($CheckBoxEnableSharingMappedDrives.Checked -eq $true) {
        $CheckBoxDisableSharingMappedDrives.Checked =$false
    }
}
function FunctionDisableAdminShares () {
    If ($CheckBoxDisableAdminShares.Checked -eq $true) {
        $CheckBoxEnableAdminShares.Checked =$false
    }
}
function FunctionEnableAdminShares () {
    If ($CheckBoxEnableAdminShares.Checked -eq $true) {
        $CheckBoxDisableAdminShares.Checked =$false
    }
}
function FunctionDisableSMB1 () {
    If ($CheckBoxDisableSMB1.Checked -eq $true) {
        $CheckBoxEnableSMB1.Checked =$false
    }
}
function FunctionEnableSMB1 () {
    If ($CheckBoxEnableSMB1.Checked -eq $true) {
        $CheckBoxDisableSMB1.Checked =$false
    }
}
function FunctionCurrentNetworkPrivate () {
    If ($CheckBoxCurrentNetworkPrivate.Checked -eq $true) {
        $CheckBoxCurrentNetworkPublic.Checked =$false
    }
}
function FunctionCurrentNetworkPublic () {
    If ($CheckBoxCurrentNetworkPublic.Checked -eq $true) {
        $CheckBoxCurrentNetworkPrivate.Checked =$false
    }
}
function FunctionUnknownNetworksPrivate () {
    If ($CheckBoxUnknownNetworksPrivate.Checked -eq $true) {
        $CheckBoxUnknownNetworksPublic.Checked =$false
    }
}
function FunctionUnknownNetworksPublic () {
    If ($CheckBoxUnknownNetworksPublic.Checked -eq $true) {
        $CheckBoxUnknownNetworksPrivate.Checked =$false
    }
}
function FunctionDisableCtrldFolderAccess () {
    If ($CheckBoxDisableCtrldFolderAccess.Checked -eq $true) {
        $CheckBoxEnableCtrldFolderAccess.Checked =$false
    }
}
function FunctionEnableCtrldFolderAccess () {
    If ($CheckBoxEnableCtrldFolderAccess.Checked -eq $true) {
        $CheckBoxDisableCtrldFolderAccess.Checked =$false
    }
}
function FunctionDisableFirewall () {
    If ($CheckBoxDisableFirewall.Checked -eq $true) {
        $CheckBoxEnableFirewall.Checked =$false
    }
}
function FunctionEnableFirewall () {
    If ($CheckBoxEnableFirewall.Checked -eq $true) {
        $CheckBoxDisableFirewall.Checked =$false
    }
}
function FunctionDisableDefender () {
    If ($CheckBoxDisableDefender.Checked -eq $true) {
        $CheckBoxEnableDefender.Checked =$false
    }
}
function FunctionEnableDefender () {
    If ($CheckBoxEnableDefender.Checked -eq $true) {
        $CheckBoxDisableDefender.Checked =$false
    }
}
function FunctionDisableUpdateMSRT () {
    If ($CheckBoxDisableUpdateMSRT.Checked -eq $true) {
        $CheckBoxEnableUpdateMSRT.Checked =$false
    }
}
function FunctionEnableUpdateMSRT () {
    If ($CheckBoxEnableUpdateMSRT.Checked -eq $true) {
        $CheckBoxDisableUpdateMSRT.Checked =$false
    }
}
function FunctionDisableUpdateDriver () {
    If ($CheckBoxDisableUpdateDriver.Checked -eq $true) {
        $CheckBoxEnableUpdateDriver.Checked =$false
    }
}
function FunctionEnableUpdateDriver () {
    If ($CheckBoxEnableUpdateDriver.Checked -eq $true) {
        $CheckBoxDisableUpdateDriver.Checked =$false
    }
}
function FunctionDisableUpdateRestart () {
    If ($CheckBoxDisableUpdateRestart.Checked -eq $true) {
        $CheckBoxEnableUpdateRestart.Checked =$false
    }
}
function FunctionEnableUpdateRestart () {
    If ($CheckBoxEnableUpdateRestart.Checked -eq $true) {
        $CheckBoxDisableUpdateRestart.Checked =$false
    }
}
function FunctionDisableHomeGroups () {
    If ($CheckBoxDisableHomeGroups.Checked -eq $true) {
        $CheckBoxEnableHomeGroups.Checked =$false
    }
}
function FunctionEnableHomeGroups () {
    If ($CheckBoxEnableHomeGroups.Checked -eq $true) {
        $CheckBoxDisableHomeGroups.Checked =$false
    }
}
function FunctionDisableSharedExperiences () {
    If ($CheckBoxDisableSharedExperiences.Checked -eq $true) {
        $CheckBoxEnableSharedExperiences.Checked =$false
    }
}
function FunctionEnableSharedExperiences () {
    If ($CheckBoxEnableSharedExperiences.Checked -eq $true) {
        $CheckBoxDisableSharedExperiences.Checked =$false
    }
}
function FunctionDisableRemoteAssistance () {
    If ($CheckBoxDisableRemoteAssistance.Checked -eq $true) {
        $CheckBoxEnableRemoteAssistance.Checked =$false
    }
}
function FunctionEnableRemoteAssistance () {
    If ($CheckBoxEnableRemoteAssistance.Checked -eq $true) {
        $CheckBoxDisableRemoteAssistance.Checked =$false
    }
}
function FunctionDisableRemoteDesktop () {
    If ($CheckBoxDisableRemoteDesktop.Checked -eq $true) {
        $CheckBoxEnableRemoteDesktop.Checked =$false
    }
}
function FunctionEnableRemoteDesktop () {
    If ($CheckBoxEnableRemoteDesktop.Checked -eq $true) {
        $CheckBoxDisableRemoteDesktop.Checked =$false
    }
}
function FunctionDisableAutoplay () {
    If ($CheckBoxDisableAutoplay.Checked -eq $true) {
        $CheckBoxEnableAutoplay.Checked =$false
    }
}
function FunctionEnableAutoplay () {
    If ($CheckBoxEnableAutoplay.Checked -eq $true) {
        $CheckBoxDisableAutoplay.Checked =$false
    }
}
function FunctionDisableAutorun () {
    If ($CheckBoxDisableAutorun.Checked -eq $true) {
        $CheckBoxEnableAutorun.Checked =$false
    }
}
function FunctionEnableAutorun () {
    If ($CheckBoxEnableAutorun.Checked -eq $true) {
        $CheckBoxDisableAutorun.Checked =$false
    }
}
function FunctionDisableStorageSense () {
    If ($CheckBoxDisableStorageSense.Checked -eq $true) {
        $CheckBoxEnableStorageSense.Checked =$false
    }
}
function FunctionEnableStorageSense () {
    If ($CheckBoxEnableStorageSense.Checked -eq $true) {
        $CheckBoxDisableStorageSense.Checked =$false
    }
}
function FunctionDisableDefragmentation () {
    If ($CheckBoxDisableDefragmentation.Checked -eq $true) {
        $CheckBoxEnableDefragmentation.Checked =$false
    }
}
function FunctionEnableDefragmentation () {
    If ($CheckBoxEnableDefragmentation.Checked -eq $true) {
        $CheckBoxDisableDefragmentation.Checked =$false
    }
}
function FunctionDisableSuperfetch () {
    If ($CheckBoxDisableSuperfetch.Checked -eq $true) {
        $CheckBoxEnableSuperfetch.Checked =$false
    }
}
function FunctionEnableSuperfetch () {
    If ($CheckBoxEnableSuperfetch.Checked -eq $true) {
        $CheckBoxDisableSuperfetch.Checked =$false
    }
}
function FunctionDisableIndexing () {
    If ($CheckBoxDisableIndexing.Checked -eq $true) {
        $CheckBoxEnableIndexing.Checked =$false
    }
}
function FunctionEnableIndexing () {
    If ($CheckBoxEnableIndexing.Checked -eq $true) {
        $CheckBoxDisableIndexing.Checked =$false
    }
}
function FunctionSetBIOSTimeUTC () {
    If ($CheckBoxSetBIOSTimeUTC.Checked -eq $true) {
        $CheckBoxSetBIOSTimeLocal.Checked =$false
    }
}
function FunctionSetBIOSTimeLocal () {
    If ($CheckBoxSetBIOSTimeLocal.Checked -eq $true) {
        $CheckBoxSetBIOSTimeUTC.Checked =$false
    }
}
function FunctionDisableHibernation () {
    If ($CheckBoxDisableHibernation.Checked -eq $true) {
        $CheckBoxEnableHibernation.Checked =$false
    }
}
function FunctionEnableHibernation () {
    If ($CheckBoxEnableHibernation.Checked -eq $true) {
        $CheckBoxDisableHibernation.Checked =$false
    }
}
function FunctionDisableFastStartup () {
    If ($CheckBoxDisableFastStartup.Checked -eq $true) {
        $CheckBoxEnableFastStartup.Checked =$false
    }
}
function FunctionEnableFastStartup () {
    If ($CheckBoxEnableFastStartup.Checked -eq $true) {
        $CheckBoxDisableFastStartup.Checked =$false
    }
}
function FunctionDisableDefenderCloud () {
    If ($CheckBoxDisableDefenderCloud.Checked -eq $true) {
        $CheckBoxEnableDefenderCloud.Checked =$false
    }
}
function FunctionEnableDefenderCloud () {
    If ($CheckBoxEnableDefenderCloud.Checked -eq $true) {
        $CheckBoxDisableDefenderCloud.Checked =$false
    }
}
function FunctionDisableActionCenter () {
	If ($ChechBoxDisableActionCenter.Checked -eq $true) {
		$CheckBoxEnableActionCenter.Checked =$false
	}
}
function FunctionEnableActionCenter () {
	If ($CheckBoxEnableActionCenter.Checked -eq $true) {
		$CheckboxDisableActionCenter.Checked =$false
	}
}
function FunctionDisableLockScreen () {
	If ($CheckBoxDisableLockScreen.Checked -eq $true) {
		$CheckBoxEnableLockScreen.Checked =$false
	}
}
function FunctionEnableLockScreen () {
	If ($CheckBoxEnableLockScreen.Checked -eq $true) {
		$CheckBoxDisableLockScreen.Checked =$false
	}
}
function FunctionHideNetworkOnLockScreen () {
	If ($CheckBoxHideNetworkOnLockScreen.Checked -eq $true) {
		$CheckBoxShowNetworkOnLockScreen.Checked =$false
	}
}
function FunctionShowNetworkOnLockScreen () {
	If ($CheckBoxShowNetworkOnLockScreen.Checked -eq $true) {
		$CheckBoxHideNetworkOnLockScreen.Checked =$false
	}
}
function FunctionHideShutdownFromLockScreen () {
	If ($CheckBoxHideShutdownFromLockScreen.Checked -eq $true) {
		$CheckBoxShowShutdownOnLockScreen.Checked =$false
	}
}
function FunctionShowShutdownOnLockScreen () {
	If ($CheckBoxShowShutdownOnLockScreen.Checked -eq $true) {
		$CheckBoxHideShutdownFromLockScreen.Checked =$false
	}
}
function FunctionDisableStickyKeys () {
	If ($CheckBoxDisableStickyKeys.Checked -eq $true) {
		$CheckBoxEnableStickyKeys.Checked =$false
	}
}
function FunctionEnableStickyKeys () {
	If ($CheckBoxEnableStickyKeys.Checked -eq $true) {
		$CheckBoxDisableStickyKeys.Checked =$false
	}
}
function FunctionShowTaskManagerDetails () {
	If ($CheckBoxShowTaskManagerDetails.Checked -eq $true) {
		$CheckBoxHideTaskManagerDetails.Checked =$false
	}
}
function FunctionHideTaskManagerDetails () {
	If ($CheckBoxHideTaskManagerDetails.Checked -eq $true) {
		$CheckBoxShowTaskManagerDetails.Checked =$false
	}
}
function FunctionShowFileOperationsDetails () {
	If ($CheckBoxShowFileOperationsDetails.Checked -eq $true) {
		$CheckBoxHideFileOperationsDetails.Checked =$false
	}
}
function FunctionHideFileOperationsDetails () {
	If ($CheckBoxHideFileOperationsDetails.Checked -eq $true) {
		$CheckBoxShowFileOperationsDetails.Checked =$false
	}
}
function FunctionDisableFileDeleteConfirm () {
	If ($CheckBoxDisableFileDeleteConfirm.Checked -eq $true) {
		$CheckBoxEnableFileDeleteConfirm.Checked =$false
	}
}
function FunctionEnableFileDeleteConfirm () {
	If ($CheckBoxEnableFileDeleteConfirm.Checked -eq $true) {
		$CheckBoxDisableFileDeleteConfirm.Checked =$false
	}
}
function FunctionShowTaskbarSearchBox () {
	If ($CheckBoxShowTaskbarSearchBox.Checked -eq $true) {
		$CheckBoxHideTaskbarSearchBox.Checked =$false
	}
}
function FunctionHideTaskbarSearchBox () {
	If ($CheckBoxHideTaskbarSearchBox.Checked -eq $true) {
		$CheckBoxShowTaskbarSearchBox.Checked =$false
	}
}
function FunctionShowTaskView () {
	If ($CheckBoxShowTaskView.Checked -eq $true) {
		$CheckBoxHideTaskView.Checked =$false
	}
}
function FunctionHideTaskView () {
	If ($CheckBoxHideTaskView.Checked -eq $true) {
		$CheckBoxShowTaskView.Checked =$false
	}
}
function FunctionSmallTaskbarIcons () {
	If ($CheckBoxSmallTaskbarIcons.Checked -eq $true) {
		$CheckBoxLargeTaskbarIcons.Checked =$false
	}
}
function FunctionLargeTaskbarIcons () {
	If ($CheckBoxLargeTaskbarIcons.Checked -eq $true) {
		$CheckBoxSmallTaskbarIcons.Checked =$false
	}
}
function FunctionShowTaskbarTitles () {
	If ($CheckBoxShowTaskbarTitles.Checked -eq $true) {
		$CheckBoxHideTaskbarTitles.Checked =$false
	}
}
function FunctionHideTaskbarTitles () {
	If ($CheckBoxHideTaskbarTitles.Checked -eq $true) {
		$CheckBoxShowTaskbarTitles.Checked =$false
	}
}
function FunctionShowTaskbarPeopleIcon () {
	If ($CheckBoxShowTaskbarPeopleIcon.Checked -eq $true) {
		$CheckBoxHideTaskbarPeopleIcon.Checked =$false
	}
}
function FunctionHideTaskbarPeopleIcon () {
	If ($CheckBoxHideTaskbarPeopleIcon.Checked -eq $true) {
		$CheckBoxShowTaskbarPeopleIcon.Checked =$false
	}
}
function FunctionShowTrayIcons () {
	If ($CheckBoxShowTrayIcons.Checked -eq $true) {
		$CheckBoxHideTrayIcons.Checked =$false
	}
}
function FunctionHideTrayIcons () {
	If ($CheckBoxHideTrayIcons.Checked -eq $true) {
		$CheckBoxShowTrayIcons.Checked =$false
	}
}
function FunctionShowKnownExtensions () {
	If ($CheckBoxShowKnownExtensions.Checked -eq $true) {
		$CheckBoxHideKnownExtensions.Checked =$false
	}
}
function FunctionHideKnownExtensions () {
	If ($CheckBoxHideKnownExtensions.Checked -eq $true) {
		$CheckBoxShowKnownExtensions.Checked =$false
	}
}
function FunctionShowHiddenFiles () {
	If ($CheckBoxShowHiddenFiles.Checked -eq $true) {
		$CheckBoxHideHiddenFiles.Checked =$false
	}
}
function FunctionHideHiddenFiles () {
	If ($CheckBoxHideHiddenFiles.Checked -eq $true) {
		$CheckBoxShowHiddenFiles.Checked =$false
	}
}
function FunctionShowSyncNotifications () {
	If ($CheckBoxShowSyncNotifications.Checked -eq $true) {
		$CheckBoxHideSyncNotifications.Checked =$false
	}
}
function FunctionHideSyncNotifications () {
	If ($CheckBoxHideSyncNotifications.Checked -eq $true) {
		$CheckBoxShowSyncNotifications.Checked =$false
	}
}
function FunctionShowRecentShortcuts () {
	If ($CheckBoxShowRecentShortcuts.Checked -eq $true) {
		$CheckBoxHideRecentShortcuts.Checked =$false
	}
}
function FunctionHideRecentShortcuts () {
	If ($CheckBoxHideRecentShortcuts.Checked -eq $true) {
		$CheckBoxShowRecentShortcuts.Checked =$false
	}
}
function FunctionSetExplorerQuickAccess () {
	If ($CheckBoxSetExplorerQuickAccess.Checked -eq $true) {
		$CheckBoxSetExplorerThisPC.Checked =$false
	}
}
function FunctionSetExplorerThisPC () {
	If ($CheckBoxSetExplorerThisPC.Checked -eq $true) {
		$CheckBoxSetExplorerQuickAccess.Checked =$false
	}
}
function FunctionShowThisPCOnDesktop () {
	If ($CheckBoxShowThisPCOnDesktop.Checked -eq $true) {
		$CheckBoxHideThisPCFromDesktop.Checked =$false
	}
}
function FunctionHideThisPCFromDesktop () {
	If ($CheckBoxHideThisPCFromDesktop.Checked -eq $true) {
		$CheckBoxShowThisPCOnDesktop.Checked =$false
	}
}
function FunctionShowDesktopInThisPC () {
	If ($CheckBoxShowDesktopInThisPC.Checked -eq $true) {
		$CheckBoxHideDesktopFromThisPC.Checked =$false
	}
}
function FunctionHideDesktopFromThisPC () {
	If ($CheckBoxHideDesktopFromThisPC.Checked -eq $true) {
		$CheckBoxShowDesktopInThisPC.Checked =$false
	}
}
function FunctionShowDocumentsInThisPC () {
	If ($CheckBoxShowDocumentsInThisPC.Checked -eq $true) {
		$CheckBoxHideDocumentsFromThisPC.Checked =$false
	}
}
function FunctionHideDocumentsFromThisPC () {
	If ($CheckBoxHideDocumentsFromThisPC.Checked -eq $true) {
		$CheckBoxShowDocumentsInThisPC.Checked =$false
	}
}
function FunctionShowDownloadsInThisPC () {
	If ($CheckBoxShowDownloadsInThisPC.Checked -eq $true) {
		$CheckBoxHideDownloadsFromThisPC.Checked =$false
	}
}
function FunctionHideDownloadsFromThisPC () {
	If ($CheckBoxHideDownloadsFromThisPC.Checked -eq $true) {
		$CheckBoxShowDownloadsInThisPC.Checked =$false
	}
}
function FunctionShowMusicInThisPC () {
	If ($CheckBoxShowMusicInThisPC.Checked -eq $true) {
		$CheckBoxHideMusicFromThisPC.Checked =$false
	}
}
function FunctionHideMusicFromThisPC () {
	If ($CheckBoxHideMusicFromThisPC.Checked -eq $true) {
		$CheckBoxShowMusicInThisPC.Checked =$false
	}
}
function FunctionShowPicturesInThisPC () {
	If ($CheckBoxShowPicturesInThisPC.Checked -eq $true) {
		$CheckBoxHidePicturesFromThisPC.Checked =$false
	}
}
function FunctionHidePicturesFromThisPC () {
	If ($CheckBoxHidePicturesFromThisPC.Checked -eq $true) {
		$CheckBoxShowPicturesInThisPC.Checked =$false
	}
}
function FunctionShowVideosInThisPC () {
	If ($CheckBoxShowVideosInThisPC.Checked -eq $true) {
		$CheckBoxHideVideosFromThisPC.Checked =$false
	}
}
function FunctionHideVideosFromThisPC () {
	If ($CheckBoxHideVideosFromThisPC.Checked -eq $true) {
		$CheckBoxShowVideosInThisPC.Checked =$false
	}
}
function FunctionShow3DObjectsInThisPC () {
	If ($CheckBoxShow3DObjectsInThisPC.Checked -eq $true) {
		$CheckBoxHide3DObjectsFromThisPC.Checked =$false
	}
}
function FunctionHide3DObjectsFromThisPC () {
	If ($CheckBoxHide3DObjectsFromThisPC.Checked -eq $true) {
		$CheckBoxShow3DObjectsInThisPC.Checked =$false
	}
}
function FunctionSetVisualFXPerformance () {
	If ($CheckBoxSetVisualFXPerformance.Checked -eq $true) {
		$CheckBoxSetVisualFXAppearance.Checked =$false
	}
}
function FunctionSetVisualFXAppearance () {
	If ($CheckBoxSetVisualFXAppearance.Checked -eq $true) {
		$CheckBoxSetVisualFXPerformance.Checked =$false
	}
}
function FunctionEnableThumbnails () {
	If ($CheckBoxEnableThumbnails.Checked -eq $true) {
		$CheckBoxDisableThumbnails.Checked =$false
	}
}
function FunctionDisableThumbnails () {
	If ($CheckBoxDisableThumbnails.Checked -eq $true) {
		$CheckBoxEnableThumbnails.Checked =$false
	}
}
function FunctionDisableThumbsDB () {
	If ($CheckBoxDisableThumbsDB.Checked -eq $true) {
		$CheckBoxEnableThumbsDB.Checked =$false
	}
}
function FunctionEnableThumbsDB () {
	If ($CheckBoxEnableThumbsDB.Checked -eq $true) {
		$CheckBoxDisableThumbsDB.Checked =$false
	}
}
function FunctionAddENKeyboard () {
	If ($CheckBoxAddENKeyboard.Checked -eq $true) {
		$CheckBoxRemoveENKeyboard.Checked =$false
	}
}
function FunctionRemoveENKeyboard () {
	If ($CheckBoxRemoveENKeyboard.Checked -eq $true) {
		$CheckBoxAddENKeyboard.Checked =$false
	}
}
function FunctionDisableNumlock () {
	If ($CheckBoxDisableNumlock.Checked -eq $true) {
		$CheckBoxEnableNumlock.Checked =$false
	}
}
function FunctionEnableNumlock () {
	If ($CheckBoxEnableNumlock.Checked -eq $true) {
		$CheckBoxDisableNumlock.Checked =$false
	}
}
function FunctionDisableOneDrive () {
	If ($CheckBoxDisableOneDrive.Checked -eq $true) {
		$CheckBoxEnableOneDrive.Checked =$false
	}
}
function FunctionEnableOneDrive () {
	If ($CheckBoxEnableOneDrive.Checked -eq $true) {
		$CheckBoxDisableOneDrive.Checked =$false
	}
}
function FunctionUninstallOneDrive () {
	If ($CheckBoxUninstallOneDrive.Checked -eq $true) {
		$CheckBoxInstallOneDrive.Checked =$false
	}
}
function FunctionInstallOneDrive () {
	If ($CheckBoxInstallOneDrive.Checked -eq $true) {
		$CheckBoxUninstallOneDrive.Checked =$false
	}
}
function FunctionUninstallMsftBloat () {
	If ($CheckBoxUninstallMsftBloat.Checked -eq $true) {
		$CheckBoxInstallMsftBloat.Checked =$false
	}
}
function FunctionInstallMsftBloat () {
	If ($CheckBoxInstallMsftBloat.Checked -eq $true) {
		$CheckBoxUninstallMsftBloat.Checked =$false
	}
}
function FunctionUninstallThirdPartyBloat () {
	If ($CheckBoxUninstallThirdPartyBloat.Checked -eq $true) {
		$CheckBoxInstallThirdPartyBloat.Checked =$false
	}
}
function FunctionInstallThirdPartyBloat () {
	If ($CheckBoxInstallThirdPartyBloat.Checked -eq $true) {
		$CheckBoxUninstallThirdPartyBloat.Checked =$false
	}
}
function FunctionUninstallWindowsStore () {
	If ($CheckBoxUninstallWindowsStore.Checked -eq $true) {
		$CheckBoxInstallWindowsStore.Checked =$false
	}
}
function FunctionInstallWindowsStore () {
	If ($CheckBoxInstallWindowsStore.Checked -eq $true) {
		$CheckBoxUninstallWindowsStore.Checked =$false
	}
}
function FunctionDisableXboxFeatures () {
	If ($CheckBoxDisableXboxFeatures.Checked -eq $true) {
		$CheckBoxEnableXboxFeatures.Checked =$false
	}
}
function FunctionEnableXboxFeatures () {
	If ($CheckBoxEnableXboxFeatures.Checked -eq $true) {
		$CheckBoxDisableXboxFeatures.Checked =$false
	}
}
function FunctionDisableAdobeFlash () {
	If ($CheckBoxDisableAdobeFlash.Checked -eq $true) {
		$CheckBoxEnableAdobeFlash.Checked =$false
	}
}
function FunctionEnableAdobeFlash () {
	If ($CheckBoxEnableAdobeFlash.Checked -eq $true) {
		$CheckBoxDisableAdobeFlash.Checked =$false
	}
}
function FunctionUninstallMediaPlayer () {
	If ($CheckBoxUninstallMediaPlayer.Checked -eq $true) {
		$CheckBoxInstallMediaPlayer.Checked =$false
	}
}
function FunctionInstallMediaPlayer () {
	If ($CheckBoxInstallMediaPlayer.Checked -eq $true) {
		$CheckBoxUninstallMediaPlayer.Checked =$false
	}
}
function FunctionUninstallWorkFolders () {
	If ($CheckBoxUninstallWorkFolders.Checked -eq $true) {
		$CheckBoxInstallWorkFolders.Checked =$false
	}
}
function FunctionInstallWorkFolders () {
	If ($CheckBoxInstallWorkFolders.Checked -eq $true) {
		$CheckBoxUninstallWorkFolders.Checked =$false
	}
}
function FunctionUninstallLinuxSubsystem () {
	If ($CheckBoxUninstallLinuxSubsystem.Checked -eq $true) {
		$CheckBoxInstallLinuxSubsystem.Checked =$false
	}
}
function FunctionInstallLinuxSubsystem () {
	If ($CheckBoxInstallLinuxSubsystem.Checked -eq $true) {
		$CheckBoxUninstallLinuxSubsystem.Checked =$false
	}
}
function FunctionUninstallHyperV () {
	If ($CheckBoxUninstallHyperV.Checked -eq $true) {
		$CheckBoxInstallHyperV.Checked =$false
	}
}
function FunctionInstallHyperV () {
	If ($CheckBoxInstallHyperV.Checked -eq $true) {
		$CheckBoxUninstallHyperV.Checked =$false
	}
}
function FunctionSetPhotoViewerAssociation () {
	If ($CheckBoxSetPhotoViewerAssociation.Checked -eq $true) {
		$CheckBoxUnsetPhotoViewerAssociation.Checked =$false
	}
}
function FunctionUnsetPhotoViewerAssociation () {
	If ($CheckBoxUnsetPhotoViewerAssociation.Checked -eq $true) {
		$CheckBoxSetPhotoViewerAssociation.Checked =$false
	}
}
function FunctionAddPhotoViewerOpenWith () {
	If ($CheckBoxAddPhotoViewerOpenWith.Checked -eq $true) {
		$CheckBoxRemovePhotoViewerOpenWith.Checked =$false
	}
}
function FunctionRemovePhotoViewerOpenWith () {
	If ($CheckBoxRemovePhotoViewerOpenWith.Checked -eq $true) {
		$CheckBoxAddPhotoViewerOpenWith.Checked =$false
	}
}
function FunctionDisableSearchAppInStore () {
	If ($CheckBoxDisableSearchAppInStore.Checked -eq $true) {
		$CheckBoxEnableSearchAppInStore.Checked =$false
	}
}
function FunctionEnableSearchAppInStore () {
	If ($CheckBoxEnableSearchAppInStore.Checked -eq $true) {
		$CheckBoxDisableSearchAppInStore.Checked =$false
	}
}
function FunctionDisableNewAppPrompt () {
	If ($CheckBoxDisableNewAppPrompt.Checked -eq $true) {
		$CheckBoxEnableNewAppPrompt.Checked =$false
	}
}
function FunctionEnableNewAppPrompt () {
	If ($CheckBoxEnableNewAppPrompt.Checked -eq $true) {
		$CheckBoxDisableNewAppPrompt.Checked =$false
	}
}
function FunctionDisableF8BootMenu () {
	If ($CheckBoxDisableF8BootMenu.Checked -eq $true) {
		$CheckBoxEnableF8BootMenu.Checked =$false
	}
}
function FunctionEnableF8BootMenu () {
	If ($CheckBoxEnableF8BootMenu.Checked -eq $true) {
		$CheckBoxDisableF8BootMenu.Checked =$false
	}
}
function FunctionSetDEPOptIn () {
	If ($CheckBoxSetDEPOptIn.Checked -eq $true) {
		$CheckBoxSetDEPOptOut.Checked =$false
	}
}
function FunctionSetDEPOptOut () {
	If ($CheckBoxSetDEPOptOut.Checked -eq $true) {
		$CheckBoxSetDEPOptIn.Checked =$false
	}
}
function FunctionHideServerManagerOnLogin () {
	If ($CheckBoxHideServerManagerOnLogin.Checked -eq $true) {
		$CheckBoxShowServerManagerOnLogin.Checked =$false
	}
}
function FunctionShowServerManagerOnLogin () {
	If ($CheckBoxShowServerManagerOnLogin.Checked -eq $true) {
		$CheckBoxHideServerManagerOnLogin.Checked =$false
	}
}
function FunctionDisableShutdownTracker () {
	If ($CheckBoxDisableShutdownTracker.Checked -eq $true) {
		$CheckBoxEnableShutdownTracker.Checked =$false
	}
}
function FunctionEnableShutdownTracker () {
	If ($CheckBoxEnableShutdownTracker.Checked -eq $true) {
		$CheckBoxDisableShutdownTracker.Checked =$false
	}
}
function FunctionDisablePasswordPolicy () {
	If ($CheckBoxDisablePasswordPolicy.Checked -eq $true) {
		$CheckBoxEnablePasswordPolicy.Checked =$false
	}
}
function FunctionEnablePasswordPolicy () {
	If ($CheckBoxEnablePasswordPolicy.Checked -eq $true) {
		$CheckBoxDisablePasswordPolicy.Checked =$false
	}
}
function FunctionDisableCtrlAltDelLogin () {
	If ($CheckBoxDisableCtrlAltDelLogin.Checked -eq $true) {
		$CheckBoxEnableCtrlAltDelLogin.Checked =$false
	}
}
function FunctionEnableCtrlAltDelLogin () {
	If ($CheckBoxEnableCtrlAltDelLogin.Checked -eq $true) {
		$CheckBoxDisableCtrlAltDelLogin.Checked =$false
	}
}
function FunctionDisableIEEnhancedSecurity () {
	If ($CheckBoxDisableIEEnhancedSecurity.Checked -eq $true) {
		$CheckBoxEnableIEEnhancedSecurity.Checked =$false
	}
}
function FunctionEnableIEEnhancedSecurity () {
	If ($CheckBoxEnableIEEnhancedSecurity.Checked -eq $true) {
		$CheckBoxDisableIEEnhancedSecurity.Checked =$false
	}
}
function FunctionDisableAutoMaintenance () {        
    If ($CheckBoxDisableAutoMaintenance.checked -eq $true) {
        $CheckBoxEnableAutoMaintenance.checked = $false
    }
}
function FunctionEnableAutoMaintenance () {        
    If ($CheckBoxEnableAutoMaintenance.checked -eq $true) {
        $CheckBoxDisableAutoMaintenance.checked = $false
    }
}
function FunctionSetEasternTime () {
	If ($CheckBoxSetEasternTime.checked -eq $true) {
		$CheckBoxSetCentralTime.checked = $flase
        $CheckBoxSetMountainTime.checked = $flase
        $CheckBoxSetPacificTime.checked = $flase
	}
}
function FunctionSetCentralTime () {
	If ($CheckBoxSetCentralTime.checked -eq $true) {
		$CheckBoxSetEasternTime.checked = $flase
        $CheckBoxSetMountainTime.checked = $flase
        $CheckBoxSetPacificTime.checked = $flase
	}
}
function FunctionSetMountainTime () {
	If ($CheckBoxSetMountainTime.checked -eq $true) {
		$CheckBoxSetEasternTime.checked = $flase
		$CheckBoxSetCentralTime.checked = $flase
        $CheckBoxSetPacificTime.checked = $flase
	}
}
function FunctionSetPacificTime () {
	If ($CheckBoxSetPacificTime.checked -eq $true) {
		$CheckBoxSetEasternTime.checked = $flase
        $CheckBoxSetCentralTime.checked = $flase
        $CheckBoxSetMountainTime.checked = $flase
	}
}

function FunctionEnableMulticasting () {
 	If ($CheckBoxEnableMulticasting.Checked -eq $true) {
		$CheckBoxDisableMulticasting.Checked =$false
	}
}

function FunctionDisableMulticasting () {
    If ($CheckBoxDisableMulticasting.Checked -eq $true) {
		$CheckBoxEnableMulticasting.Checked =$false
	}
}

function FunctionSetPagingAuto () {
 	If ($CheckBoxSetPagingAuto.Checked -eq $true) {
		$CheckBoxSetPagingManual.Checked =$false
	}
}

function FunctionSetPagingManual () {
    If ($CheckBoxSetPagingManual.Checked -eq $true) {
		$CheckBoxSetPagingAuto.Checked =$false
	}
}

function FunctionEnableIPV6 () {
 	If ($CheckBoxEnableIPV6.Checked -eq $true) {
		$CheckBoxDisableIPV6.Checked =$false
	}
}

function FunctionDisableIPV6 () {
    If ($CheckBoxDisableIPV6.Checked -eq $true) {
		$CheckBoxEnableIPV6.Checked =$false
	}
}

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$FormBackupTool                  = New-Object system.Windows.Forms.Form
$FormBackupTool.ClientSize       = '680,120'
$FormBackupTool.text             = "Windows 10 Optimzer"
$FormBackupTool.TopMost          = $false

$CheckBoxAutoSelect                      = New-Object system.Windows.Forms.CheckBox
$CheckBoxAutoSelect.text                 = "Auto Select Options"
$CheckBoxAutoSelect.location             = New-Object System.Drawing.Point(10,10)
$CheckBoxAutoSelect.width                = 150
$CheckBoxAutoSelect.height               = 20
$CheckBoxAutoSelect.AutoSize             = $false
$CheckBoxAutoSelect.Font                 = 'Microsoft Sans Serif,10'
$CheckBoxAutoSelect.checked              = $true
$CheckBoxAutoSelect.Visible              = $true
$CheckBoxAutoSelect.Enabled              = $true

$CheckBoxAdvancedSelect                  = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSelect.text             = "Advanced Options"
$CheckBoxAdvancedSelect.location         = New-Object System.Drawing.Point(160,10)
$CheckBoxAdvancedSelect.width            = 150
$CheckBoxAdvancedSelect.height           = 20
$CheckBoxAdvancedSelect.AutoSize         = $false
$CheckBoxAdvancedSelect.Font             = 'Microsoft Sans Serif,10'
$CheckBoxAdvancedSelect.checked          = $false
$CheckBoxAdvancedSelect.Visible          = $true
$CheckBoxAdvancedSelect.Enabled          = $true

#--------------------------------------------------------

$CheckBoxQuickClean                      = New-Object system.Windows.Forms.CheckBox
$CheckBoxQuickClean.text                 = "Quick Clean"
$CheckBoxQuickClean.location             = New-Object System.Drawing.Point(10,30)
$CheckBoxQuickClean.width                = 120
$CheckBoxQuickClean.height               = 20
$CheckBoxQuickClean.AutoSize             = $false
$CheckBoxQuickClean.Font                 = 'Microsoft Sans Serif,10'
$CheckBoxQuickClean.checked              = $true
$CheckBoxQuickClean.Visible              = $true
$CheckBoxQuickClean.Enabled              = $true

$CheckBoxDeepClean                       = New-Object system.Windows.Forms.CheckBox
$CheckBoxDeepClean.text                  = "Deep Clean"
$CheckBoxDeepClean.location              = New-Object System.Drawing.Point(130,30)
$CheckBoxDeepClean.width                 = 120
$CheckBoxDeepClean.height                = 20
$CheckBoxDeepClean.AutoSize              = $false
$CheckBoxDeepClean.Font                  = 'Microsoft Sans Serif,10'
$CheckBoxDeepClean.checked               = $false
$CheckBoxDeepClean.Visible               = $true
$CheckBoxDeepClean.Enabled               = $true

$CheckBoxNewComputer                     = New-Object system.Windows.Forms.CheckBox
$CheckBoxNewComputer.text                = "New Computer"
$CheckBoxNewComputer.location            = New-Object System.Drawing.Point(250,30)
$CheckBoxNewComputer.width               = 120
$CheckBoxNewComputer.height              = 20
$CheckBoxNewComputer.AutoSize            = $false
$CheckBoxNewComputer.Font                = 'Microsoft Sans Serif,10'
$CheckBoxNewComputer.checked             = $false
$CheckBoxNewComputer.Visible             = $true
$CheckBoxNewComputer.Enabled             = $true

$CheckBoxServer                          = New-Object system.Windows.Forms.CheckBox
$CheckBoxServer.text                     = "Server"
$CheckBoxServer.location                 = New-Object System.Drawing.Point(370,30)
$CheckBoxServer.width                    = 120
$CheckBoxServer.height                   = 20
$CheckBoxServer.AutoSize                 = $false
$CheckBoxServer.Font                     = 'Microsoft Sans Serif,10'
$CheckBoxServer.checked                  = $false
$CheckBoxServer.Visible                  = $true
$CheckBoxServer.Enabled                  = $true

$CheckBoxClearAll                     = New-Object system.Windows.Forms.CheckBox
$CheckBoxClearAll.text                = "Clear All"
$CheckBoxClearAll.location            = New-Object System.Drawing.Point(490,30)
$CheckBoxClearAll.width               = 120
$CheckBoxClearAll.height              = 20
$CheckBoxClearAll.AutoSize            = $false
$CheckBoxClearAll.Font                = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxClearAll.checked             = $false
$CheckBoxClearAll.Visible             = $false
$CheckBoxClearAll.Enabled             = $true

#--------------------------------------------------------

$ButtonStart                             = New-Object system.Windows.Forms.Button
$ButtonStart.text                        = "Start"
$ButtonStart.location                    = New-Object System.Drawing.Point(10,60)
$ButtonStart.width                       = 116
$ButtonStart.height                      = 30
$ButtonStart.BackColor                   = "#417505"
$ButtonStart.Font                        = 'Microsoft Sans Serif,12,style=Bold'

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-

$CheckBoxAdvancedSectionPrivace                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSectionPrivace.text               = "Privacy"
$CheckBoxAdvancedSectionPrivace.location           = New-Object System.Drawing.Point(10,105)
$CheckBoxAdvancedSectionPrivace.AutoSize           = $true
$CheckBoxAdvancedSectionPrivace.width              = 150
$CheckBoxAdvancedSectionPrivace.height             = 20
$CheckBoxAdvancedSectionPrivace.Font               = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxAdvancedSectionPrivace.checked            = $false
$CheckBoxAdvancedSectionPrivace.Visible            = $false
$CheckBoxAdvancedSectionPrivace.Enabled            = $true

$CheckBoxAdvancedSectionServices                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSectionServices.text               = "Services"
$CheckBoxAdvancedSectionServices.location           = New-Object System.Drawing.Point(100,105)
$CheckBoxAdvancedSectionServices.AutoSize           = $true
$CheckBoxAdvancedSectionServices.width              = 150
$CheckBoxAdvancedSectionServices.height             = 20
$CheckBoxAdvancedSectionServices.Font               = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxAdvancedSectionServices.checked             = $false
$CheckBoxAdvancedSectionServices.Visible             = $false
$CheckBoxAdvancedSectionServices.Enabled             = $true

$CheckBoxAdvancedSectionUI                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSectionUI.text               = "UI"
$CheckBoxAdvancedSectionUI.location           = New-Object System.Drawing.Point(190,105)
$CheckBoxAdvancedSectionUI.AutoSize           = $true
$CheckBoxAdvancedSectionUI.width              = 150
$CheckBoxAdvancedSectionUI.height             = 20
$CheckBoxAdvancedSectionUI.Font               = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxAdvancedSectionUI.checked             = $false
$CheckBoxAdvancedSectionUI.Visible             = $false
$CheckBoxAdvancedSectionUI.Enabled             = $true

$CheckBoxAdvancedSectionApp                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSectionApp.text               = "Application"
$CheckBoxAdvancedSectionApp.location           = New-Object System.Drawing.Point(250,105)
$CheckBoxAdvancedSectionApp.AutoSize           = $true
$CheckBoxAdvancedSectionApp.width              = 100
$CheckBoxAdvancedSectionApp.height             = 20
$CheckBoxAdvancedSectionApp.Font               = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxAdvancedSectionApp.checked             = $false
$CheckBoxAdvancedSectionApp.Visible             = $false
$CheckBoxAdvancedSectionApp.Enabled             = $true

$CheckBoxAdvancedSectionServer                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSectionServer.text               = "Server"
$CheckBoxAdvancedSectionServer.location           = New-Object System.Drawing.Point(360,105)
$CheckBoxAdvancedSectionServer.AutoSize           = $true
$CheckBoxAdvancedSectionServer.width              = 100
$CheckBoxAdvancedSectionServer.height             = 20
$CheckBoxAdvancedSectionServer.Font               = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxAdvancedSectionServer.checked             = $false
$CheckBoxAdvancedSectionServer.Visible             = $false
$CheckBoxAdvancedSectionServer.Enabled             = $true

$CheckBoxAdvancedSectionOther                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSectionOther.text               = "Other"
$CheckBoxAdvancedSectionOther.location           = New-Object System.Drawing.Point(450,105)
$CheckBoxAdvancedSectionOther.AutoSize           = $true
$CheckBoxAdvancedSectionOther.width              = 100
$CheckBoxAdvancedSectionOther.height             = 20
$CheckBoxAdvancedSectionOther.Font               = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxAdvancedSectionOther.checked             = $false
$CheckBoxAdvancedSectionOther.Visible             = $false
$CheckBoxAdvancedSectionOther.Enabled             = $true

$CheckBoxAdvancedSectionNiNite                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxAdvancedSectionNiNite.text               = "NiNite"
$CheckBoxAdvancedSectionNiNite.location           = New-Object System.Drawing.Point(540,105)
$CheckBoxAdvancedSectionNiNite.AutoSize           = $true
$CheckBoxAdvancedSectionNiNite.width              = 100
$CheckBoxAdvancedSectionNiNite.height             = 20
$CheckBoxAdvancedSectionNiNite.Font               = 'Microsoft Sans Serif,10,style=Bold'
$CheckBoxAdvancedSectionNiNite.checked             = $false
$CheckBoxAdvancedSectionNiNite.Visible             = $false
$CheckBoxAdvancedSectionNiNite.Enabled             = $true

$TextBoxOutput                   = New-Object system.Windows.Forms.TextBox
$TextBoxOutput.multiline         = $true
$TextBoxOutput.width             = 640
$TextBoxOutput.height            = 440
$TextBoxOutput.location          = New-Object System.Drawing.Point(10,130)
$TextBoxOutput.Font              = 'Microsoft Sans Serif,10'
$TextBoxOutput.ScrollBars        ='Vertical'
$TextBoxOutput.Visible           = $false

#--PRIVACY--###########################################################################################################################################################################################

#--Disable--Enable--Telemetry
# DisableTelemetry EnableTelemetry

$CheckBoxDisableTelemetry                = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableTelemetry.text           = "Disable "
$CheckBoxDisableTelemetry.location       = New-Object System.Drawing.Point(10,130)
$CheckBoxDisableTelemetry.width          = 100
$CheckBoxDisableTelemetry.height         = 20
$CheckBoxDisableTelemetry.AutoSize       = $false
$CheckBoxDisableTelemetry.Font           = 'Microsoft Sans Serif,10'
$CheckBoxDisableTelemetry.checked        = $true
$CheckBoxDisableTelemetry.Visible        = $false
$CheckBoxDisableTelemetry.Enabled        = $true

$CheckBoxEnableTelemetry                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableTelemetry.text            = "Enable Telemetry"
$CheckBoxEnableTelemetry.location        = New-Object System.Drawing.Point(110,130)
$CheckBoxEnableTelemetry.width           = 600
$CheckBoxEnableTelemetry.height          = 20
$CheckBoxEnableTelemetry.AutoSize        = $false
$CheckBoxEnableTelemetry.Font            = 'Microsoft Sans Serif,10'
$CheckBoxEnableTelemetry.checked         = $false
$CheckBoxEnableTelemetry.Visible         = $false
$CheckBoxEnableTelemetry.Enabled         = $true

#--Disable--Enable--WiFi Sense
# DisableensWiFiSe EnableWiFiSense

$CheckBoxDisableWiFiSense                = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableWiFiSense.text           = "Disable "
$CheckBoxDisableWiFiSense.location       = New-Object System.Drawing.Point(10,150)
$CheckBoxDisableWiFiSense.width          = 100
$CheckBoxDisableWiFiSense.height         = 20
$CheckBoxDisableWiFiSense.AutoSize       = $false
$CheckBoxDisableWiFiSense.Font           = 'Microsoft Sans Serif,10'
$CheckBoxDisableWiFiSense.checked        = $true
$CheckBoxDisableWiFiSense.Visible        = $false
$CheckBoxDisableWiFiSense.Enabled        = $true

$CheckBoxEnableWiFiSense                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableWiFiSense.text            = "Enable WiFi Sense"
$CheckBoxEnableWiFiSense.location        = New-Object System.Drawing.Point(110,150)
$CheckBoxEnableWiFiSense.width           = 600
$CheckBoxEnableWiFiSense.height          = 20
$CheckBoxEnableWiFiSense.AutoSize        = $false
$CheckBoxEnableWiFiSense.Font            = 'Microsoft Sans Serif,10'
$CheckBoxEnableWiFiSense.checked         = $false
$CheckBoxEnableWiFiSense.Visible         = $false
$CheckBoxEnableWiFiSense.Enabled         = $true

#--Disable--Enable--Smart Screen
# DisableSmartScreen EnableSmartScreen

$CheckBoxDisableSmartScreen              = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableSmartScreen.text         = "Disable "
$CheckBoxDisableSmartScreen.location     = New-Object System.Drawing.Point(10,170)
$CheckBoxDisableSmartScreen.width        = 100
$CheckBoxDisableSmartScreen.height       = 20
$CheckBoxDisableSmartScreen.AutoSize     = $false
$CheckBoxDisableSmartScreen.Font         = 'Microsoft Sans Serif,10'
$CheckBoxDisableSmartScreen.checked      = $true
$CheckBoxDisableSmartScreen.Visible      = $false
$CheckBoxDisableSmartScreen.Enabled      = $true

$CheckBoxEnableSmartScreen               = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableSmartScreen.text          = "Enable Smart Screen"
$CheckBoxEnableSmartScreen.location      = New-Object System.Drawing.Point(110,170)
$CheckBoxEnableSmartScreen.width         = 600
$CheckBoxEnableSmartScreen.height        = 20
$CheckBoxEnableSmartScreen.AutoSize      = $false
$CheckBoxEnableSmartScreen.Font          = 'Microsoft Sans Serif,10'
$CheckBoxEnableSmartScreen.checked       = $false
$CheckBoxEnableSmartScreen.Visible       = $false
$CheckBoxEnableSmartScreen.Enabled       = $true

#--Disable--Enable--Web Search
# DisableWebSearch EnableWebSearch

$CheckBoxDisableWebSearch                = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableWebSearch.text           = "Disable "
$CheckBoxDisableWebSearch.location       = New-Object System.Drawing.Point(10,190)
$CheckBoxDisableWebSearch.width          = 100
$CheckBoxDisableWebSearch.height         = 20
$CheckBoxDisableWebSearch.AutoSize       = $false
$CheckBoxDisableWebSearch.Font           = 'Microsoft Sans Serif,10'
$CheckBoxDisableWebSearch.checked        = $true
$CheckBoxDisableWebSearch.Visible        = $false
$CheckBoxDisableWebSearch.Enabled        = $true

$CheckBoxEnableWebSearch                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableWebSearch.text            = "Enable Web Search"
$CheckBoxEnableWebSearch.location        = New-Object System.Drawing.Point(110,190)
$CheckBoxEnableWebSearch.width           = 600
$CheckBoxEnableWebSearch.height          = 20
$CheckBoxEnableWebSearch.AutoSize        = $false
$CheckBoxEnableWebSearch.Font            = 'Microsoft Sans Serif,10'
$CheckBoxEnableWebSearch.checked         = $false
$CheckBoxEnableWebSearch.Visible         = $false
$CheckBoxEnableWebSearch.Enabled         = $true

#--Disable--Enable--App Suggestions
# DisableAppSuggestions EnableAppSuggestions

$CheckBoxDisableAppSuggestions           = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAppSuggestions.text      = "Disable "
$CheckBoxDisableAppSuggestions.location  = New-Object System.Drawing.Point(10,210)
$CheckBoxDisableAppSuggestions.width     = 100
$CheckBoxDisableAppSuggestions.height    = 20
$CheckBoxDisableAppSuggestions.AutoSize  = $false
$CheckBoxDisableAppSuggestions.Font      = 'Microsoft Sans Serif,10'
$CheckBoxDisableAppSuggestions.checked   = $true
$CheckBoxDisableAppSuggestions.Visible   = $false
$CheckBoxDisableAppSuggestions.Enabled   = $true

$CheckBoxEnableAppSuggestions            = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAppSuggestions.text       = "Enable App Suggestions"
$CheckBoxEnableAppSuggestions.location   = New-Object System.Drawing.Point(110,210)
$CheckBoxEnableAppSuggestions.width      = 600
$CheckBoxEnableAppSuggestions.height     = 20
$CheckBoxEnableAppSuggestions.AutoSize   = $false
$CheckBoxEnableAppSuggestions.Font       = 'Microsoft Sans Serif,10'
$CheckBoxEnableAppSuggestions.checked    = $false
$CheckBoxEnableAppSuggestions.Visible    = $false
$CheckBoxEnableAppSuggestions.Enabled    = $true

#--Disable--Enable--Background Apps
# DisableBackgroundApps EnableBackgroundApps 

$CheckBoxDisableBackgroundApps           = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableBackgroundApps.text      = "Disable "
$CheckBoxDisableBackgroundApps.location  = New-Object System.Drawing.Point(10,230)
$CheckBoxDisableBackgroundApps.width     = 100
$CheckBoxDisableBackgroundApps.height    = 20
$CheckBoxDisableBackgroundApps.AutoSize  = $false
$CheckBoxDisableBackgroundApps.Font      = 'Microsoft Sans Serif,10'
$CheckBoxDisableBackgroundApps.checked   = $true
$CheckBoxDisableBackgroundApps.Visible   = $false
$CheckBoxDisableBackgroundApps.Enabled   = $true

$CheckBoxEnableBackgroundApps            = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableBackgroundApps.text       = "Enable Background Apps"
$CheckBoxEnableBackgroundApps.location   = New-Object System.Drawing.Point(110,230)
$CheckBoxEnableBackgroundApps.width      = 600
$CheckBoxEnableBackgroundApps.height     = 20
$CheckBoxEnableBackgroundApps.AutoSize   = $false
$CheckBoxEnableBackgroundApps.Font       = 'Microsoft Sans Serif,10'
$CheckBoxEnableBackgroundApps.checked    = $false
$CheckBoxEnableBackgroundApps.Visible    = $false
$CheckBoxEnableBackgroundApps.Enabled    = $true

#--Disable--Enable--Lock Screen Spotlight
# DisableLockScreenSpotlight EnableLockScreenSpotlight

$CheckBoxDisableLockScreenSpotlight          = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableLockScreenSpotlight.text     = "Disable "
$CheckBoxDisableLockScreenSpotlight.location = New-Object System.Drawing.Point(10,250)
$CheckBoxDisableLockScreenSpotlight.width    = 100
$CheckBoxDisableLockScreenSpotlight.height   = 20
$CheckBoxDisableLockScreenSpotlight.AutoSize = $false
$CheckBoxDisableLockScreenSpotlight.Font     = 'Microsoft Sans Serif,10'
$CheckBoxDisableLockScreenSpotlight.checked  = $true
$CheckBoxDisableLockScreenSpotlight.Visible  = $false
$CheckBoxDisableLockScreenSpotlight.Enabled  = $true

$CheckBoxEnableLockScreenSpotlight           = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableLockScreenSpotlight.text      = "Enable Lock Screen Spotlight"
$CheckBoxEnableLockScreenSpotlight.location  = New-Object System.Drawing.Point(110,250)
$CheckBoxEnableLockScreenSpotlight.width     = 600
$CheckBoxEnableLockScreenSpotlight.height    = 20
$CheckBoxEnableLockScreenSpotlight.AutoSize  = $false
$CheckBoxEnableLockScreenSpotlight.Font      = 'Microsoft Sans Serif,10'
$CheckBoxEnableLockScreenSpotlight.checked   = $false
$CheckBoxEnableLockScreenSpotlight.Visible   = $false
$CheckBoxEnableLockScreenSpotlight.Enabled   = $true

#--Disable--Enable--Location Tracking
# DisableLocationTracking EnableLocationTracking

$CheckBoxDisableLocationTracking          = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableLocationTracking.text     = "Disable "
$CheckBoxDisableLocationTracking.location = New-Object System.Drawing.Point(10,270)
$CheckBoxDisableLocationTracking.width    = 100
$CheckBoxDisableLocationTracking.height   = 20
$CheckBoxDisableLocationTracking.AutoSize = $false
$CheckBoxDisableLocationTracking.Font     = 'Microsoft Sans Serif,10'
$CheckBoxDisableLocationTracking.checked  = $true
$CheckBoxDisableLocationTracking.Visible  = $false
$CheckBoxDisableLocationTracking.Enabled  = $true

$CheckBoxEnableLocationTracking           = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableLocationTracking.text      = "Enable LocationTracking"
$CheckBoxEnableLocationTracking.location  = New-Object System.Drawing.Point(110,270)
$CheckBoxEnableLocationTracking.width     = 600
$CheckBoxEnableLocationTracking.height    = 20
$CheckBoxEnableLocationTracking.AutoSize  = $false
$CheckBoxEnableLocationTracking.Font      = 'Microsoft Sans Serif,10'
$CheckBoxEnableLocationTracking.checked   = $false
$CheckBoxEnableLocationTracking.Visible   = $false
$CheckBoxEnableLocationTracking.Enabled   = $true

#--Disable--Enable--Map Updates
# DisableMapUpdates EnableMapUpdates

$CheckBoxDisableMapUpdates               = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableMapUpdates.text          = "Disable "
$CheckBoxDisableMapUpdates.location      = New-Object System.Drawing.Point(10,290)
$CheckBoxDisableMapUpdates.width         = 100
$CheckBoxDisableMapUpdates.height        = 20
$CheckBoxDisableMapUpdates.AutoSize      = $false
$CheckBoxDisableMapUpdates.Font          = 'Microsoft Sans Serif,10'
$CheckBoxDisableMapUpdates.checked       = $true
$CheckBoxDisableMapUpdates.Visible       = $false
$CheckBoxDisableMapUpdates.Enabled       = $true

$CheckBoxEnableMapUpdates                = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableMapUpdates.text           = "Enable Map Updates"
$CheckBoxEnableMapUpdates.location       = New-Object System.Drawing.Point(110,290)
$CheckBoxEnableMapUpdates.width          = 600
$CheckBoxEnableMapUpdates.height         = 20
$CheckBoxEnableMapUpdates.AutoSize       = $false
$CheckBoxEnableMapUpdates.Font           = 'Microsoft Sans Serif,10'
$CheckBoxEnableMapUpdates.checked        = $false
$CheckBoxEnableMapUpdates.Visible        = $false
$CheckBoxEnableMapUpdates.Enabled        = $true

#--Disable--Enable--Feedback
# DisableFeedback EnableFeedback

$CheckBoxDisableFeedback                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableFeedback.text              = "Disable "
$CheckBoxDisableFeedback.location          = New-Object System.Drawing.Point(10,310)
$CheckBoxDisableFeedback.width             = 100
$CheckBoxDisableFeedback.height            = 20
$CheckBoxDisableFeedback.AutoSize          = $false
$CheckBoxDisableFeedback.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableFeedback.checked           = $true
$CheckBoxDisableFeedback.Visible           = $false
$CheckBoxDisableFeedback.Enabled           = $true

$CheckBoxEnableFeedback                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableFeedback.text               = "Enable Feedback"
$CheckBoxEnableFeedback.location           = New-Object System.Drawing.Point(110,310)
$CheckBoxEnableFeedback.width              = 600
$CheckBoxEnableFeedback.height             = 20
$CheckBoxEnableFeedback.AutoSize           = $false
$CheckBoxEnableFeedback.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableFeedback.checked            = $false
$CheckBoxEnableFeedback.Visible            = $false
$CheckBoxEnableFeedback.Enabled            = $true

#--Disable--Enable--Advertising ID
# DisableAdvertisingID EnableAdvertisingID

$CheckBoxDisableAdvertisingID              = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAdvertisingID.text         = "Disable "
$CheckBoxDisableAdvertisingID.location     = New-Object System.Drawing.Point(10,330)
$CheckBoxDisableAdvertisingID.width        = 100
$CheckBoxDisableAdvertisingID.height       = 20
$CheckBoxDisableAdvertisingID.AutoSize     = $false
$CheckBoxDisableAdvertisingID.Font         = 'Microsoft Sans Serif,10'
$CheckBoxDisableAdvertisingID.checked      = $true
$CheckBoxDisableAdvertisingID.Visible      = $false
$CheckBoxDisableAdvertisingID.Enabled      = $true

$CheckBoxEnableAdvertisingID               = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAdvertisingID.text          = "Enable Advertising ID"
$CheckBoxEnableAdvertisingID.location      = New-Object System.Drawing.Point(110,330)
$CheckBoxEnableAdvertisingID.width         = 600
$CheckBoxEnableAdvertisingID.height        = 20
$CheckBoxEnableAdvertisingID.AutoSize      = $false
$CheckBoxEnableAdvertisingID.Font          = 'Microsoft Sans Serif,10'
$CheckBoxEnableAdvertisingID.checked       = $false
$CheckBoxEnableAdvertisingID.Visible       = $false
$CheckBoxEnableAdvertisingID.Enabled       = $true

#--Disable--Enable--Cortana
# DisableCortana EnableCortana

$CheckBoxDisableCortana                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableCortana.text              = "Disable "
$CheckBoxDisableCortana.location          = New-Object System.Drawing.Point(10,350)
$CheckBoxDisableCortana.width             = 100
$CheckBoxDisableCortana.height            = 20
$CheckBoxDisableCortana.AutoSize          = $false
$CheckBoxDisableCortana.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableCortana.checked           = $true
$CheckBoxDisableCortana.Visible           = $false
$CheckBoxDisableCortana.Enabled           = $true

$CheckBoxEnableCortana                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableCortana.text               = "Enable Cortana"
$CheckBoxEnableCortana.location           = New-Object System.Drawing.Point(110,350)
$CheckBoxEnableCortana.width              = 600
$CheckBoxEnableCortana.height             = 20
$CheckBoxEnableCortana.AutoSize           = $false
$CheckBoxEnableCortana.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableCortana.checked            = $false
$CheckBoxEnableCortana.Visible            = $false
$CheckBoxEnableCortana.Enabled            = $true

#--Disable--Enable--Error Reporting
# DisableErrorReporting EnableErrorReporting

$CheckBoxDisableErrorReporting            = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableErrorReporting.text       = "Disable "
$CheckBoxDisableErrorReporting.location   = New-Object System.Drawing.Point(10,370)
$CheckBoxDisableErrorReporting.width      = 100
$CheckBoxDisableErrorReporting.height     = 20
$CheckBoxDisableErrorReporting.AutoSize   = $false
$CheckBoxDisableErrorReporting.Font       = 'Microsoft Sans Serif,10'
$CheckBoxDisableErrorReporting.checked    = $true
$CheckBoxDisableErrorReporting.Visible    = $false
$CheckBoxDisableErrorReporting.Enabled    = $true

$CheckBoxEnableErrorReporting             = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableErrorReporting.text        = "Enable Error Reporting"
$CheckBoxEnableErrorReporting.location    = New-Object System.Drawing.Point(110,370)
$CheckBoxEnableErrorReporting.width       = 600
$CheckBoxEnableErrorReporting.height      = 20
$CheckBoxEnableErrorReporting.AutoSize    = $false
$CheckBoxEnableErrorReporting.Font        = 'Microsoft Sans Serif,10'
$CheckBoxEnableErrorReporting.checked     = $false
$CheckBoxEnableErrorReporting.Visible     = $false
$CheckBoxEnableErrorReporting.Enabled     = $true

#--Disable--Enable--Auto Logger
# DisableAutoLogger EnableAutoLogger

$CheckBoxDisableAutoLogger                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAutoLogger.text              = "Disable "
$CheckBoxDisableAutoLogger.location          = New-Object System.Drawing.Point(10,390)
$CheckBoxDisableAutoLogger.width             = 100
$CheckBoxDisableAutoLogger.height            = 20
$CheckBoxDisableAutoLogger.AutoSize          = $false
$CheckBoxDisableAutoLogger.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableAutoLogger.checked           = $true
$CheckBoxDisableAutoLogger.Visible           = $false
$CheckBoxDisableAutoLogger.Enabled           = $true

$CheckBoxEnableAutoLogger                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAutoLogger.text               = "Enable Auto Logger"
$CheckBoxEnableAutoLogger.location           = New-Object System.Drawing.Point(110,390)
$CheckBoxEnableAutoLogger.width              = 600
$CheckBoxEnableAutoLogger.height             = 20
$CheckBoxEnableAutoLogger.AutoSize           = $false
$CheckBoxEnableAutoLogger.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableAutoLogger.checked            = $false
$CheckBoxEnableAutoLogger.Visible            = $false
$CheckBoxEnableAutoLogger.Enabled            = $true

#--Disable--Enable--Diag Track
# DisableDiagTrack EnableDiagTrack 

$CheckBoxDisableDiagTrack                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableDiagTrack.text              = "Disable "
$CheckBoxDisableDiagTrack.location          = New-Object System.Drawing.Point(10,410)
$CheckBoxDisableDiagTrack.width             = 100
$CheckBoxDisableDiagTrack.height            = 20
$CheckBoxDisableDiagTrack.AutoSize          = $false
$CheckBoxDisableDiagTrack.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableDiagTrack.checked           = $true
$CheckBoxDisableDiagTrack.Visible           = $false
$CheckBoxDisableDiagTrack.Enabled           = $true

$CheckBoxEnableDiagTrack                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableDiagTrack.text               = "Enable Diag Track"
$CheckBoxEnableDiagTrack.location           = New-Object System.Drawing.Point(110,410)
$CheckBoxEnableDiagTrack.width              = 600
$CheckBoxEnableDiagTrack.height             = 20
$CheckBoxEnableDiagTrack.AutoSize           = $false
$CheckBoxEnableDiagTrack.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableDiagTrack.checked            = $false
$CheckBoxEnableDiagTrack.Visible            = $false
$CheckBoxEnableDiagTrack.Enabled            = $true

#--Disable--Enable--WAP Push
# DisableWAPPush EnableWAPPush 

$CheckBoxDisableWAPPush                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableWAPPush.text              = "Disable "
$CheckBoxDisableWAPPush.location          = New-Object System.Drawing.Point(10,430)
$CheckBoxDisableWAPPush.width             = 100
$CheckBoxDisableWAPPush.height            = 20
$CheckBoxDisableWAPPush.AutoSize          = $false
$CheckBoxDisableWAPPush.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableWAPPush.checked           = $true
$CheckBoxDisableWAPPush.Visible           = $false
$CheckBoxDisableWAPPush.Enabled           = $true

$CheckBoxEnableWAPPush                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableWAPPush.text               = "Enable WAP Push"
$CheckBoxEnableWAPPush.location           = New-Object System.Drawing.Point(110,430)
$CheckBoxEnableWAPPush.width              = 600
$CheckBoxEnableWAPPush.height             = 20
$CheckBoxEnableWAPPush.AutoSize           = $false
$CheckBoxEnableWAPPush.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableWAPPush.checked            = $false
$CheckBoxEnableWAPPush.Visible            = $false
$CheckBoxEnableWAPPush.Enabled            = $true

#--Disable--Enable--P2P Update Local--P2P Update Internet
# SetP2PUpdateLocal SetP2PUpdateInternet

$CheckBoxP2PUpdateLocal                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxP2PUpdateLocal.text              = "P2P Update Local "
$CheckBoxP2PUpdateLocal.location          = New-Object System.Drawing.Point(10,450)
$CheckBoxP2PUpdateLocal.width             = 100
$CheckBoxP2PUpdateLocal.height            = 20
$CheckBoxP2PUpdateLocal.AutoSize          = $false
$CheckBoxP2PUpdateLocal.Font              = 'Microsoft Sans Serif,10'
$CheckBoxP2PUpdateLocal.checked           = $true
$CheckBoxP2PUpdateLocal.Visible           = $false
$CheckBoxP2PUpdateLocal.Enabled           = $true

$CheckBoxP2PUpdateInternet                = New-Object system.Windows.Forms.CheckBox
$CheckBoxP2PUpdateInternet.text           = "P2P Update Internet "
$CheckBoxP2PUpdateInternet.location       = New-Object System.Drawing.Point(110,450)
$CheckBoxP2PUpdateInternet.width          = 600
$CheckBoxP2PUpdateInternet.height         = 20
$CheckBoxP2PUpdateInternet.AutoSize       = $false
$CheckBoxP2PUpdateInternet.Font           = 'Microsoft Sans Serif,10'
$CheckBoxP2PUpdateInternet.checked        = $false
$CheckBoxP2PUpdateInternet.Visible        = $false
$CheckBoxP2PUpdateInternet.Enabled        = $true

#--Service Tweaks--#############################################################################################################################################################################
 
#--Set UAC Low--Set UAC High
# SetUACLow SetUACHigh

$CheckBoxSetUACLow                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetUACLow.text              = "UAC Low "
$CheckBoxSetUACLow.location          = New-Object System.Drawing.Point(10,130)
$CheckBoxSetUACLow.width             = 100
$CheckBoxSetUACLow.height            = 20
$CheckBoxSetUACLow.AutoSize          = $false
$CheckBoxSetUACLow.Font              = 'Microsoft Sans Serif,10'
$CheckBoxSetUACLow.checked           = $true
$CheckBoxSetUACLow.Visible           = $false
$CheckBoxSetUACLow.Enabled           = $true

$CheckBoxSetUACHigh                  = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetUACHigh.text             = "UAC High "
$CheckBoxSetUACHigh.location         = New-Object System.Drawing.Point(110,130)
$CheckBoxSetUACHigh.width            = 600
$CheckBoxSetUACHigh.height           = 20
$CheckBoxSetUACHigh.AutoSize         = $false
$CheckBoxSetUACHigh.Font             = 'Microsoft Sans Serif,10'
$CheckBoxSetUACHigh.checked          = $false
$CheckBoxSetUACHigh.Visible          = $false
$CheckBoxSetUACHigh.Enabled          = $true

#--Enable Sharing Mapped Drives--Disable Sharing Mapped Drives
# EnableSharingMappedDrives DisableSharingMappedDrives

$CheckBoxEnableSharingMappedDrives                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableSharingMappedDrives.text              = "Enable "
$CheckBoxEnableSharingMappedDrives.location          = New-Object System.Drawing.Point(10,150)
$CheckBoxEnableSharingMappedDrives.width             = 100
$CheckBoxEnableSharingMappedDrives.height            = 20
$CheckBoxEnableSharingMappedDrives.AutoSize          = $false
$CheckBoxEnableSharingMappedDrives.Font              = 'Microsoft Sans Serif,10'
$CheckBoxEnableSharingMappedDrives.checked           = $true
$CheckBoxEnableSharingMappedDrives.Visible           = $false
$CheckBoxEnableSharingMappedDrives.Enabled           = $true

$CheckBoxDisableSharingMappedDrives                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableSharingMappedDrives.text               = "Disable Sharing Mapped Drives "
$CheckBoxDisableSharingMappedDrives.location           = New-Object System.Drawing.Point(110,150)
$CheckBoxDisableSharingMappedDrives.width              = 600
$CheckBoxDisableSharingMappedDrives.height             = 20
$CheckBoxDisableSharingMappedDrives.AutoSize           = $false
$CheckBoxDisableSharingMappedDrives.Font               = 'Microsoft Sans Serif,10'
$CheckBoxDisableSharingMappedDrives.checked            = $false
$CheckBoxDisableSharingMappedDrives.Visible            = $false
$CheckBoxDisableSharingMappedDrives.Enabled            = $true

#--Disable--Enable--Admin Shares
# DisableAdminShares EnableAdminShares

$CheckBoxDisableAdminShares                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAdminShares.text              = "Disable "
$CheckBoxDisableAdminShares.location          = New-Object System.Drawing.Point(10,170)
$CheckBoxDisableAdminShares.width             = 100
$CheckBoxDisableAdminShares.height            = 20
$CheckBoxDisableAdminShares.AutoSize          = $false
$CheckBoxDisableAdminShares.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableAdminShares.checked           = $true
$CheckBoxDisableAdminShares.Visible           = $false
$CheckBoxDisableAdminShares.Enabled           = $true

$CheckBoxEnableAdminShares                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAdminShares.text               = "Enable Admin Shares"
$CheckBoxEnableAdminShares.location           = New-Object System.Drawing.Point(110,170)
$CheckBoxEnableAdminShares.width              = 600
$CheckBoxEnableAdminShares.height             = 20
$CheckBoxEnableAdminShares.AutoSize           = $false
$CheckBoxEnableAdminShares.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableAdminShares.checked            = $false
$CheckBoxEnableAdminShares.Visible            = $false
$CheckBoxEnableAdminShares.Enabled            = $true

#--Disable--Enable--SMB1
# DisableSMB1 EnableSMB1

$CheckBoxDisableSMB1                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableSMB1.text              = "Disable "
$CheckBoxDisableSMB1.location          = New-Object System.Drawing.Point(10,190)
$CheckBoxDisableSMB1.width             = 100
$CheckBoxDisableSMB1.height            = 20
$CheckBoxDisableSMB1.AutoSize          = $false
$CheckBoxDisableSMB1.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableSMB1.checked           = $true
$CheckBoxDisableSMB1.Visible           = $false
$CheckBoxDisableSMB1.Enabled           = $true

$CheckBoxEnableSMB1                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableSMB1.text               = "Enable SMB1"
$CheckBoxEnableSMB1.location           = New-Object System.Drawing.Point(110,190)
$CheckBoxEnableSMB1.width              = 600
$CheckBoxEnableSMB1.height             = 20
$CheckBoxEnableSMB1.AutoSize           = $false
$CheckBoxEnableSMB1.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableSMB1.checked            = $false
$CheckBoxEnableSMB1.Visible            = $false
$CheckBoxEnableSMB1.Enabled            = $true

#--Set Current Network Private--Public
# SetCurrentNetworkPrivate SetCurrentNetworkPublic

$CheckBoxCurrentNetworkPrivate                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxCurrentNetworkPrivate.text              = "Private "
$CheckBoxCurrentNetworkPrivate.location          = New-Object System.Drawing.Point(10,210)
$CheckBoxCurrentNetworkPrivate.width             = 100
$CheckBoxCurrentNetworkPrivate.height            = 20
$CheckBoxCurrentNetworkPrivate.AutoSize          = $false
$CheckBoxCurrentNetworkPrivate.Font              = 'Microsoft Sans Serif,10'
$CheckBoxCurrentNetworkPrivate.checked           = $true
$CheckBoxCurrentNetworkPrivate.Visible           = $false
$CheckBoxCurrentNetworkPrivate.Enabled           = $true

$CheckBoxCurrentNetworkPublic                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxCurrentNetworkPublic.text               = "Public - Set Current Network "
$CheckBoxCurrentNetworkPublic.location           = New-Object System.Drawing.Point(110,210)
$CheckBoxCurrentNetworkPublic.width              = 600
$CheckBoxCurrentNetworkPublic.height             = 20
$CheckBoxCurrentNetworkPublic.AutoSize           = $false
$CheckBoxCurrentNetworkPublic.Font               = 'Microsoft Sans Serif,10'
$CheckBoxCurrentNetworkPublic.checked            = $false
$CheckBoxCurrentNetworkPublic.Visible            = $false
$CheckBoxCurrentNetworkPublic.Enabled            = $true

#--Set Unknown Networks Private--Public
# SetUnknownNetworksPrivate SetUnknownNetworksPublic

$CheckBoxUnknownNetworksPrivate                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUnknownNetworksPrivate.text              = "Private "
$CheckBoxUnknownNetworksPrivate.location          = New-Object System.Drawing.Point(10,230)
$CheckBoxUnknownNetworksPrivate.width             = 100
$CheckBoxUnknownNetworksPrivate.height            = 20
$CheckBoxUnknownNetworksPrivate.AutoSize          = $false
$CheckBoxUnknownNetworksPrivate.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUnknownNetworksPrivate.checked           = $true
$CheckBoxUnknownNetworksPrivate.Visible           = $false
$CheckBoxUnknownNetworksPrivate.Enabled           = $true

$CheckBoxUnknownNetworksPublic                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxUnknownNetworksPublic.text               = "Public - Set Unknown Networks "
$CheckBoxUnknownNetworksPublic.location           = New-Object System.Drawing.Point(110,230)
$CheckBoxUnknownNetworksPublic.width              = 600
$CheckBoxUnknownNetworksPublic.height             = 20
$CheckBoxUnknownNetworksPublic.AutoSize           = $false
$CheckBoxUnknownNetworksPublic.Font               = 'Microsoft Sans Serif,10'
$CheckBoxUnknownNetworksPublic.checked            = $false
$CheckBoxUnknownNetworksPublic.Visible            = $false
$CheckBoxUnknownNetworksPublic.Enabled            = $true

#--Enable--Disable--Controlled Folder Access
# EnableCtrldFolderAccess DisableCtrldFolderAccess

$CheckBoxEnableCtrldFolderAccess                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableCtrldFolderAccess.text              = "Enable "
$CheckBoxEnableCtrldFolderAccess.location          = New-Object System.Drawing.Point(10,250)
$CheckBoxEnableCtrldFolderAccess.width             = 100
$CheckBoxEnableCtrldFolderAccess.height            = 20
$CheckBoxEnableCtrldFolderAccess.AutoSize          = $false
$CheckBoxEnableCtrldFolderAccess.Font              = 'Microsoft Sans Serif,10'
$CheckBoxEnableCtrldFolderAccess.checked           = $true
$CheckBoxEnableCtrldFolderAccess.Visible           = $false
$CheckBoxEnableCtrldFolderAccess.Enabled           = $true

$CheckBoxDisableCtrldFolderAccess                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableCtrldFolderAccess.text               = "Disable Controlled  Folder Access"
$CheckBoxDisableCtrldFolderAccess.location           = New-Object System.Drawing.Point(110,250)
$CheckBoxDisableCtrldFolderAccess.width              = 600
$CheckBoxDisableCtrldFolderAccess.height             = 20
$CheckBoxDisableCtrldFolderAccess.AutoSize           = $false
$CheckBoxDisableCtrldFolderAccess.Font               = 'Microsoft Sans Serif,10'
$CheckBoxDisableCtrldFolderAccess.checked            = $false
$CheckBoxDisableCtrldFolderAccess.Visible            = $false
$CheckBoxDisableCtrldFolderAccess.Enabled            = $true

#--Disable--Enable--Firewall
# DisableFirewall EnableFirewall

$CheckBoxDisableFirewall                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableFirewall.text              = "Disable "
$CheckBoxDisableFirewall.location          = New-Object System.Drawing.Point(10,270)
$CheckBoxDisableFirewall.width             = 100
$CheckBoxDisableFirewall.height            = 20
$CheckBoxDisableFirewall.AutoSize          = $false
$CheckBoxDisableFirewall.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableFirewall.checked           = $false
$CheckBoxDisableFirewall.Visible           = $false
$CheckBoxDisableFirewall.Enabled           = $true

$CheckBoxEnableFirewall                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableFirewall.text               = "Enable Firewall"
$CheckBoxEnableFirewall.location           = New-Object System.Drawing.Point(110,270)
$CheckBoxEnableFirewall.width              = 600
$CheckBoxEnableFirewall.height             = 20
$CheckBoxEnableFirewall.AutoSize           = $false
$CheckBoxEnableFirewall.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableFirewall.checked            = $true
$CheckBoxEnableFirewall.Visible            = $false
$CheckBoxEnableFirewall.Enabled            = $true

#--Disable--Enable--Defender
# DisableDefender EnableDefender

$CheckBoxDisableDefender                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableDefender.text              = "Disable "
$CheckBoxDisableDefender.location          = New-Object System.Drawing.Point(10,290)
$CheckBoxDisableDefender.width             = 100
$CheckBoxDisableDefender.height            = 20
$CheckBoxDisableDefender.AutoSize          = $false
$CheckBoxDisableDefender.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableDefender.checked           = $false
$CheckBoxDisableDefender.Visible           = $false
$CheckBoxDisableDefender.Enabled           = $true

$CheckBoxEnableDefender                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableDefender.text               = "Enable Defender "
$CheckBoxEnableDefender.location           = New-Object System.Drawing.Point(110,290)
$CheckBoxEnableDefender.width              = 600
$CheckBoxEnableDefender.height             = 20
$CheckBoxEnableDefender.AutoSize           = $false
$CheckBoxEnableDefender.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableDefender.checked            = $true
$CheckBoxEnableDefender.Visible            = $false
$CheckBoxEnableDefender.Enabled            = $true

#--Disable--Enable--Defender Cloud
# DisableDefenderCloud EnableDefenderCloud

$CheckBoxDisableDefenderCloud                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableDefenderCloud.text              = "Disable "
$CheckBoxDisableDefenderCloud.location          = New-Object System.Drawing.Point(10,310)
$CheckBoxDisableDefenderCloud.width             = 100
$CheckBoxDisableDefenderCloud.height            = 20
$CheckBoxDisableDefenderCloud.AutoSize          = $false
$CheckBoxDisableDefenderCloud.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableDefenderCloud.checked           = $false
$CheckBoxDisableDefenderCloud.Visible           = $false
$CheckBoxDisableDefenderCloud.Enabled           = $true

$CheckBoxEnableDefenderCloud                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableDefenderCloud.text               = "Enable Defender Cloud"
$CheckBoxEnableDefenderCloud.location           = New-Object System.Drawing.Point(110,310)
$CheckBoxEnableDefenderCloud.width              = 600
$CheckBoxEnableDefenderCloud.height             = 20
$CheckBoxEnableDefenderCloud.AutoSize           = $false
$CheckBoxEnableDefenderCloud.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableDefenderCloud.checked            = $true
$CheckBoxEnableDefenderCloud.Visible            = $false
$CheckBoxEnableDefenderCloud.Enabled            = $true

#--Disable--Enable--Update MSRT
# DisableUpdateMSRT EnableUpdateMSRT

$CheckBoxDisableUpdateMSRT                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableUpdateMSRT.text              = "Disable "
$CheckBoxDisableUpdateMSRT.location          = New-Object System.Drawing.Point(10,330)
$CheckBoxDisableUpdateMSRT.width             = 100
$CheckBoxDisableUpdateMSRT.height            = 20
$CheckBoxDisableUpdateMSRT.AutoSize          = $false
$CheckBoxDisableUpdateMSRT.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableUpdateMSRT.checked           = $true
$CheckBoxDisableUpdateMSRT.Visible           = $false
$CheckBoxDisableUpdateMSRT.Enabled           = $true

$CheckBoxEnableUpdateMSRT                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableUpdateMSRT.text               = "Enable UpdateMSRT"
$CheckBoxEnableUpdateMSRT.location           = New-Object System.Drawing.Point(110,330)
$CheckBoxEnableUpdateMSRT.width              = 600
$CheckBoxEnableUpdateMSRT.height             = 20
$CheckBoxEnableUpdateMSRT.AutoSize           = $false
$CheckBoxEnableUpdateMSRT.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableUpdateMSRT.checked            = $false
$CheckBoxEnableUpdateMSRT.Visible            = $false
$CheckBoxEnableUpdateMSRT.Enabled            = $true

#--Disable--Enable--Update Driver
# DisableUpdateDriver EnableUpdateDriver

$CheckBoxDisableUpdateDriver                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableUpdateDriver.text              = "Disable "
$CheckBoxDisableUpdateDriver.location          = New-Object System.Drawing.Point(10,350)
$CheckBoxDisableUpdateDriver.width             = 100
$CheckBoxDisableUpdateDriver.height            = 20
$CheckBoxDisableUpdateDriver.AutoSize          = $false
$CheckBoxDisableUpdateDriver.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableUpdateDriver.checked           = $true
$CheckBoxDisableUpdateDriver.Visible           = $false
$CheckBoxDisableUpdateDriver.Enabled           = $true

$CheckBoxEnableUpdateDriver                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableUpdateDriver.text               = "Enable Update Driver"
$CheckBoxEnableUpdateDriver.location           = New-Object System.Drawing.Point(110,350)
$CheckBoxEnableUpdateDriver.width              = 600
$CheckBoxEnableUpdateDriver.height             = 20
$CheckBoxEnableUpdateDriver.AutoSize           = $false
$CheckBoxEnableUpdateDriver.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableUpdateDriver.checked            = $false
$CheckBoxEnableUpdateDriver.Visible            = $false
$CheckBoxEnableUpdateDriver.Enabled            = $true

#--Disable--Enable--Update Restart
# DisableUpdateRestart EnableUpdateRestart

$CheckBoxDisableUpdateRestart                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableUpdateRestart.text              = "Disable "
$CheckBoxDisableUpdateRestart.location          = New-Object System.Drawing.Point(10,370)
$CheckBoxDisableUpdateRestart.width             = 100
$CheckBoxDisableUpdateRestart.height            = 20
$CheckBoxDisableUpdateRestart.AutoSize          = $false
$CheckBoxDisableUpdateRestart.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableUpdateRestart.checked           = $true
$CheckBoxDisableUpdateRestart.Visible           = $false
$CheckBoxDisableUpdateRestart.Enabled           = $true

$CheckBoxEnableUpdateRestart                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableUpdateRestart.text               = "Enable Update Restart"
$CheckBoxEnableUpdateRestart.location           = New-Object System.Drawing.Point(110,370)
$CheckBoxEnableUpdateRestart.width              = 600
$CheckBoxEnableUpdateRestart.height             = 20
$CheckBoxEnableUpdateRestart.AutoSize           = $false
$CheckBoxEnableUpdateRestart.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableUpdateRestart.checked            = $false
$CheckBoxEnableUpdateRestart.Visible            = $false
$CheckBoxEnableUpdateRestart.Enabled            = $true

#--Disable--Enable--Home Groups
# DisableHomeGroups EnableHomeGroups

$CheckBoxDisableHomeGroups                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableHomeGroups.text              = "Disable "
$CheckBoxDisableHomeGroups.location          = New-Object System.Drawing.Point(10,390)
$CheckBoxDisableHomeGroups.width             = 100
$CheckBoxDisableHomeGroups.height            = 20
$CheckBoxDisableHomeGroups.AutoSize          = $false
$CheckBoxDisableHomeGroups.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableHomeGroups.checked           = $true
$CheckBoxDisableHomeGroups.Visible           = $false
$CheckBoxDisableHomeGroups.Enabled           = $true

$CheckBoxEnableHomeGroups                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableHomeGroups.text               = "Enable Home Groups"
$CheckBoxEnableHomeGroups.location           = New-Object System.Drawing.Point(110,390)
$CheckBoxEnableHomeGroups.width              = 600
$CheckBoxEnableHomeGroups.height             = 20
$CheckBoxEnableHomeGroups.AutoSize           = $false
$CheckBoxEnableHomeGroups.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableHomeGroups.checked            = $false
$CheckBoxEnableHomeGroups.Visible            = $false
$CheckBoxEnableHomeGroups.Enabled            = $true

#--Disable--Enable--Shared Experiences
# DisableSharedExperiences EnableSharedExperiences

$CheckBoxDisableSharedExperiences                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableSharedExperiences.text              = "Disable "
$CheckBoxDisableSharedExperiences.location          = New-Object System.Drawing.Point(10,410)
$CheckBoxDisableSharedExperiences.width             = 100
$CheckBoxDisableSharedExperiences.height            = 20
$CheckBoxDisableSharedExperiences.AutoSize          = $false
$CheckBoxDisableSharedExperiences.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableSharedExperiences.checked           = $true
$CheckBoxDisableSharedExperiences.Visible           = $false
$CheckBoxDisableSharedExperiences.Enabled           = $true

$CheckBoxEnableSharedExperiences                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableSharedExperiences.text               = "Enable Shared Experiences"
$CheckBoxEnableSharedExperiences.location           = New-Object System.Drawing.Point(110,410)
$CheckBoxEnableSharedExperiences.width              = 600
$CheckBoxEnableSharedExperiences.height             = 20
$CheckBoxEnableSharedExperiences.AutoSize           = $false
$CheckBoxEnableSharedExperiences.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableSharedExperiences.checked            = $false
$CheckBoxEnableSharedExperiences.Visible            = $false
$CheckBoxEnableSharedExperiences.Enabled            = $true

#--Disable--Enable--Remote Assistance
# DisableRemoteAssistance EnableRemoteAssistance

$CheckBoxDisableRemoteAssistance                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableRemoteAssistance.text              = "Disable "
$CheckBoxDisableRemoteAssistance.location          = New-Object System.Drawing.Point(10,430)
$CheckBoxDisableRemoteAssistance.width             = 100
$CheckBoxDisableRemoteAssistance.height            = 20
$CheckBoxDisableRemoteAssistance.AutoSize          = $false
$CheckBoxDisableRemoteAssistance.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableRemoteAssistance.checked           = $true
$CheckBoxDisableRemoteAssistance.Visible           = $false
$CheckBoxDisableRemoteAssistance.Enabled           = $true

$CheckBoxEnableRemoteAssistance                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableRemoteAssistance.text               = "Enable Remote Assistance"
$CheckBoxEnableRemoteAssistance.location           = New-Object System.Drawing.Point(110,430)
$CheckBoxEnableRemoteAssistance.width              = 600
$CheckBoxEnableRemoteAssistance.height             = 20
$CheckBoxEnableRemoteAssistance.AutoSize           = $false
$CheckBoxEnableRemoteAssistance.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableRemoteAssistance.checked            = $false
$CheckBoxEnableRemoteAssistance.Visible            = $false
$CheckBoxEnableRemoteAssistance.Enabled            = $true

#--Disable--Enable--Remote Desktop
# DisableRemoteDesktop EnableRemoteDesktop

$CheckBoxDisableRemoteDesktop                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableRemoteDesktop.text              = "Disable "
$CheckBoxDisableRemoteDesktop.location          = New-Object System.Drawing.Point(10,450)
$CheckBoxDisableRemoteDesktop.width             = 100
$CheckBoxDisableRemoteDesktop.height            = 20
$CheckBoxDisableRemoteDesktop.AutoSize          = $false
$CheckBoxDisableRemoteDesktop.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableRemoteDesktop.checked           = $true
$CheckBoxDisableRemoteDesktop.Visible           = $false
$CheckBoxDisableRemoteDesktop.Enabled           = $true

$CheckBoxEnableRemoteDesktop                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableRemoteDesktop.text               = "Enable Remote Desktop"
$CheckBoxEnableRemoteDesktop.location           = New-Object System.Drawing.Point(110,450)
$CheckBoxEnableRemoteDesktop.width              = 600
$CheckBoxEnableRemoteDesktop.height             = 20
$CheckBoxEnableRemoteDesktop.AutoSize           = $false
$CheckBoxEnableRemoteDesktop.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableRemoteDesktop.checked            = $false
$CheckBoxEnableRemoteDesktop.Visible            = $false
$CheckBoxEnableRemoteDesktop.Enabled            = $true

#--Disable--Enable--Auto play
# DisableAutoplay EnableAutoplay

$CheckBoxDisableAutoplay                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAutoplay.text              = "Disable "
$CheckBoxDisableAutoplay.location          = New-Object System.Drawing.Point(10,470)
$CheckBoxDisableAutoplay.width             = 100
$CheckBoxDisableAutoplay.height            = 20
$CheckBoxDisableAutoplay.AutoSize          = $false
$CheckBoxDisableAutoplay.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableAutoplay.checked           = $true
$CheckBoxDisableAutoplay.Visible           = $false
$CheckBoxDisableAutoplay.Enabled           = $true

$CheckBoxEnableAutoplay                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAutoplay.text               = "Enable Auto Play"
$CheckBoxEnableAutoplay.location           = New-Object System.Drawing.Point(110,470)
$CheckBoxEnableAutoplay.width              = 600
$CheckBoxEnableAutoplay.height             = 20
$CheckBoxEnableAutoplay.AutoSize           = $false
$CheckBoxEnableAutoplay.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableAutoplay.checked            = $false
$CheckBoxEnableAutoplay.Visible            = $false
$CheckBoxEnableAutoplay.Enabled            = $true

#--Disable--Enable--Auto run
# DisableAutorun EnableAutorun

$CheckBoxDisableAutorun                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAutorun.text              = "Disable "
$CheckBoxDisableAutorun.location          = New-Object System.Drawing.Point(10,490)
$CheckBoxDisableAutorun.width             = 100
$CheckBoxDisableAutorun.height            = 20
$CheckBoxDisableAutorun.AutoSize          = $false
$CheckBoxDisableAutorun.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableAutorun.checked           = $true
$CheckBoxDisableAutorun.Visible           = $false
$CheckBoxDisableAutorun.Enabled           = $true

$CheckBoxEnableAutorun                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAutorun.text               = "Enable Auto Run"
$CheckBoxEnableAutorun.location           = New-Object System.Drawing.Point(110,490)
$CheckBoxEnableAutorun.width              = 600
$CheckBoxEnableAutorun.height             = 20
$CheckBoxEnableAutorun.AutoSize           = $false
$CheckBoxEnableAutorun.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableAutorun.checked            = $false
$CheckBoxEnableAutorun.Visible            = $false
$CheckBoxEnableAutorun.Enabled            = $true

#--Disable--Enable--Storage Sense
# EnableStorageSense DisableStorageSense

$CheckBoxDisableStorageSense                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableStorageSense.text              = "Disable "
$CheckBoxDisableStorageSense.location          = New-Object System.Drawing.Point(10,510)
$CheckBoxDisableStorageSense.width             = 100
$CheckBoxDisableStorageSense.height            = 20
$CheckBoxDisableStorageSense.AutoSize          = $false
$CheckBoxDisableStorageSense.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableStorageSense.checked           = $true
$CheckBoxDisableStorageSense.Visible           = $false
$CheckBoxDisableStorageSense.Enabled           = $true

$CheckBoxEnableStorageSense                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableStorageSense.text               = "Enable Storage Sense"
$CheckBoxEnableStorageSense.location           = New-Object System.Drawing.Point(110,510)
$CheckBoxEnableStorageSense.width              = 600
$CheckBoxEnableStorageSense.height             = 20
$CheckBoxEnableStorageSense.AutoSize           = $false
$CheckBoxEnableStorageSense.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableStorageSense.checked            = $false
$CheckBoxEnableStorageSense.Visible            = $false
$CheckBoxEnableStorageSense.Enabled            = $true

#--Disable--Enable--Defragmentation
# DisableDefragmentation EnableDefragmentation

$CheckBoxDisableDefragmentation                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableDefragmentation.text              = "Disable "
$CheckBoxDisableDefragmentation.location          = New-Object System.Drawing.Point(10,530)
$CheckBoxDisableDefragmentation.width             = 100
$CheckBoxDisableDefragmentation.height            = 20
$CheckBoxDisableDefragmentation.AutoSize          = $false
$CheckBoxDisableDefragmentation.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableDefragmentation.checked           = $false
$CheckBoxDisableDefragmentation.Visible           = $false
$CheckBoxDisableDefragmentation.Enabled           = $true

$CheckBoxEnableDefragmentation                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableDefragmentation.text               = "Enable Defragmentation"
$CheckBoxEnableDefragmentation.location           = New-Object System.Drawing.Point(110,530)
$CheckBoxEnableDefragmentation.width              = 600
$CheckBoxEnableDefragmentation.height             = 20
$CheckBoxEnableDefragmentation.AutoSize           = $false
$CheckBoxEnableDefragmentation.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableDefragmentation.checked            = $true
$CheckBoxEnableDefragmentation.Visible            = $false
$CheckBoxEnableDefragmentation.Enabled            = $true

#--Disable--Enable--Super fetch
# DisableSuperfetch EnableSuperfetch

$CheckBoxDisableSuperfetch                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableSuperfetch.text              = "Disable "
$CheckBoxDisableSuperfetch.location          = New-Object System.Drawing.Point(10,550)
$CheckBoxDisableSuperfetch.width             = 100
$CheckBoxDisableSuperfetch.height            = 20
$CheckBoxDisableSuperfetch.AutoSize          = $false
$CheckBoxDisableSuperfetch.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableSuperfetch.checked           = $true
$CheckBoxDisableSuperfetch.Visible           = $false
$CheckBoxDisableSuperfetch.Enabled           = $true

$CheckBoxEnableSuperfetch                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableSuperfetch.text               = "Enable Super Fetch"
$CheckBoxEnableSuperfetch.location           = New-Object System.Drawing.Point(110,550)
$CheckBoxEnableSuperfetch.width              = 600
$CheckBoxEnableSuperfetch.height             = 20
$CheckBoxEnableSuperfetch.AutoSize           = $false
$CheckBoxEnableSuperfetch.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableSuperfetch.checked            = $false
$CheckBoxEnableSuperfetch.Visible            = $false
$CheckBoxEnableSuperfetch.Enabled            = $true

#--Disable--Enable--Indexing
# DisableIndexing EnableIndexing

$CheckBoxDisableIndexing                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableIndexing.text              = "Disable "
$CheckBoxDisableIndexing.location          = New-Object System.Drawing.Point(10,570)
$CheckBoxDisableIndexing.width             = 100
$CheckBoxDisableIndexing.height            = 20
$CheckBoxDisableIndexing.AutoSize          = $false
$CheckBoxDisableIndexing.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableIndexing.checked           = $false
$CheckBoxDisableIndexing.Visible           = $false
$CheckBoxDisableIndexing.Enabled           = $true

$CheckBoxEnableIndexing                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableIndexing.text               = "Enable Indexing"
$CheckBoxEnableIndexing.location           = New-Object System.Drawing.Point(110,570)
$CheckBoxEnableIndexing.width              = 600
$CheckBoxEnableIndexing.height             = 20
$CheckBoxEnableIndexing.AutoSize           = $false
$CheckBoxEnableIndexing.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableIndexing.checked            = $true
$CheckBoxEnableIndexing.Visible            = $false
$CheckBoxEnableIndexing.Enabled            = $true

#--Disable--Enable--BIOS Time UTC or Local
# SetBIOSTimeUTC SetBIOSTimeLocal

$CheckBoxSetBIOSTimeUTC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetBIOSTimeUTC.text              = "UTC "
$CheckBoxSetBIOSTimeUTC.location          = New-Object System.Drawing.Point(10,590)
$CheckBoxSetBIOSTimeUTC.width             = 100
$CheckBoxSetBIOSTimeUTC.height            = 20
$CheckBoxSetBIOSTimeUTC.AutoSize          = $false
$CheckBoxSetBIOSTimeUTC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxSetBIOSTimeUTC.checked           = $true
$CheckBoxSetBIOSTimeUTC.Visible           = $false
$CheckBoxSetBIOSTimeUTC.Enabled           = $true

$CheckBoxSetBIOSTimeLocal                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetBIOSTimeLocal.text               = "Local BIOS Time "
$CheckBoxSetBIOSTimeLocal.location           = New-Object System.Drawing.Point(110,590)
$CheckBoxSetBIOSTimeLocal.width              = 600
$CheckBoxSetBIOSTimeLocal.height             = 20
$CheckBoxSetBIOSTimeLocal.AutoSize           = $false
$CheckBoxSetBIOSTimeLocal.Font               = 'Microsoft Sans Serif,10'
$CheckBoxSetBIOSTimeLocal.checked            = $false
$CheckBoxSetBIOSTimeLocal.Visible            = $false
$CheckBoxSetBIOSTimeLocal.Enabled            = $true
$CheckBoxSetBIOSTimeLocal.Name               = "SetBIOSTimeLocal"

#--Disable--Enable--Hibernation
# DisableHibernation EnableHibernation

$CheckBoxDisableHibernation                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableHibernation.text              = "Disable "
$CheckBoxDisableHibernation.location          = New-Object System.Drawing.Point(10,610)
$CheckBoxDisableHibernation.width             = 100
$CheckBoxDisableHibernation.height            = 20
$CheckBoxDisableHibernation.AutoSize          = $false
$CheckBoxDisableHibernation.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableHibernation.checked           = $true
$CheckBoxDisableHibernation.Visible           = $false
$CheckBoxDisableHibernation.Enabled           = $true

$CheckBoxEnableHibernation                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableHibernation.text               = "Enable Hibernation"
$CheckBoxEnableHibernation.location           = New-Object System.Drawing.Point(110,610)
$CheckBoxEnableHibernation.width              = 600
$CheckBoxEnableHibernation.height             = 20
$CheckBoxEnableHibernation.AutoSize           = $false
$CheckBoxEnableHibernation.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableHibernation.checked            = $false
$CheckBoxEnableHibernation.Visible            = $false
$CheckBoxEnableHibernation.Enabled            = $true

#--Disable--Enable--FastStartup
# DisableFastStartup EnableFastStartup

$CheckBoxDisableFastStartup                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableFastStartup.text              = "Disable "
$CheckBoxDisableFastStartup.location          = New-Object System.Drawing.Point(10,630)
$CheckBoxDisableFastStartup.width             = 100
$CheckBoxDisableFastStartup.height            = 20
$CheckBoxDisableFastStartup.AutoSize          = $false
$CheckBoxDisableFastStartup.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableFastStartup.checked           = $true
$CheckBoxDisableFastStartup.Visible           = $false
$CheckBoxDisableFastStartup.Enabled           = $true

$CheckBoxEnableFastStartup                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableFastStartup.text               = "Enable Fast Startup"
$CheckBoxEnableFastStartup.location           = New-Object System.Drawing.Point(110,630)
$CheckBoxEnableFastStartup.width              = 600
$CheckBoxEnableFastStartup.height             = 20
$CheckBoxEnableFastStartup.AutoSize           = $false
$CheckBoxEnableFastStartup.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableFastStartup.checked            = $false
$CheckBoxEnableFastStartup.Visible            = $false
$CheckBoxEnableFastStartup.Enabled            = $true

#--Disable--Enable--Multicast
# DisableMulticasting EnableMulticasting

$CheckBoxDisableMulticasting                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableMulticasting.text              = "Disable "
$CheckBoxDisableMulticasting.location          = New-Object System.Drawing.Point(10,650)
$CheckBoxDisableMulticasting.width             = 100
$CheckBoxDisableMulticasting.height            = 20
$CheckBoxDisableMulticasting.AutoSize          = $false
$CheckBoxDisableMulticasting.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableMulticasting.checked           = $true
$CheckBoxDisableMulticasting.Visible           = $false
$CheckBoxDisableMulticasting.Enabled           = $true

$CheckBoxEnableMulticasting                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableMulticasting.text               = "Enable Multicasting"
$CheckBoxEnableMulticasting.location           = New-Object System.Drawing.Point(110,650)
$CheckBoxEnableMulticasting.width              = 600
$CheckBoxEnableMulticasting.height             = 20
$CheckBoxEnableMulticasting.AutoSize           = $false
$CheckBoxEnableMulticasting.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableMulticasting.checked            = $false
$CheckBoxEnableMulticasting.Visible            = $false
$CheckBoxEnableMulticasting.Enabled            = $true

#--Disable--Enable--IPV6
# EnableIPV6 DisableIPV6

$CheckBoxEnableIPV6                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableIPV6.text              = "Enable "
$CheckBoxEnableIPV6.location          = New-Object System.Drawing.Point(10,670)
$CheckBoxEnableIPV6.width             = 100
$CheckBoxEnableIPV6.height            = 20
$CheckBoxEnableIPV6.AutoSize          = $false
$CheckBoxEnableIPV6.Font              = 'Microsoft Sans Serif,10'
$CheckBoxEnableIPV6.checked           = $false
$CheckBoxEnableIPV6.Visible           = $false
$CheckBoxEnableIPV6.Enabled           = $true

$CheckBoxDisableIPV6                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableIPV6.text               = "Dislable IPV6"
$CheckBoxDisableIPV6.location           = New-Object System.Drawing.Point(110,670)
$CheckBoxDisableIPV6.width              = 600
$CheckBoxDisableIPV6.height             = 20
$CheckBoxDisableIPV6.AutoSize           = $false
$CheckBoxDisableIPV6.Font               = 'Microsoft Sans Serif,10'
$CheckBoxDisableIPV6.checked            = $true
$CheckBoxDisableIPV6.Visible            = $false
$CheckBoxDisableIPV6.Enabled            = $true


#--UI Tweaks--#############################################################################################################################################################################################

#--Disable--Enable--Action Center
# DisableActionCenter EnableActionCenter

$CheckBoxDisableActionCenter                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableActionCenter.text              = "Disable "
$CheckBoxDisableActionCenter.location          = New-Object System.Drawing.Point(10,130)
$CheckBoxDisableActionCenter.width             = 100
$CheckBoxDisableActionCenter.height            = 20
$CheckBoxDisableActionCenter.AutoSize          = $false
$CheckBoxDisableActionCenter.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableActionCenter.checked           = $true
$CheckBoxDisableActionCenter.Visible           = $false
$CheckBoxDisableActionCenter.Enabled           = $true

$CheckBoxEnableActionCenter                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableActionCenter.text               = "Enable Action Center"
$CheckBoxEnableActionCenter.location           = New-Object System.Drawing.Point(110,130)
$CheckBoxEnableActionCenter.width              = 600
$CheckBoxEnableActionCenter.height             = 20
$CheckBoxEnableActionCenter.AutoSize           = $false
$CheckBoxEnableActionCenter.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableActionCenter.checked            = $false
$CheckBoxEnableActionCenter.Visible            = $false
$CheckBoxEnableActionCenter.Enabled            = $true

#--Disable--Enable--Lock Screen
# DisableLockScreen EnableLockScreen

$CheckBoxDisableLockScreen                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableLockScreen.text              = "Disable "
$CheckBoxDisableLockScreen.location          = New-Object System.Drawing.Point(10,150)
$CheckBoxDisableLockScreen.width             = 100
$CheckBoxDisableLockScreen.height            = 20
$CheckBoxDisableLockScreen.AutoSize          = $false
$CheckBoxDisableLockScreen.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableLockScreen.checked           = $true
$CheckBoxDisableLockScreen.Visible           = $false
$CheckBoxDisableLockScreen.Enabled           = $true

$CheckBoxEnableLockScreen                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableLockScreen.text               = "Enable Lock Screen"
$CheckBoxEnableLockScreen.location           = New-Object System.Drawing.Point(110,150)
$CheckBoxEnableLockScreen.width              = 600
$CheckBoxEnableLockScreen.height             = 20
$CheckBoxEnableLockScreen.AutoSize           = $false
$CheckBoxEnableLockScreen.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableLockScreen.checked            = $false
$CheckBoxEnableLockScreen.Visible            = $false
$CheckBoxEnableLockScreen.Enabled            = $true

#--Hide--Show--Network on Lock Screen
# HideNetworkFromLockScreen ShowNetworkOnLockScreen

$CheckBoxHideNetworkOnLockScreen                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideNetworkOnLockScreen.text              = "Hide "
$CheckBoxHideNetworkOnLockScreen.location          = New-Object System.Drawing.Point(10,170)
$CheckBoxHideNetworkOnLockScreen.width             = 100
$CheckBoxHideNetworkOnLockScreen.height            = 20
$CheckBoxHideNetworkOnLockScreen.AutoSize          = $false
$CheckBoxHideNetworkOnLockScreen.Font              = 'Microsoft Sans Serif,10'
$CheckBoxHideNetworkOnLockScreen.checked           = $true
$CheckBoxHideNetworkOnLockScreen.Visible           = $false
$CheckBoxHideNetworkOnLockScreen.Enabled           = $true

$CheckBoxShowNetworkOnLockScreen                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowNetworkOnLockScreen.text               = "Show Network on Lock Screen"
$CheckBoxShowNetworkOnLockScreen.location           = New-Object System.Drawing.Point(110,170)
$CheckBoxShowNetworkOnLockScreen.width              = 600
$CheckBoxShowNetworkOnLockScreen.height             = 20
$CheckBoxShowNetworkOnLockScreen.AutoSize           = $false
$CheckBoxShowNetworkOnLockScreen.Font               = 'Microsoft Sans Serif,10'
$CheckBoxShowNetworkOnLockScreen.checked            = $false
$CheckBoxShowNetworkOnLockScreen.Visible            = $false
$CheckBoxShowNetworkOnLockScreen.Enabled            = $true

#--Hide--Show--Shutdown On Lock Screen
# HideShutdownFromLockScreen ShowShutdownOnLockScreen

$CheckBoxHideShutdownFromLockScreen                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideShutdownFromLockScreen.text              = "Hide "
$CheckBoxHideShutdownFromLockScreen.location          = New-Object System.Drawing.Point(10,190)
$CheckBoxHideShutdownFromLockScreen.width             = 100
$CheckBoxHideShutdownFromLockScreen.height            = 20
$CheckBoxHideShutdownFromLockScreen.AutoSize          = $false
$CheckBoxHideShutdownFromLockScreen.Font              = 'Microsoft Sans Serif,10'
$CheckBoxHideShutdownFromLockScreen.checked           = $false
$CheckBoxHideShutdownFromLockScreen.Visible           = $false
$CheckBoxHideShutdownFromLockScreen.Enabled           = $true

$CheckBoxShowShutdownOnLockScreen                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowShutdownOnLockScreen.text               = "Show Shutdown On Lock Screen "
$CheckBoxShowShutdownOnLockScreen.location           = New-Object System.Drawing.Point(110,190)
$CheckBoxShowShutdownOnLockScreen.width              = 600
$CheckBoxShowShutdownOnLockScreen.height             = 20
$CheckBoxShowShutdownOnLockScreen.AutoSize           = $false
$CheckBoxShowShutdownOnLockScreen.Font               = 'Microsoft Sans Serif,10'
$CheckBoxShowShutdownOnLockScreen.checked            = $true
$CheckBoxShowShutdownOnLockScreen.Visible            = $false
$CheckBoxShowShutdownOnLockScreen.Enabled            = $true

#--Disable--Enable--Stickey Keys
# DisableStickyKeys EnableStickyKeys

$CheckBoxDisableStickyKeys                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableStickyKeys.text              = "Disable "
$CheckBoxDisableStickyKeys.location          = New-Object System.Drawing.Point(10,210)
$CheckBoxDisableStickyKeys.width             = 100
$CheckBoxDisableStickyKeys.height            = 20
$CheckBoxDisableStickyKeys.AutoSize          = $false
$CheckBoxDisableStickyKeys.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableStickyKeys.checked           = $true
$CheckBoxDisableStickyKeys.Visible           = $false
$CheckBoxDisableStickyKeys.Enabled           = $true

$CheckBoxEnableStickyKeys                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableStickyKeys.text               = "Enable Sticky Keys"
$CheckBoxEnableStickyKeys.location           = New-Object System.Drawing.Point(110,210)
$CheckBoxEnableStickyKeys.width              = 600
$CheckBoxEnableStickyKeys.height             = 20
$CheckBoxEnableStickyKeys.AutoSize           = $false
$CheckBoxEnableStickyKeys.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableStickyKeys.checked            = $false
$CheckBoxEnableStickyKeys.Visible            = $false
$CheckBoxEnableStickyKeys.Enabled            = $true

#--Show--Hide--Task Manager Details
# ShowTaskManagerDetails HideTaskManagerDetails

$CheckBoxShowTaskManagerDetails                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowTaskManagerDetails.text              = "Show "
$CheckBoxShowTaskManagerDetails.location          = New-Object System.Drawing.Point(10,230)
$CheckBoxShowTaskManagerDetails.width             = 100
$CheckBoxShowTaskManagerDetails.height            = 20
$CheckBoxShowTaskManagerDetails.AutoSize          = $false
$CheckBoxShowTaskManagerDetails.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowTaskManagerDetails.checked           = $true
$CheckBoxShowTaskManagerDetails.Visible           = $false
$CheckBoxShowTaskManagerDetails.Enabled           = $true

$CheckBoxHideTaskManagerDetails                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideTaskManagerDetails.text               = "Hide Task Manager Details "
$CheckBoxHideTaskManagerDetails.location           = New-Object System.Drawing.Point(110,230)
$CheckBoxHideTaskManagerDetails.width              = 600
$CheckBoxHideTaskManagerDetails.height             = 20
$CheckBoxHideTaskManagerDetails.AutoSize           = $false
$CheckBoxHideTaskManagerDetails.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideTaskManagerDetails.checked            = $false
$CheckBoxHideTaskManagerDetails.Visible            = $false
$CheckBoxHideTaskManagerDetails.Enabled            = $true

#--Show--Hide--File Operations Details
# ShowFileOperationsDetails HideFileOperationsDetails

$CheckBoxShowFileOperationsDetails                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowFileOperationsDetails.text              = "Show "
$CheckBoxShowFileOperationsDetails.location          = New-Object System.Drawing.Point(10,250)
$CheckBoxShowFileOperationsDetails.width             = 100
$CheckBoxShowFileOperationsDetails.height            = 20
$CheckBoxShowFileOperationsDetails.AutoSize          = $false
$CheckBoxShowFileOperationsDetails.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowFileOperationsDetails.checked           = $true
$CheckBoxShowFileOperationsDetails.Visible           = $false
$CheckBoxShowFileOperationsDetails.Enabled           = $true

$CheckBoxHideFileOperationsDetails                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideFileOperationsDetails.text               = "Hide File Operations Details "
$CheckBoxHideFileOperationsDetails.location           = New-Object System.Drawing.Point(110,250)
$CheckBoxHideFileOperationsDetails.width              = 600
$CheckBoxHideFileOperationsDetails.height             = 20
$CheckBoxHideFileOperationsDetails.AutoSize           = $false
$CheckBoxHideFileOperationsDetails.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideFileOperationsDetails.checked            = $false
$CheckBoxHideFileOperationsDetails.Visible            = $false
$CheckBoxHideFileOperationsDetails.Enabled            = $true

#--Disable--Enable--File Delete Confirm
# DisableFileDeleteConfirm EnableFileDeleteConfirm

$CheckBoxDisableFileDeleteConfirm                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableFileDeleteConfirm.text              = "Disable "
$CheckBoxDisableFileDeleteConfirm.location          = New-Object System.Drawing.Point(10,270)
$CheckBoxDisableFileDeleteConfirm.width             = 100
$CheckBoxDisableFileDeleteConfirm.height            = 20
$CheckBoxDisableFileDeleteConfirm.AutoSize          = $false
$CheckBoxDisableFileDeleteConfirm.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableFileDeleteConfirm.checked           = $true
$CheckBoxDisableFileDeleteConfirm.Visible           = $false
$CheckBoxDisableFileDeleteConfirm.Enabled           = $true

$CheckBoxEnableFileDeleteConfirm                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableFileDeleteConfirm.text               = "Enable File Delete Confirm "
$CheckBoxEnableFileDeleteConfirm.location           = New-Object System.Drawing.Point(110,270)
$CheckBoxEnableFileDeleteConfirm.width              = 600
$CheckBoxEnableFileDeleteConfirm.height             = 20
$CheckBoxEnableFileDeleteConfirm.AutoSize           = $false
$CheckBoxEnableFileDeleteConfirm.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableFileDeleteConfirm.checked            = $false
$CheckBoxEnableFileDeleteConfirm.Visible            = $false
$CheckBoxEnableFileDeleteConfirm.Enabled            = $true

#--Show--Hide--Taskbar Search Box
# ShowTaskbarSearchBox HideTaskbarSearchBox

$CheckBoxShowTaskbarSearchBox                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowTaskbarSearchBox.text              = "Show "
$CheckBoxShowTaskbarSearchBox.location          = New-Object System.Drawing.Point(10,290)
$CheckBoxShowTaskbarSearchBox.width             = 100
$CheckBoxShowTaskbarSearchBox.height            = 20
$CheckBoxShowTaskbarSearchBox.AutoSize          = $false
$CheckBoxShowTaskbarSearchBox.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowTaskbarSearchBox.checked           = $true
$CheckBoxShowTaskbarSearchBox.Visible           = $false
$CheckBoxShowTaskbarSearchBox.Enabled           = $true

$CheckBoxHideTaskbarSearchBox                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideTaskbarSearchBox.text               = "Hide Taskbar Search Box "
$CheckBoxHideTaskbarSearchBox.location           = New-Object System.Drawing.Point(110,290)
$CheckBoxHideTaskbarSearchBox.width              = 600
$CheckBoxHideTaskbarSearchBox.height             = 20
$CheckBoxHideTaskbarSearchBox.AutoSize           = $false
$CheckBoxHideTaskbarSearchBox.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideTaskbarSearchBox.checked            = $false
$CheckBoxHideTaskbarSearchBox.Visible            = $false
$CheckBoxHideTaskbarSearchBox.Enabled            = $true

#--Show--Hide--Task View
# ShowTaskView HideTaskView

$CheckBoxShowTaskView                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowTaskView.text              = "Show Task View "
$CheckBoxShowTaskView.location          = New-Object System.Drawing.Point(10,310)
$CheckBoxShowTaskView.width             = 100
$CheckBoxShowTaskView.height            = 20
$CheckBoxShowTaskView.AutoSize          = $false
$CheckBoxShowTaskView.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowTaskView.checked           = $true
$CheckBoxShowTaskView.Visible           = $false
$CheckBoxShowTaskView.Enabled           = $true

$CheckBoxHideTaskView                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideTaskView.text               = "Hide Task View "
$CheckBoxHideTaskView.location           = New-Object System.Drawing.Point(110,310)
$CheckBoxHideTaskView.width              = 600
$CheckBoxHideTaskView.height             = 20
$CheckBoxHideTaskView.AutoSize           = $false
$CheckBoxHideTaskView.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideTaskView.checked            = $false
$CheckBoxHideTaskView.Visible            = $false
$CheckBoxHideTaskView.Enabled            = $true

#--Small--Large--Taskbar Icons
# ShowSmallTaskbarIcons ShowLargeTaskbarIcons

$CheckBoxSmallTaskbarIcons                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxSmallTaskbarIcons.text              = "Small "
$CheckBoxSmallTaskbarIcons.location          = New-Object System.Drawing.Point(10,330)
$CheckBoxSmallTaskbarIcons.width             = 100
$CheckBoxSmallTaskbarIcons.height            = 20
$CheckBoxSmallTaskbarIcons.AutoSize          = $false
$CheckBoxSmallTaskbarIcons.Font              = 'Microsoft Sans Serif,10'
$CheckBoxSmallTaskbarIcons.checked           = $true
$CheckBoxSmallTaskbarIcons.Visible           = $false
$CheckBoxSmallTaskbarIcons.Enabled           = $true

$CheckBoxLargeTaskbarIcons                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxLargeTaskbarIcons.text               = "Large Taskbar Icons "
$CheckBoxLargeTaskbarIcons.location           = New-Object System.Drawing.Point(110,330)
$CheckBoxLargeTaskbarIcons.width              = 600
$CheckBoxLargeTaskbarIcons.height             = 20
$CheckBoxLargeTaskbarIcons.AutoSize           = $false
$CheckBoxLargeTaskbarIcons.Font               = 'Microsoft Sans Serif,10'
$CheckBoxLargeTaskbarIcons.checked            = $false
$CheckBoxLargeTaskbarIcons.Visible            = $false
$CheckBoxLargeTaskbarIcons.Enabled            = $true

#--Show--Hide--Taskbar Titles
# ShowTaskbarTitles HideTaskbarTitles

$CheckBoxShowTaskbarTitles                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowTaskbarTitles.text              = "Show "
$CheckBoxShowTaskbarTitles.location          = New-Object System.Drawing.Point(10,350)
$CheckBoxShowTaskbarTitles.width             = 100
$CheckBoxShowTaskbarTitles.height            = 20
$CheckBoxShowTaskbarTitles.AutoSize          = $false
$CheckBoxShowTaskbarTitles.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowTaskbarTitles.checked           = $true
$CheckBoxShowTaskbarTitles.Visible           = $false
$CheckBoxShowTaskbarTitles.Enabled           = $true

$CheckBoxHideTaskbarTitles                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideTaskbarTitles.text               = "Hide Taskbar Titles "
$CheckBoxHideTaskbarTitles.location           = New-Object System.Drawing.Point(110,350)
$CheckBoxHideTaskbarTitles.width              = 600
$CheckBoxHideTaskbarTitles.height             = 20
$CheckBoxHideTaskbarTitles.AutoSize           = $false
$CheckBoxHideTaskbarTitles.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideTaskbarTitles.checked            = $false
$CheckBoxHideTaskbarTitles.Visible            = $false
$CheckBoxHideTaskbarTitles.Enabled            = $true

#--Show--Hide--Taskbar People Icon
# ShowTaskbarPeopleIcon HideTaskbarPeopleIcon

$CheckBoxShowTaskbarPeopleIcon                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowTaskbarPeopleIcon.text              = "Show "
$CheckBoxShowTaskbarPeopleIcon.location          = New-Object System.Drawing.Point(10,370)
$CheckBoxShowTaskbarPeopleIcon.width             = 100
$CheckBoxShowTaskbarPeopleIcon.height            = 20
$CheckBoxShowTaskbarPeopleIcon.AutoSize          = $false
$CheckBoxShowTaskbarPeopleIcon.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowTaskbarPeopleIcon.checked           = $false
$CheckBoxShowTaskbarPeopleIcon.Visible           = $false
$CheckBoxShowTaskbarPeopleIcon.Enabled           = $true

$CheckBoxHideTaskbarPeopleIcon                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideTaskbarPeopleIcon.text               = "Hide Taskbar People Icon "
$CheckBoxHideTaskbarPeopleIcon.location           = New-Object System.Drawing.Point(110,370)
$CheckBoxHideTaskbarPeopleIcon.width              = 600
$CheckBoxHideTaskbarPeopleIcon.height             = 20
$CheckBoxHideTaskbarPeopleIcon.AutoSize           = $false
$CheckBoxHideTaskbarPeopleIcon.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideTaskbarPeopleIcon.checked            = $true
$CheckBoxHideTaskbarPeopleIcon.Visible            = $false
$CheckBoxHideTaskbarPeopleIcon.Enabled            = $true

#--Show--Hide--All Try Icons
# ShowTrayIcons HideTrayIcons

$CheckBoxShowTrayIcons                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowTrayIcons.text              = "Show "
$CheckBoxShowTrayIcons.location          = New-Object System.Drawing.Point(10,390)
$CheckBoxShowTrayIcons.width             = 100
$CheckBoxShowTrayIcons.height            = 20
$CheckBoxShowTrayIcons.AutoSize          = $false
$CheckBoxShowTrayIcons.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowTrayIcons.checked           = $true
$CheckBoxShowTrayIcons.Visible           = $false
$CheckBoxShowTrayIcons.Enabled           = $true

$CheckBoxHideTrayIcons                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideTrayIcons.text               = "Hide All Tray Icons "
$CheckBoxHideTrayIcons.location           = New-Object System.Drawing.Point(110,390)
$CheckBoxHideTrayIcons.width              = 600
$CheckBoxHideTrayIcons.height             = 20
$CheckBoxHideTrayIcons.AutoSize           = $false
$CheckBoxHideTrayIcons.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideTrayIcons.checked            = $false
$CheckBoxHideTrayIcons.Visible            = $false
$CheckBoxHideTrayIcons.Enabled            = $true

#--Show--Hide--Known Extensions
# ShowKnownExtensions HideKnownExtensions

$CheckBoxShowKnownExtensions                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowKnownExtensions.text              = "Show "
$CheckBoxShowKnownExtensions.location          = New-Object System.Drawing.Point(10,410)
$CheckBoxShowKnownExtensions.width             = 100
$CheckBoxShowKnownExtensions.height            = 20
$CheckBoxShowKnownExtensions.AutoSize          = $false
$CheckBoxShowKnownExtensions.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowKnownExtensions.checked           = $true
$CheckBoxShowKnownExtensions.Visible           = $false
$CheckBoxShowKnownExtensions.Enabled           = $true

$CheckBoxHideKnownExtensions                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideKnownExtensions.text               = "Hide Known Extensions "
$CheckBoxHideKnownExtensions.location           = New-Object System.Drawing.Point(110,410)
$CheckBoxHideKnownExtensions.width              = 600
$CheckBoxHideKnownExtensions.height             = 20
$CheckBoxHideKnownExtensions.AutoSize           = $false
$CheckBoxHideKnownExtensions.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideKnownExtensions.checked            = $false
$CheckBoxHideKnownExtensions.Visible            = $false
$CheckBoxHideKnownExtensions.Enabled            = $true

#--Show--Hide--Hidden Files
# ShowHiddenFiles HideHiddenFiles

$CheckBoxShowHiddenFiles                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowHiddenFiles.text              = "Show "
$CheckBoxShowHiddenFiles.location          = New-Object System.Drawing.Point(10,430)
$CheckBoxShowHiddenFiles.width             = 100
$CheckBoxShowHiddenFiles.height            = 20
$CheckBoxShowHiddenFiles.AutoSize          = $false
$CheckBoxShowHiddenFiles.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowHiddenFiles.checked           = $false
$CheckBoxShowHiddenFiles.Visible           = $false
$CheckBoxShowHiddenFiles.Enabled           = $true

$CheckBoxHideHiddenFiles                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideHiddenFiles.text               = "Hide Hidden Files "
$CheckBoxHideHiddenFiles.location           = New-Object System.Drawing.Point(110,430)
$CheckBoxHideHiddenFiles.width              = 600
$CheckBoxHideHiddenFiles.height             = 20
$CheckBoxHideHiddenFiles.AutoSize           = $false
$CheckBoxHideHiddenFiles.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideHiddenFiles.checked            = $true
$CheckBoxHideHiddenFiles.Visible            = $false
$CheckBoxHideHiddenFiles.Enabled            = $true

#--Show--Hide--Sync Provider Notifications
# ShowSyncNotifications HideSyncNotifications

$CheckBoxShowSyncNotifications                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowSyncNotifications.text              = "Show "
$CheckBoxShowSyncNotifications.location          = New-Object System.Drawing.Point(10,450)
$CheckBoxShowSyncNotifications.width             = 100
$CheckBoxShowSyncNotifications.height            = 20
$CheckBoxShowSyncNotifications.AutoSize          = $false
$CheckBoxShowSyncNotifications.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowSyncNotifications.checked           = $true
$CheckBoxShowSyncNotifications.Visible           = $false
$CheckBoxShowSyncNotifications.Enabled           = $true

$CheckBoxHideSyncNotifications                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideSyncNotifications.text               = "Hide Sync Notifications "
$CheckBoxHideSyncNotifications.location           = New-Object System.Drawing.Point(110,450)
$CheckBoxHideSyncNotifications.width              = 600
$CheckBoxHideSyncNotifications.height             = 20
$CheckBoxHideSyncNotifications.AutoSize           = $false
$CheckBoxHideSyncNotifications.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideSyncNotifications.checked            = $false
$CheckBoxHideSyncNotifications.Visible            = $false
$CheckBoxHideSyncNotifications.Enabled            = $true

#--Show--Hide--Recently and frequently used item shortcuts in Explorer
# ShowRecentShortcuts HideRecentShortcuts

$CheckBoxShowRecentShortcuts                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowRecentShortcuts.text              = "Show "
$CheckBoxShowRecentShortcuts.location          = New-Object System.Drawing.Point(10,470)
$CheckBoxShowRecentShortcuts.width             = 100
$CheckBoxShowRecentShortcuts.height            = 20
$CheckBoxShowRecentShortcuts.AutoSize          = $false
$CheckBoxShowRecentShortcuts.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowRecentShortcuts.checked           = $true
$CheckBoxShowRecentShortcuts.Visible           = $false
$CheckBoxShowRecentShortcuts.Enabled           = $true

$CheckBoxHideRecentShortcuts                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideRecentShortcuts.text               = "Hide Recently and Frequently used item shortcuts in Explorer "
$CheckBoxHideRecentShortcuts.location           = New-Object System.Drawing.Point(110,470)
$CheckBoxHideRecentShortcuts.width              = 600
$CheckBoxHideRecentShortcuts.height             = 20
$CheckBoxHideRecentShortcuts.AutoSize           = $false
$CheckBoxHideRecentShortcuts.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideRecentShortcuts.checked            = $false
$CheckBoxHideRecentShortcuts.Visible            = $false
$CheckBoxHideRecentShortcuts.Enabled            = $true

#--Default Explorer view to Quick Access OR This PC
# SetExplorerQuickAccess SetExplorerThisPC

$CheckBoxSetExplorerQuickAccess                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetExplorerQuickAccess.text              = "Quick Access "
$CheckBoxSetExplorerQuickAccess.location          = New-Object System.Drawing.Point(10,490)
$CheckBoxSetExplorerQuickAccess.width             = 100
$CheckBoxSetExplorerQuickAccess.height            = 20
$CheckBoxSetExplorerQuickAccess.AutoSize          = $false
$CheckBoxSetExplorerQuickAccess.Font              = 'Microsoft Sans Serif,10'
$CheckBoxSetExplorerQuickAccess.checked           = $true
$CheckBoxSetExplorerQuickAccess.Visible           = $false
$CheckBoxSetExplorerQuickAccess.Enabled           = $true

$CheckBoxSetExplorerThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetExplorerThisPC.text               = "This PC explorere view "
$CheckBoxSetExplorerThisPC.location           = New-Object System.Drawing.Point(110,490)
$CheckBoxSetExplorerThisPC.width              = 600
$CheckBoxSetExplorerThisPC.height             = 20
$CheckBoxSetExplorerThisPC.AutoSize           = $false
$CheckBoxSetExplorerThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxSetExplorerThisPC.checked            = $false
$CheckBoxSetExplorerThisPC.Visible            = $false
$CheckBoxSetExplorerThisPC.Enabled            = $true

#--Show--Hide--User Folder On the Desktop
# ShowThisPCOnDesktop HideThisPCFromDesktop

$CheckBoxShowThisPCOnDesktop                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowThisPCOnDesktop.text              = "Show "
$CheckBoxShowThisPCOnDesktop.location          = New-Object System.Drawing.Point(10,510)
$CheckBoxShowThisPCOnDesktop.width             = 100
$CheckBoxShowThisPCOnDesktop.height            = 20
$CheckBoxShowThisPCOnDesktop.AutoSize          = $false
$CheckBoxShowThisPCOnDesktop.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowThisPCOnDesktop.checked           = $true
$CheckBoxShowThisPCOnDesktop.Visible           = $false
$CheckBoxShowThisPCOnDesktop.Enabled           = $true

$CheckBoxHideThisPCFromDesktop                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideThisPCFromDesktop.text               = "Hide This PC Folder on Desktop "
$CheckBoxHideThisPCFromDesktop.location           = New-Object System.Drawing.Point(110,510)
$CheckBoxHideThisPCFromDesktop.width              = 600
$CheckBoxHideThisPCFromDesktop.height             = 20
$CheckBoxHideThisPCFromDesktop.AutoSize           = $false
$CheckBoxHideThisPCFromDesktop.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideThisPCFromDesktop.checked            = $false
$CheckBoxHideThisPCFromDesktop.Visible            = $false
$CheckBoxHideThisPCFromDesktop.Enabled            = $true

#--Show--Hide--User Folder On Desktop
# ShowUserFolderOnDesktop HideUserFolderFromDesktop

$CheckBoxShowUserFolderOnDesktop                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowUserFolderOnDesktop.text              = "Show "
$CheckBoxShowUserFolderOnDesktop.location          = New-Object System.Drawing.Point(10,530)
$CheckBoxShowUserFolderOnDesktop.width             = 100
$CheckBoxShowUserFolderOnDesktop.height            = 20
$CheckBoxShowUserFolderOnDesktop.AutoSize          = $false
$CheckBoxShowUserFolderOnDesktop.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowUserFolderOnDesktop.checked           = $true
$CheckBoxShowUserFolderOnDesktop.Visible           = $false
$CheckBoxShowUserFolderOnDesktop.Enabled           = $true

$CheckBoxHideUserFolderFromDesktop                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideUserFolderFromDesktop.text               = "Hide User Folder On Desktop "
$CheckBoxHideUserFolderFromDesktop.location           = New-Object System.Drawing.Point(110,530)
$CheckBoxHideUserFolderFromDesktop.width              = 600
$CheckBoxHideUserFolderFromDesktop.height             = 20
$CheckBoxHideUserFolderFromDesktop.AutoSize           = $false
$CheckBoxHideUserFolderFromDesktop.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideUserFolderFromDesktop.checked            = $false
$CheckBoxHideUserFolderFromDesktop.Visible            = $false
$CheckBoxHideUserFolderFromDesktop.Enabled            = $true

#--Show--Hide--Desktop In This PC
# ShowDesktopInThisPC HideDesktopFromThisPC

$CheckBoxShowDesktopInThisPC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowDesktopInThisPC.text              = "Show "
$CheckBoxShowDesktopInThisPC.location          = New-Object System.Drawing.Point(10,550)
$CheckBoxShowDesktopInThisPC.width             = 100
$CheckBoxShowDesktopInThisPC.height            = 20
$CheckBoxShowDesktopInThisPC.AutoSize          = $false
$CheckBoxShowDesktopInThisPC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowDesktopInThisPC.checked           = $true
$CheckBoxShowDesktopInThisPC.Visible           = $false
$CheckBoxShowDesktopInThisPC.Enabled           = $true

$CheckBoxHideDesktopFromThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideDesktopFromThisPC.text               = "Hide Desktop icon from This PC "
$CheckBoxHideDesktopFromThisPC.location           = New-Object System.Drawing.Point(110,550)
$CheckBoxHideDesktopFromThisPC.width              = 600
$CheckBoxHideDesktopFromThisPC.height             = 20
$CheckBoxHideDesktopFromThisPC.AutoSize           = $false
$CheckBoxHideDesktopFromThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideDesktopFromThisPC.checked            = $false
$CheckBoxHideDesktopFromThisPC.Visible            = $false
$CheckBoxHideDesktopFromThisPC.Enabled            = $true

#--Show--Hide--Documents Icon From This PC
# ShowDocumentsInThisPC HideDocumentsFromThisPC

$CheckBoxShowDocumentsInThisPC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowDocumentsInThisPC.text              = "Show "
$CheckBoxShowDocumentsInThisPC.location          = New-Object System.Drawing.Point(10,570)
$CheckBoxShowDocumentsInThisPC.width             = 100
$CheckBoxShowDocumentsInThisPC.height            = 20
$CheckBoxShowDocumentsInThisPC.AutoSize          = $false
$CheckBoxShowDocumentsInThisPC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowDocumentsInThisPC.checked           = $true
$CheckBoxShowDocumentsInThisPC.Visible           = $false
$CheckBoxShowDocumentsInThisPC.Enabled           = $true

$CheckBoxHideDocumentsFromThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideDocumentsFromThisPC.text               = "Hide Documents Icon from This PC "
$CheckBoxHideDocumentsFromThisPC.location           = New-Object System.Drawing.Point(110,570)
$CheckBoxHideDocumentsFromThisPC.width              = 600
$CheckBoxHideDocumentsFromThisPC.height             = 20
$CheckBoxHideDocumentsFromThisPC.AutoSize           = $false
$CheckBoxHideDocumentsFromThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideDocumentsFromThisPC.checked            = $false
$CheckBoxHideDocumentsFromThisPC.Visible            = $false
$CheckBoxHideDocumentsFromThisPC.Enabled            = $true

#--Show--Hide--Downloads icon from This PC
# ShowDownloadsInThisPC HideDownloadsFromThisPC

$CheckBoxShowDownloadsInThisPC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowDownloadsInThisPC.text              = "Show "
$CheckBoxShowDownloadsInThisPC.location          = New-Object System.Drawing.Point(10,590)
$CheckBoxShowDownloadsInThisPC.width             = 100
$CheckBoxShowDownloadsInThisPC.height            = 20
$CheckBoxShowDownloadsInThisPC.AutoSize          = $false
$CheckBoxShowDownloadsInThisPC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowDownloadsInThisPC.checked           = $true
$CheckBoxShowDownloadsInThisPC.Visible           = $false
$CheckBoxShowDownloadsInThisPC.Enabled           = $true

$CheckBoxHideDownloadsFromThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideDownloadsFromThisPC.text               = "Hide Downloads icon from This PC "
$CheckBoxHideDownloadsFromThisPC.location           = New-Object System.Drawing.Point(110,590)
$CheckBoxHideDownloadsFromThisPC.width              = 600
$CheckBoxHideDownloadsFromThisPC.height             = 20
$CheckBoxHideDownloadsFromThisPC.AutoSize           = $false
$CheckBoxHideDownloadsFromThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideDownloadsFromThisPC.checked            = $false
$CheckBoxHideDownloadsFromThisPC.Visible            = $false
$CheckBoxHideDownloadsFromThisPC.Enabled            = $true

#--Show--Hide--Music icon in This PC
# ShowMusicInThisPC HideMusicFromThisPC

$CheckBoxShowMusicInThisPC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowMusicInThisPC.text              = "Show "
$CheckBoxShowMusicInThisPC.location          = New-Object System.Drawing.Point(10,610)
$CheckBoxShowMusicInThisPC.width             = 100
$CheckBoxShowMusicInThisPC.height            = 20
$CheckBoxShowMusicInThisPC.AutoSize          = $false
$CheckBoxShowMusicInThisPC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowMusicInThisPC.checked           = $true
$CheckBoxShowMusicInThisPC.Visible           = $false
$CheckBoxShowMusicInThisPC.Enabled           = $true

$CheckBoxHideMusicFromThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideMusicFromThisPC.text               = "Hide Music icon in This PC"
$CheckBoxHideMusicFromThisPC.location           = New-Object System.Drawing.Point(110,610)
$CheckBoxHideMusicFromThisPC.width              = 600
$CheckBoxHideMusicFromThisPC.height             = 20
$CheckBoxHideMusicFromThisPC.AutoSize           = $false
$CheckBoxHideMusicFromThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideMusicFromThisPC.checked            = $false
$CheckBoxHideMusicFromThisPC.Visible            = $false
$CheckBoxHideMusicFromThisPC.Enabled            = $true

#--Show--Hide--Pictures icon from This PC
# ShowPicturesInThisPC HidePicturesFromThisPC

$CheckBoxShowPicturesInThisPC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowPicturesInThisPC.text              = "Show "
$CheckBoxShowPicturesInThisPC.location          = New-Object System.Drawing.Point(10,630)
$CheckBoxShowPicturesInThisPC.width             = 100
$CheckBoxShowPicturesInThisPC.height            = 20
$CheckBoxShowPicturesInThisPC.AutoSize          = $false
$CheckBoxShowPicturesInThisPC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowPicturesInThisPC.checked           = $true
$CheckBoxShowPicturesInThisPC.Visible           = $false
$CheckBoxShowPicturesInThisPC.Enabled           = $true

$CheckBoxHidePicturesFromThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHidePicturesFromThisPC.text               = "Hide Pictures icon from This PC"
$CheckBoxHidePicturesFromThisPC.location           = New-Object System.Drawing.Point(110,630)
$CheckBoxHidePicturesFromThisPC.width              = 600
$CheckBoxHidePicturesFromThisPC.height             = 20
$CheckBoxHidePicturesFromThisPC.AutoSize           = $false
$CheckBoxHidePicturesFromThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHidePicturesFromThisPC.checked            = $false
$CheckBoxHidePicturesFromThisPC.Visible            = $false
$CheckBoxHidePicturesFromThisPC.Enabled            = $true

#--Show--Hide--Videos In This PC
# ShowVideosInThisPC HideVideosFromThisPC

$CheckBoxShowVideosInThisPC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowVideosInThisPC.text              = "Show "
$CheckBoxShowVideosInThisPC.location          = New-Object System.Drawing.Point(10,650)
$CheckBoxShowVideosInThisPC.width             = 100
$CheckBoxShowVideosInThisPC.height            = 20
$CheckBoxShowVideosInThisPC.AutoSize          = $false
$CheckBoxShowVideosInThisPC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShowVideosInThisPC.checked           = $true
$CheckBoxShowVideosInThisPC.Visible           = $false
$CheckBoxShowVideosInThisPC.Enabled           = $true

$CheckBoxHideVideosFromThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideVideosFromThisPC.text               = "Hide Videos From This PC"
$CheckBoxHideVideosFromThisPC.location           = New-Object System.Drawing.Point(110,650)
$CheckBoxHideVideosFromThisPC.width              = 600
$CheckBoxHideVideosFromThisPC.height             = 20
$CheckBoxHideVideosFromThisPC.AutoSize           = $false
$CheckBoxHideVideosFromThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHideVideosFromThisPC.checked            = $false
$CheckBoxHideVideosFromThisPC.Visible            = $false
$CheckBoxHideVideosFromThisPC.Enabled            = $true

#--Show--Hide--3D Objects icon from This PC
# Show3DObjectsInThisPC Hide3DObjectsFromThisPC

$CheckBoxShow3DObjectsInThisPC                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxShow3DObjectsInThisPC.text              = "Show "
$CheckBoxShow3DObjectsInThisPC.location          = New-Object System.Drawing.Point(10,670)
$CheckBoxShow3DObjectsInThisPC.width             = 100
$CheckBoxShow3DObjectsInThisPC.height            = 20
$CheckBoxShow3DObjectsInThisPC.AutoSize          = $false
$CheckBoxShow3DObjectsInThisPC.Font              = 'Microsoft Sans Serif,10'
$CheckBoxShow3DObjectsInThisPC.checked           = $false
$CheckBoxShow3DObjectsInThisPC.Visible           = $false
$CheckBoxShow3DObjectsInThisPC.Enabled           = $true

$CheckBoxHide3DObjectsFromThisPC                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxHide3DObjectsFromThisPC.text               = "Hide 3D Objects icon from This PC "
$CheckBoxHide3DObjectsFromThisPC.location           = New-Object System.Drawing.Point(110,670)
$CheckBoxHide3DObjectsFromThisPC.width              = 600
$CheckBoxHide3DObjectsFromThisPC.height             = 20
$CheckBoxHide3DObjectsFromThisPC.AutoSize           = $false
$CheckBoxHide3DObjectsFromThisPC.Font               = 'Microsoft Sans Serif,10'
$CheckBoxHide3DObjectsFromThisPC.checked            = $true
$CheckBoxHide3DObjectsFromThisPC.Visible            = $false
$CheckBoxHide3DObjectsFromThisPC.Enabled            = $true

#--Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
#--Adjusts visual effects for appearance
# SetVisualFXPerformance SetVisualFXAppearance

$CheckBoxSetVisualFXPerformance                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetVisualFXPerformance.text              = "Preformance "
$CheckBoxSetVisualFXPerformance.location          = New-Object System.Drawing.Point(10,690)
$CheckBoxSetVisualFXPerformance.width             = 100
$CheckBoxSetVisualFXPerformance.height            = 20
$CheckBoxSetVisualFXPerformance.AutoSize          = $false
$CheckBoxSetVisualFXPerformance.Font              = 'Microsoft Sans Serif,10'
$CheckBoxSetVisualFXPerformance.checked           = $true
$CheckBoxSetVisualFXPerformance.Visible           = $false
$CheckBoxSetVisualFXPerformance.Enabled           = $true

$CheckBoxSetVisualFXAppearance                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetVisualFXAppearance.text               = "Appearance - Adjusts visual effects for Preformance or Appearance "
$CheckBoxSetVisualFXAppearance.location           = New-Object System.Drawing.Point(110,690)
$CheckBoxSetVisualFXAppearance.width              = 600
$CheckBoxSetVisualFXAppearance.height             = 20
$CheckBoxSetVisualFXAppearance.AutoSize           = $false
$CheckBoxSetVisualFXAppearance.Font               = 'Microsoft Sans Serif,10'
$CheckBoxSetVisualFXAppearance.checked            = $false
$CheckBoxSetVisualFXAppearance.Visible            = $false
$CheckBoxSetVisualFXAppearance.Enabled            = $true

#--Enable--Disable--Thumbnails, show only file extension icons
# EnableThumbnails DisableThumbnails

$CheckBoxEnableThumbnails                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableThumbnails.text              = "Enable "
$CheckBoxEnableThumbnails.location          = New-Object System.Drawing.Point(10,710)
$CheckBoxEnableThumbnails.width             = 100
$CheckBoxEnableThumbnails.height            = 20
$CheckBoxEnableThumbnails.AutoSize          = $false
$CheckBoxEnableThumbnails.Font              = 'Microsoft Sans Serif,10'
$CheckBoxEnableThumbnails.checked           = $true
$CheckBoxEnableThumbnails.Visible           = $false
$CheckBoxEnableThumbnails.Enabled           = $true

$CheckBoxDisableThumbnails                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableThumbnails.text               = "Disable Thumbnails, show only file extension icons "
$CheckBoxDisableThumbnails.location           = New-Object System.Drawing.Point(110,710)
$CheckBoxDisableThumbnails.width              = 600
$CheckBoxDisableThumbnails.height             = 20
$CheckBoxDisableThumbnails.AutoSize           = $false
$CheckBoxDisableThumbnails.Font               = 'Microsoft Sans Serif,10'
$CheckBoxDisableThumbnails.checked            = $false
$CheckBoxDisableThumbnails.Visible            = $false
$CheckBoxDisableThumbnails.Enabled            = $true

#--Disable--Enable--Creation of Thumbs.db thumbnail cache files
# DisableThumbsDB EnableThumbsDB

$CheckBoxDisableThumbsDB                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableThumbsDB.text              = "Disable "
$CheckBoxDisableThumbsDB.location          = New-Object System.Drawing.Point(10,730)
$CheckBoxDisableThumbsDB.width             = 100
$CheckBoxDisableThumbsDB.height            = 20
$CheckBoxDisableThumbsDB.AutoSize          = $false
$CheckBoxDisableThumbsDB.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableThumbsDB.checked           = $false
$CheckBoxDisableThumbsDB.Visible           = $false
$CheckBoxDisableThumbsDB.Enabled           = $true

$CheckBoxEnableThumbsDB                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableThumbsDB.text               = "Enable Creation of Thumbs.db thumbnail cache files"
$CheckBoxEnableThumbsDB.location           = New-Object System.Drawing.Point(110,730)
$CheckBoxEnableThumbsDB.width              = 600
$CheckBoxEnableThumbsDB.height             = 20
$CheckBoxEnableThumbsDB.AutoSize           = $false
$CheckBoxEnableThumbsDB.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableThumbsDB.checked            = $true
$CheckBoxEnableThumbsDB.Visible            = $false
$CheckBoxEnableThumbsDB.Enabled            = $true

#--Add--Remove--Secondary Keyboard (Russian)
# AddENKeyboard RemoveENKeyboard

$CheckBoxAddENKeyboard                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxAddENKeyboard.text              = "Add "
$CheckBoxAddENKeyboard.location          = New-Object System.Drawing.Point(10,750)
$CheckBoxAddENKeyboard.width             = 100
$CheckBoxAddENKeyboard.height            = 20
$CheckBoxAddENKeyboard.AutoSize          = $false
$CheckBoxAddENKeyboard.Font              = 'Microsoft Sans Serif,10'
$CheckBoxAddENKeyboard.checked           = $true
$CheckBoxAddENKeyboard.Visible           = $false
$CheckBoxAddENKeyboard.Enabled           = $true

$CheckBoxRemoveENKeyboard                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxRemoveENKeyboard.text               = "Remove Seconday Keyboard (Russian) "
$CheckBoxRemoveENKeyboard.location           = New-Object System.Drawing.Point(110,750)
$CheckBoxRemoveENKeyboard.width              = 600
$CheckBoxRemoveENKeyboard.height             = 20
$CheckBoxRemoveENKeyboard.AutoSize           = $false
$CheckBoxRemoveENKeyboard.Font               = 'Microsoft Sans Serif,10'
$CheckBoxRemoveENKeyboard.checked            = $false
$CheckBoxRemoveENKeyboard.Visible            = $false
$CheckBoxRemoveENKeyboard.Enabled            = $true


#--Disable--Enable--NumLock after startup
# DisableNumlock EnableNumlock

$CheckBoxDisableNumlock                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableNumlock.text              = "Disable "
$CheckBoxDisableNumlock.location          = New-Object System.Drawing.Point(10,770)
$CheckBoxDisableNumlock.width             = 100
$CheckBoxDisableNumlock.height            = 20
$CheckBoxDisableNumlock.AutoSize          = $false
$CheckBoxDisableNumlock.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableNumlock.checked           = $false
$CheckBoxDisableNumlock.Visible           = $false
$CheckBoxDisableNumlock.Enabled           = $true

$CheckBoxEnableNumlock                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableNumlock.text               = "Enable NumLock after startup"
$CheckBoxEnableNumlock.location           = New-Object System.Drawing.Point(110,770)
$CheckBoxEnableNumlock.width              = 600
$CheckBoxEnableNumlock.height             = 20
$CheckBoxEnableNumlock.AutoSize           = $false
$CheckBoxEnableNumlock.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableNumlock.checked            = $true
$CheckBoxEnableNumlock.Visible            = $false
$CheckBoxEnableNumlock.Enabled            = $true


#--Application Tweaks--##############################################################################################################################################################################

#--Disable--Enable--OneDrive
# DisableOneDrive EnableOneDrive

$CheckBoxDisableOneDrive                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableOneDrive.text              = "Disable "
$CheckBoxDisableOneDrive.location          = New-Object System.Drawing.Point(10,130)
$CheckBoxDisableOneDrive.width             = 100
$CheckBoxDisableOneDrive.height            = 20
$CheckBoxDisableOneDrive.AutoSize          = $false
$CheckBoxDisableOneDrive.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableOneDrive.checked           = $true
$CheckBoxDisableOneDrive.Visible           = $false
$CheckBoxDisableOneDrive.Enabled           = $true

$CheckBoxEnableOneDrive                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableOneDrive.text               = "Enable OneDrive"
$CheckBoxEnableOneDrive.location           = New-Object System.Drawing.Point(110,130)
$CheckBoxEnableOneDrive.width              = 600
$CheckBoxEnableOneDrive.height             = 20
$CheckBoxEnableOneDrive.AutoSize           = $false
$CheckBoxEnableOneDrive.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableOneDrive.checked            = $false
$CheckBoxEnableOneDrive.Visible            = $false
$CheckBoxEnableOneDrive.Enabled            = $true

#--Uninstall--Install--OneDrive
# UninstallOneDrive InstallOneDrive

$CheckBoxUninstallOneDrive                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallOneDrive.text              = "Uninstall "
$CheckBoxUninstallOneDrive.location          = New-Object System.Drawing.Point(10,150)
$CheckBoxUninstallOneDrive.width             = 100
$CheckBoxUninstallOneDrive.height            = 20
$CheckBoxUninstallOneDrive.AutoSize          = $false
$CheckBoxUninstallOneDrive.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallOneDrive.checked           = $true
$CheckBoxUninstallOneDrive.Visible           = $false
$CheckBoxUninstallOneDrive.Enabled           = $true

$CheckBoxInstallOneDrive                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallOneDrive.text               = "Install OneDrive"
$CheckBoxInstallOneDrive.location           = New-Object System.Drawing.Point(110,150)
$CheckBoxInstallOneDrive.width              = 600
$CheckBoxInstallOneDrive.height             = 20
$CheckBoxInstallOneDrive.AutoSize           = $false
$CheckBoxInstallOneDrive.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallOneDrive.checked            = $false
$CheckBoxInstallOneDrive.Visible            = $false
$CheckBoxInstallOneDrive.Enabled            = $true

#--Uninstall--Install default Microsoft applications BLOAT
# UninstallMsftBloat InstallMsftBloat

$CheckBoxUninstallMsftBloat                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallMsftBloat.text              = "Uninstall "
$CheckBoxUninstallMsftBloat.location          = New-Object System.Drawing.Point(10,170)
$CheckBoxUninstallMsftBloat.width             = 100
$CheckBoxUninstallMsftBloat.height            = 20
$CheckBoxUninstallMsftBloat.AutoSize          = $false
$CheckBoxUninstallMsftBloat.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallMsftBloat.checked           = $true
$CheckBoxUninstallMsftBloat.Visible           = $false
$CheckBoxUninstallMsftBloat.Enabled           = $true

$CheckBoxInstallMsftBloat                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallMsftBloat.text               = "Install Microsoft Applications BLOATWARE "
$CheckBoxInstallMsftBloat.location           = New-Object System.Drawing.Point(110,170)
$CheckBoxInstallMsftBloat.width              = 600
$CheckBoxInstallMsftBloat.height             = 20
$CheckBoxInstallMsftBloat.AutoSize           = $false
$CheckBoxInstallMsftBloat.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallMsftBloat.checked            = $false
$CheckBoxInstallMsftBloat.Visible            = $false
$CheckBoxInstallMsftBloat.Enabled            = $true

#--Uninstall--Install--Default third party applications
# UninstallThirdPartyBloat InstallThirdPartyBloat

$CheckBoxUninstallThirdPartyBloat                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallThirdPartyBloat.text              = "Uninstall "
$CheckBoxUninstallThirdPartyBloat.location          = New-Object System.Drawing.Point(10,190)
$CheckBoxUninstallThirdPartyBloat.width             = 100
$CheckBoxUninstallThirdPartyBloat.height            = 20
$CheckBoxUninstallThirdPartyBloat.AutoSize          = $false
$CheckBoxUninstallThirdPartyBloat.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallThirdPartyBloat.checked           = $true
$CheckBoxUninstallThirdPartyBloat.Visible           = $false
$CheckBoxUninstallThirdPartyBloat.Enabled           = $true

$CheckBoxInstallThirdPartyBloat                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallThirdPartyBloat.text               = "Install third party applications"
$CheckBoxInstallThirdPartyBloat.location           = New-Object System.Drawing.Point(110,190)
$CheckBoxInstallThirdPartyBloat.width              = 600
$CheckBoxInstallThirdPartyBloat.height             = 20
$CheckBoxInstallThirdPartyBloat.AutoSize           = $false
$CheckBoxInstallThirdPartyBloat.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallThirdPartyBloat.checked            = $false
$CheckBoxInstallThirdPartyBloat.Visible            = $false
$CheckBoxInstallThirdPartyBloat.Enabled            = $true

#--Uninstall--Install--Windows Store
# UninstallWindowsStore InstallWindowsStore

$CheckBoxUninstallWindowsStore                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallWindowsStore.text              = "Uninstall "
$CheckBoxUninstallWindowsStore.location          = New-Object System.Drawing.Point(10,210)
$CheckBoxUninstallWindowsStore.width             = 100
$CheckBoxUninstallWindowsStore.height            = 20
$CheckBoxUninstallWindowsStore.AutoSize          = $false
$CheckBoxUninstallWindowsStore.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallWindowsStore.checked           = $true
$CheckBoxUninstallWindowsStore.Visible           = $false
$CheckBoxUninstallWindowsStore.Enabled           = $true

$CheckBoxInstallWindowsStore                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallWindowsStore.text               = "Install Windows Store "
$CheckBoxInstallWindowsStore.location           = New-Object System.Drawing.Point(110,210)
$CheckBoxInstallWindowsStore.width              = 600
$CheckBoxInstallWindowsStore.height             = 20
$CheckBoxInstallWindowsStore.AutoSize           = $false
$CheckBoxInstallWindowsStore.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallWindowsStore.checked            = $false
$CheckBoxInstallWindowsStore.Visible            = $false
$CheckBoxInstallWindowsStore.Enabled            = $true

#--Disable--Enable--Xbox Features
# DisableXboxFeatures EnableXboxFeatures

$CheckBoxDisableXboxFeatures                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableXboxFeatures.text              = "Disable "
$CheckBoxDisableXboxFeatures.location          = New-Object System.Drawing.Point(10,230)
$CheckBoxDisableXboxFeatures.width             = 100
$CheckBoxDisableXboxFeatures.height            = 20
$CheckBoxDisableXboxFeatures.AutoSize          = $false
$CheckBoxDisableXboxFeatures.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableXboxFeatures.checked           = $true
$CheckBoxDisableXboxFeatures.Visible           = $false
$CheckBoxDisableXboxFeatures.Enabled           = $true

$CheckBoxEnableXboxFeatures                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableXboxFeatures.text               = "Enable Xbox Features"
$CheckBoxEnableXboxFeatures.location           = New-Object System.Drawing.Point(110,230)
$CheckBoxEnableXboxFeatures.width              = 600
$CheckBoxEnableXboxFeatures.height             = 20
$CheckBoxEnableXboxFeatures.AutoSize           = $false
$CheckBoxEnableXboxFeatures.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableXboxFeatures.checked            = $false
$CheckBoxEnableXboxFeatures.Visible            = $false
$CheckBoxEnableXboxFeatures.Enabled            = $true

#--Disable--Enable--built-in Adobe Flash in IE and Edge
# DisableAdobeFlash EnableAdobeFlash

$CheckBoxDisableAdobeFlash                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAdobeFlash.text              = "Disable "
$CheckBoxDisableAdobeFlash.location          = New-Object System.Drawing.Point(10,250)
$CheckBoxDisableAdobeFlash.width             = 100
$CheckBoxDisableAdobeFlash.height            = 20
$CheckBoxDisableAdobeFlash.AutoSize          = $false
$CheckBoxDisableAdobeFlash.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableAdobeFlash.checked           = $true
$CheckBoxDisableAdobeFlash.Visible           = $false
$CheckBoxDisableAdobeFlash.Enabled           = $true

$CheckBoxEnableAdobeFlash                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAdobeFlash.text               = "Enable built-in Adobe Flash in IE and Edge"
$CheckBoxEnableAdobeFlash.location           = New-Object System.Drawing.Point(110,250)
$CheckBoxEnableAdobeFlash.width              = 600
$CheckBoxEnableAdobeFlash.height             = 20
$CheckBoxEnableAdobeFlash.AutoSize           = $false
$CheckBoxEnableAdobeFlash.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableAdobeFlash.checked            = $false
$CheckBoxEnableAdobeFlash.Visible            = $false
$CheckBoxEnableAdobeFlash.Enabled            = $true

#--Uninstall--Install--MediaPlayer
# UninstallMediaPlayer InstallMediaPlayer

$CheckBoxUninstallMediaPlayer                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallMediaPlayer.text              = "Uninstall "
$CheckBoxUninstallMediaPlayer.location          = New-Object System.Drawing.Point(10,270)
$CheckBoxUninstallMediaPlayer.width             = 100
$CheckBoxUninstallMediaPlayer.height            = 20
$CheckBoxUninstallMediaPlayer.AutoSize          = $false
$CheckBoxUninstallMediaPlayer.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallMediaPlayer.checked           = $true
$CheckBoxUninstallMediaPlayer.Visible           = $false
$CheckBoxUninstallMediaPlayer.Enabled           = $true

$CheckBoxInstallMediaPlayer                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallMediaPlayer.text               = "Install Media Player "
$CheckBoxInstallMediaPlayer.location           = New-Object System.Drawing.Point(110,270)
$CheckBoxInstallMediaPlayer.width              = 600
$CheckBoxInstallMediaPlayer.height             = 20
$CheckBoxInstallMediaPlayer.AutoSize           = $false
$CheckBoxInstallMediaPlayer.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallMediaPlayer.checked            = $false
$CheckBoxInstallMediaPlayer.Visible            = $false
$CheckBoxInstallMediaPlayer.Enabled            = $true

#--Uninstall--Install--Work Folders Client --  Not applicable to Server
# UninstallWorkFolders InstallWorkFolders

$CheckBoxUninstallWorkFolders                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallWorkFolders.text              = "Uninstall "
$CheckBoxUninstallWorkFolders.location          = New-Object System.Drawing.Point(10,290)
$CheckBoxUninstallWorkFolders.width             = 100
$CheckBoxUninstallWorkFolders.height            = 20
$CheckBoxUninstallWorkFolders.AutoSize          = $false
$CheckBoxUninstallWorkFolders.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallWorkFolders.checked           = $true
$CheckBoxUninstallWorkFolders.Visible           = $false
$CheckBoxUninstallWorkFolders.Enabled           = $true

$CheckBoxInstallWorkFolders                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallWorkFolders.text               = "Install Work Folders Client"
$CheckBoxInstallWorkFolders.location           = New-Object System.Drawing.Point(110,290)
$CheckBoxInstallWorkFolders.width              = 600
$CheckBoxInstallWorkFolders.height             = 20
$CheckBoxInstallWorkFolders.AutoSize           = $false
$CheckBoxInstallWorkFolders.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallWorkFolders.checked            = $false
$CheckBoxInstallWorkFolders.Visible            = $false
$CheckBoxInstallWorkFolders.Enabled            = $true

#--Uninstall--Install--Linux Subsystem -- Applicable to 1607 or newer, not applicable to Server yet
# UninstallLinuxSubsystem InstallLinuxSubsystem

$CheckBoxUninstallLinuxSubsystem                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallLinuxSubsystem.text              = "Uninstall "
$CheckBoxUninstallLinuxSubsystem.location          = New-Object System.Drawing.Point(10,310)
$CheckBoxUninstallLinuxSubsystem.width             = 100
$CheckBoxUninstallLinuxSubsystem.height            = 20
$CheckBoxUninstallLinuxSubsystem.AutoSize          = $false
$CheckBoxUninstallLinuxSubsystem.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallLinuxSubsystem.checked           = $false
$CheckBoxUninstallLinuxSubsystem.Visible           = $false
$CheckBoxUninstallLinuxSubsystem.Enabled           = $true

$CheckBoxInstallLinuxSubsystem                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallLinuxSubsystem.text               = "Install Linux Subsystem "
$CheckBoxInstallLinuxSubsystem.location           = New-Object System.Drawing.Point(110,310)
$CheckBoxInstallLinuxSubsystem.width              = 600
$CheckBoxInstallLinuxSubsystem.height             = 20
$CheckBoxInstallLinuxSubsystem.AutoSize           = $false
$CheckBoxInstallLinuxSubsystem.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallLinuxSubsystem.checked            = $false
$CheckBoxInstallLinuxSubsystem.Visible            = $false
$CheckBoxInstallLinuxSubsystem.Enabled            = $true

#--Uninstall--Install--HyperV -- Not applicable to Home
# UninstallHyperV InstallHyperV

$CheckBoxUninstallHyperV                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxUninstallHyperV.text              = "Uninstall "
$CheckBoxUninstallHyperV.location          = New-Object System.Drawing.Point(10,330)
$CheckBoxUninstallHyperV.width             = 100
$CheckBoxUninstallHyperV.height            = 20
$CheckBoxUninstallHyperV.AutoSize          = $false
$CheckBoxUninstallHyperV.Font              = 'Microsoft Sans Serif,10'
$CheckBoxUninstallHyperV.checked           = $false
$CheckBoxUninstallHyperV.Visible           = $false
$CheckBoxUninstallHyperV.Enabled           = $true

$CheckBoxInstallHyperV                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxInstallHyperV.text               = "Install HyperV "
$CheckBoxInstallHyperV.location           = New-Object System.Drawing.Point(110,330)
$CheckBoxInstallHyperV.width              = 600
$CheckBoxInstallHyperV.height             = 20
$CheckBoxInstallHyperV.AutoSize           = $false
$CheckBoxInstallHyperV.Font               = 'Microsoft Sans Serif,10'
$CheckBoxInstallHyperV.checked            = $false
$CheckBoxInstallHyperV.Visible            = $false
$CheckBoxInstallHyperV.Enabled            = $true

#--Set--Unset--Photo Viewer association for bmp, gif, jpg, png and tif
# SetPhotoViewerAssociation UnsetPhotoViewerAssociation

$CheckBoxSetPhotoViewerAssociation                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetPhotoViewerAssociation.text              = "Set "
$CheckBoxSetPhotoViewerAssociation.location          = New-Object System.Drawing.Point(10,350)
$CheckBoxSetPhotoViewerAssociation.width             = 100
$CheckBoxSetPhotoViewerAssociation.height            = 20
$CheckBoxSetPhotoViewerAssociation.AutoSize          = $false
$CheckBoxSetPhotoViewerAssociation.Font              = 'Microsoft Sans Serif,10'
$CheckBoxSetPhotoViewerAssociation.checked           = $true
$CheckBoxSetPhotoViewerAssociation.Visible           = $false
$CheckBoxSetPhotoViewerAssociation.Enabled           = $true

$CheckBoxUnsetPhotoViewerAssociation                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxUnsetPhotoViewerAssociation.text               = "Unset Photo Viewer association for bmp, gif, jpg, png and tif "
$CheckBoxUnsetPhotoViewerAssociation.location           = New-Object System.Drawing.Point(110,350)
$CheckBoxUnsetPhotoViewerAssociation.width              = 600
$CheckBoxUnsetPhotoViewerAssociation.height             = 20
$CheckBoxUnsetPhotoViewerAssociation.AutoSize           = $false
$CheckBoxUnsetPhotoViewerAssociation.Font               = 'Microsoft Sans Serif,10'
$CheckBoxUnsetPhotoViewerAssociation.checked            = $false
$CheckBoxUnsetPhotoViewerAssociation.Visible            = $false
$CheckBoxUnsetPhotoViewerAssociation.Enabled            = $true

#--Add--Remove--Photo Viewer to "Open with...`r`n"
# AddPhotoViewerOpenWith RemovePhotoViewerOpenWith

$CheckBoxAddPhotoViewerOpenWith                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxAddPhotoViewerOpenWith.text              = "Add "
$CheckBoxAddPhotoViewerOpenWith.location          = New-Object System.Drawing.Point(10,370)
$CheckBoxAddPhotoViewerOpenWith.width             = 100
$CheckBoxAddPhotoViewerOpenWith.height            = 20
$CheckBoxAddPhotoViewerOpenWith.AutoSize          = $false
$CheckBoxAddPhotoViewerOpenWith.Font              = 'Microsoft Sans Serif,10'
$CheckBoxAddPhotoViewerOpenWith.checked           = $true
$CheckBoxAddPhotoViewerOpenWith.Visible           = $false
$CheckBoxAddPhotoViewerOpenWith.Enabled           = $true

$CheckBoxRemovePhotoViewerOpenWith                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxRemovePhotoViewerOpenWith.text               = "Remove Photo Viewer from OPEN WITH...`r`n"
$CheckBoxRemovePhotoViewerOpenWith.location           = New-Object System.Drawing.Point(110,370)
$CheckBoxRemovePhotoViewerOpenWith.width              = 600
$CheckBoxRemovePhotoViewerOpenWith.height             = 20
$CheckBoxRemovePhotoViewerOpenWith.AutoSize           = $false
$CheckBoxRemovePhotoViewerOpenWith.Font               = 'Microsoft Sans Serif,10'
$CheckBoxRemovePhotoViewerOpenWith.checked            = $false
$CheckBoxRemovePhotoViewerOpenWith.Visible            = $false
$CheckBoxRemovePhotoViewerOpenWith.Enabled            = $true

#--Disable--Enable--Search for app in store for unknown extensions
# DisableSearchAppInStore EnableSearchAppInStore

$CheckBoxDisableSearchAppInStore                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableSearchAppInStore.text              = "Disable "
$CheckBoxDisableSearchAppInStore.location          = New-Object System.Drawing.Point(10,390)
$CheckBoxDisableSearchAppInStore.width             = 100
$CheckBoxDisableSearchAppInStore.height            = 20
$CheckBoxDisableSearchAppInStore.AutoSize          = $false
$CheckBoxDisableSearchAppInStore.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableSearchAppInStore.checked           = $true
$CheckBoxDisableSearchAppInStore.Visible           = $false
$CheckBoxDisableSearchAppInStore.Enabled           = $true

$CheckBoxEnableSearchAppInStore                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableSearchAppInStore.text               = "Enable SearchAppInStore"
$CheckBoxEnableSearchAppInStore.location           = New-Object System.Drawing.Point(110,390)
$CheckBoxEnableSearchAppInStore.width              = 600
$CheckBoxEnableSearchAppInStore.height             = 20
$CheckBoxEnableSearchAppInStore.AutoSize           = $false
$CheckBoxEnableSearchAppInStore.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableSearchAppInStore.checked            = $false
$CheckBoxEnableSearchAppInStore.Visible            = $false
$CheckBoxEnableSearchAppInStore.Enabled            = $true

#--Disable--Enable--'How do you want to open this file?' prompt
# DisableNewAppPrompt EnableNewAppPrompt

$CheckBoxDisableNewAppPrompt                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableNewAppPrompt.text              = "Disable "
$CheckBoxDisableNewAppPrompt.location          = New-Object System.Drawing.Point(10,410)
$CheckBoxDisableNewAppPrompt.width             = 100
$CheckBoxDisableNewAppPrompt.height            = 20
$CheckBoxDisableNewAppPrompt.AutoSize          = $false
$CheckBoxDisableNewAppPrompt.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableNewAppPrompt.checked           = $true
$CheckBoxDisableNewAppPrompt.Visible           = $false
$CheckBoxDisableNewAppPrompt.Enabled           = $true

$CheckBoxEnableNewAppPrompt                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableNewAppPrompt.text               = "Enable How do you want to open this file?"
$CheckBoxEnableNewAppPrompt.location           = New-Object System.Drawing.Point(110,410)
$CheckBoxEnableNewAppPrompt.width              = 600
$CheckBoxEnableNewAppPrompt.height             = 20
$CheckBoxEnableNewAppPrompt.AutoSize           = $false
$CheckBoxEnableNewAppPrompt.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableNewAppPrompt.checked            = $false
$CheckBoxEnableNewAppPrompt.Visible            = $false
$CheckBoxEnableNewAppPrompt.Enabled            = $true

#--Disable--Enable--F8 boot menu options
# DisableF8BootMenu EnableF8BootMenu

$CheckBoxDisableF8BootMenu                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableF8BootMenu.text              = "Disable "
$CheckBoxDisableF8BootMenu.location          = New-Object System.Drawing.Point(10,430)
$CheckBoxDisableF8BootMenu.width             = 100
$CheckBoxDisableF8BootMenu.height            = 20
$CheckBoxDisableF8BootMenu.AutoSize          = $false
$CheckBoxDisableF8BootMenu.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableF8BootMenu.checked           = $false
$CheckBoxDisableF8BootMenu.Visible           = $false
$CheckBoxDisableF8BootMenu.Enabled           = $true

$CheckBoxEnableF8BootMenu                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableF8BootMenu.text               = "Enable F8 boot menu options"
$CheckBoxEnableF8BootMenu.location           = New-Object System.Drawing.Point(110,430)
$CheckBoxEnableF8BootMenu.width              = 600
$CheckBoxEnableF8BootMenu.height             = 20
$CheckBoxEnableF8BootMenu.AutoSize           = $false
$CheckBoxEnableF8BootMenu.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableF8BootMenu.checked            = $true
$CheckBoxEnableF8BootMenu.Visible            = $false
$CheckBoxEnableF8BootMenu.Enabled            = $true

#--Opt In--Opt Out--Set Data Execution Prevention (DEP) policy 
# SetDEPOptIn SetDEPOptOut

$CheckBoxSetDEPOptIn                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetDEPOptIn.text              = "Opt In "
$CheckBoxSetDEPOptIn.location          = New-Object System.Drawing.Point(10,450)
$CheckBoxSetDEPOptIn.width             = 100
$CheckBoxSetDEPOptIn.height            = 20
$CheckBoxSetDEPOptIn.AutoSize          = $false
$CheckBoxSetDEPOptIn.Font              = 'Microsoft Sans Serif,10'
$CheckBoxSetDEPOptIn.checked           = $true
$CheckBoxSetDEPOptIn.Visible           = $false
$CheckBoxSetDEPOptIn.Enabled           = $true

$CheckBoxSetDEPOptOut                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetDEPOptOut.text               = "Opt Out of Data Execution Prevention DEP Policy "
$CheckBoxSetDEPOptOut.location           = New-Object System.Drawing.Point(110,450)
$CheckBoxSetDEPOptOut.width              = 600
$CheckBoxSetDEPOptOut.height             = 20
$CheckBoxSetDEPOptOut.AutoSize           = $false
$CheckBoxSetDEPOptOut.Font               = 'Microsoft Sans Serif,10'
$CheckBoxSetDEPOptOut.checked            = $false
$CheckBoxSetDEPOptOut.Visible            = $false
$CheckBoxSetDEPOptOut.Enabled            = $true

#--Server specific Tweaks--#######################################################################################################################################################################################

#--Hide--Show--Server Manager On Login
# HideServerManagerOnLogin ShowServerManagerOnLogin

$CheckBoxHideServerManagerOnLogin                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxHideServerManagerOnLogin.text              = "Hide "
$CheckBoxHideServerManagerOnLogin.location          = New-Object System.Drawing.Point(10,130)
$CheckBoxHideServerManagerOnLogin.width             = 100
$CheckBoxHideServerManagerOnLogin.height            = 20
$CheckBoxHideServerManagerOnLogin.AutoSize          = $false
$CheckBoxHideServerManagerOnLogin.Font              = 'Microsoft Sans Serif,10'
$CheckBoxHideServerManagerOnLogin.checked           = $false
$CheckBoxHideServerManagerOnLogin.Visible           = $false
$CheckBoxHideServerManagerOnLogin.Enabled           = $true

$CheckBoxShowServerManagerOnLogin                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxShowServerManagerOnLogin.text               = "Show Server Manager On Login "
$CheckBoxShowServerManagerOnLogin.location           = New-Object System.Drawing.Point(110,130)
$CheckBoxShowServerManagerOnLogin.width              = 600
$CheckBoxShowServerManagerOnLogin.height             = 20
$CheckBoxShowServerManagerOnLogin.AutoSize           = $false
$CheckBoxShowServerManagerOnLogin.Font               = 'Microsoft Sans Serif,10'
$CheckBoxShowServerManagerOnLogin.checked            = $false
$CheckBoxShowServerManagerOnLogin.Visible            = $false
$CheckBoxShowServerManagerOnLogin.Enabled            = $true

#--Disable--Enable--Shutdown Tracker
# DisableShutdownTracker EnableShutdownTracker

$CheckBoxDisableShutdownTracker                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableShutdownTracker.text              = "Disable "
$CheckBoxDisableShutdownTracker.location          = New-Object System.Drawing.Point(10,150)
$CheckBoxDisableShutdownTracker.width             = 100
$CheckBoxDisableShutdownTracker.height            = 20
$CheckBoxDisableShutdownTracker.AutoSize          = $false
$CheckBoxDisableShutdownTracker.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableShutdownTracker.checked           = $false
$CheckBoxDisableShutdownTracker.Visible           = $false
$CheckBoxDisableShutdownTracker.Enabled           = $true

$CheckBoxEnableShutdownTracker                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableShutdownTracker.text               = "Enable Shutdown Tracker"
$CheckBoxEnableShutdownTracker.location           = New-Object System.Drawing.Point(110,150)
$CheckBoxEnableShutdownTracker.width              = 600
$CheckBoxEnableShutdownTracker.height             = 20
$CheckBoxEnableShutdownTracker.AutoSize           = $false
$CheckBoxEnableShutdownTracker.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableShutdownTracker.checked            = $false
$CheckBoxEnableShutdownTracker.Visible            = $false
$CheckBoxEnableShutdownTracker.Enabled            = $true

#--Disable--Enable--password complexity and maximum age requirements
# DisablePasswordPolicy EnablePasswordPolicy

$CheckBoxDisablePasswordPolicy                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisablePasswordPolicy.text              = "Disable "
$CheckBoxDisablePasswordPolicy.location          = New-Object System.Drawing.Point(10,170)
$CheckBoxDisablePasswordPolicy.width             = 100
$CheckBoxDisablePasswordPolicy.height            = 20
$CheckBoxDisablePasswordPolicy.AutoSize          = $false
$CheckBoxDisablePasswordPolicy.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisablePasswordPolicy.checked           = $false
$CheckBoxDisablePasswordPolicy.Visible           = $false
$CheckBoxDisablePasswordPolicy.Enabled           = $true

$CheckBoxEnablePasswordPolicy                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnablePasswordPolicy.text               = "Enable password complexity and maximum age requirements"
$CheckBoxEnablePasswordPolicy.location           = New-Object System.Drawing.Point(110,170)
$CheckBoxEnablePasswordPolicy.width              = 600
$CheckBoxEnablePasswordPolicy.height             = 20
$CheckBoxEnablePasswordPolicy.AutoSize           = $false
$CheckBoxEnablePasswordPolicy.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnablePasswordPolicy.checked            = $false
$CheckBoxEnablePasswordPolicy.Visible            = $false
$CheckBoxEnablePasswordPolicy.Enabled            = $true

#--Disable--Enable--Ctrl+Alt+Del requirement before login
# DisableCtrlAltDelLogin EnableCtrlAltDelLogin

$CheckBoxDisableCtrlAltDelLogin                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableCtrlAltDelLogin.text              = "Disable "
$CheckBoxDisableCtrlAltDelLogin.location          = New-Object System.Drawing.Point(10,190)
$CheckBoxDisableCtrlAltDelLogin.width             = 100
$CheckBoxDisableCtrlAltDelLogin.height            = 20
$CheckBoxDisableCtrlAltDelLogin.AutoSize          = $false
$CheckBoxDisableCtrlAltDelLogin.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableCtrlAltDelLogin.checked           = $false
$CheckBoxDisableCtrlAltDelLogin.Visible           = $false
$CheckBoxDisableCtrlAltDelLogin.Enabled           = $true

$CheckBoxEnableCtrlAltDelLogin                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableCtrlAltDelLogin.text               = "Enable Ctrl+Alt+Del requirement before login"
$CheckBoxEnableCtrlAltDelLogin.location           = New-Object System.Drawing.Point(110,190)
$CheckBoxEnableCtrlAltDelLogin.width              = 600
$CheckBoxEnableCtrlAltDelLogin.height             = 20
$CheckBoxEnableCtrlAltDelLogin.AutoSize           = $false
$CheckBoxEnableCtrlAltDelLogin.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableCtrlAltDelLogin.checked            = $false
$CheckBoxEnableCtrlAltDelLogin.Visible            = $false
$CheckBoxEnableCtrlAltDelLogin.Enabled            = $true

#--Disable--Enable--Internet Explorer Enhanced Security Configuration (IE ESC)
# DisableIEEnhancedSecurity EnableIEEnhancedSecurity

$CheckBoxDisableIEEnhancedSecurity                   = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableIEEnhancedSecurity.text              = "Disable "
$CheckBoxDisableIEEnhancedSecurity.location          = New-Object System.Drawing.Point(10,210)
$CheckBoxDisableIEEnhancedSecurity.width             = 100
$CheckBoxDisableIEEnhancedSecurity.height            = 20
$CheckBoxDisableIEEnhancedSecurity.AutoSize          = $false
$CheckBoxDisableIEEnhancedSecurity.Font              = 'Microsoft Sans Serif,10'
$CheckBoxDisableIEEnhancedSecurity.checked           = $false
$CheckBoxDisableIEEnhancedSecurity.Visible           = $false
$CheckBoxDisableIEEnhancedSecurity.Enabled           = $true

$CheckBoxEnableIEEnhancedSecurity                    = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableIEEnhancedSecurity.text               = "Enable Internet Explorer Enhanced Security Configuration (IE ESC)"
$CheckBoxEnableIEEnhancedSecurity.location           = New-Object System.Drawing.Point(110,210)
$CheckBoxEnableIEEnhancedSecurity.width              = 600
$CheckBoxEnableIEEnhancedSecurity.height             = 20
$CheckBoxEnableIEEnhancedSecurity.AutoSize           = $false
$CheckBoxEnableIEEnhancedSecurity.Font               = 'Microsoft Sans Serif,10'
$CheckBoxEnableIEEnhancedSecurity.checked            = $false
$CheckBoxEnableIEEnhancedSecurity.Visible            = $false
$CheckBoxEnableIEEnhancedSecurity.Enabled            = $true

#--Other--#######################################################################################################################################################################################

#--Disable--Enable--Auto Maintenance
# DisableAutoMaintenance EnableAutoMaintenance

$CheckBoxDisableAutoMaintenance                = New-Object system.Windows.Forms.CheckBox
$CheckBoxDisableAutoMaintenance.text           = "Disable "
$CheckBoxDisableAutoMaintenance.location       = New-Object System.Drawing.Point(10,130)
$CheckBoxDisableAutoMaintenance.width          = 100
$CheckBoxDisableAutoMaintenance.height         = 20
$CheckBoxDisableAutoMaintenance.AutoSize       = $false
$CheckBoxDisableAutoMaintenance.Font           = 'Microsoft Sans Serif,10'
$CheckBoxDisableAutoMaintenance.checked        = $false
$CheckBoxDisableAutoMaintenance.Visible        = $false
$CheckBoxDisableAutoMaintenance.Enabled        = $true

$CheckBoxEnableAutoMaintenance                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxEnableAutoMaintenance.text            = "Enable Auto Maintenance"
$CheckBoxEnableAutoMaintenance.location        = New-Object System.Drawing.Point(110,130)
$CheckBoxEnableAutoMaintenance.width           = 600
$CheckBoxEnableAutoMaintenance.height          = 20
$CheckBoxEnableAutoMaintenance.AutoSize        = $false
$CheckBoxEnableAutoMaintenance.Font            = 'Microsoft Sans Serif,10'
$CheckBoxEnableAutoMaintenance.checked         = $true
$CheckBoxEnableAutoMaintenance.Visible         = $false
$CheckBoxEnableAutoMaintenance.Enabled         = $true

$CheckBoxDeleteTempFiles                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxDeleteTempFiles.text            = "Delete Temp Files, Cache and Cookies"
$CheckBoxDeleteTempFiles.location        = New-Object System.Drawing.Point(10,150)
$CheckBoxDeleteTempFiles.width           = 600
$CheckBoxDeleteTempFiles.height          = 20
$CheckBoxDeleteTempFiles.AutoSize        = $false
$CheckBoxDeleteTempFiles.Font            = 'Microsoft Sans Serif,10'
$CheckBoxDeleteTempFiles.checked         = $false
$CheckBoxDeleteTempFiles.Visible         = $false
$CheckBoxDeleteTempFiles.Enabled         = $true

$CheckBoxCleanWinSXS                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxCleanWinSXS.text            = "Clean WinSXS folder (WARNING: this takes a while!)"
$CheckBoxCleanWinSXS.location        = New-Object System.Drawing.Point(10,170)
$CheckBoxCleanWinSXS.width           = 600
$CheckBoxCleanWinSXS.height          = 20
$CheckBoxCleanWinSXS.AutoSize        = $false
$CheckBoxCleanWinSXS.Font            = 'Microsoft Sans Serif,10'
$CheckBoxCleanWinSXS.checked         = $false
$CheckBoxCleanWinSXS.Visible         = $false
$CheckBoxCleanWinSXS.Enabled         = $true

$CheckBoxDiskCleanup                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxDiskCleanup.text            = "Disk Cleanup (WARNING: this takes a while!)"
$CheckBoxDiskCleanup.location        = New-Object System.Drawing.Point(10,190)
$CheckBoxDiskCleanup.width           = 600
$CheckBoxDiskCleanup.height          = 20
$CheckBoxDiskCleanup.AutoSize        = $false
$CheckBoxDiskCleanup.Font            = 'Microsoft Sans Serif,10'
$CheckBoxDiskCleanup.checked         = $false
$CheckBoxDiskCleanup.Visible         = $false
$CheckBoxDiskCleanup.Enabled         = $true

$CheckBoxSetEasternTime                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetEasternTime.text            = "Set Time Zone to Eastern Time "
$CheckBoxSetEasternTime.location        = New-Object System.Drawing.Point(10,210)
$CheckBoxSetEasternTime.width           = 600
$CheckBoxSetEasternTime.height          = 20
$CheckBoxSetEasternTime.AutoSize        = $false
$CheckBoxSetEasternTime.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSetEasternTime.checked         = $false
$CheckBoxSetEasternTime.Visible         = $false
$CheckBoxSetEasternTime.Enabled         = $true

$CheckBoxSetCentralTime                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetCentralTime.text            = "Set Time Zone to Central Time "
$CheckBoxSetCentralTime.location        = New-Object System.Drawing.Point(10,230)
$CheckBoxSetCentralTime.width           = 600
$CheckBoxSetCentralTime.height          = 20
$CheckBoxSetCentralTime.AutoSize        = $false
$CheckBoxSetCentralTime.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSetCentralTime.checked         = $false
$CheckBoxSetCentralTime.Visible         = $false
$CheckBoxSetCentralTime.Enabled         = $true

$CheckBoxSetMountainTime                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetMountainTime.text            = "Set Time Zone to Mountian Time "
$CheckBoxSetMountainTime.location        = New-Object System.Drawing.Point(10,250)
$CheckBoxSetMountainTime.width           = 600
$CheckBoxSetMountainTime.height          = 20
$CheckBoxSetMountainTime.AutoSize        = $false
$CheckBoxSetMountainTime.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSetMountainTime.checked         = $false
$CheckBoxSetMountainTime.Visible         = $false
$CheckBoxSetMountainTime.Enabled         = $true

$CheckBoxSetPacificTime                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetPacificTime.text            = "Set Time Zone to Pacific Time "
$CheckBoxSetPacificTime.location        = New-Object System.Drawing.Point(10,270)
$CheckBoxSetPacificTime.width           = 600
$CheckBoxSetPacificTime.height          = 20
$CheckBoxSetPacificTime.AutoSize        = $false
$CheckBoxSetPacificTime.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSetPacificTime.checked         = $false
$CheckBoxSetPacificTime.Visible         = $false
$CheckBoxSetPacificTime.Enabled         = $true

$CheckBoxSyncTimeToInternet                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSyncTimeToInternet.text            = "Sync Time to the Internet "
$CheckBoxSyncTimeToInternet.location        = New-Object System.Drawing.Point(10,290)
$CheckBoxSyncTimeToInternet.width           = 600
$CheckBoxSyncTimeToInternet.height          = 20
$CheckBoxSyncTimeToInternet.AutoSize        = $false
$CheckBoxSyncTimeToInternet.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSyncTimeToInternet.checked         = $false
$CheckBoxSyncTimeToInternet.Visible         = $false
$CheckBoxSyncTimeToInternet.Enabled         = $true

$CheckBoxSFCScanNow                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSFCScanNow.text            = "SFC System File Checker (WARNING: this takes a while!)"
$CheckBoxSFCScanNow.location        = New-Object System.Drawing.Point(10,310)
$CheckBoxSFCScanNow.width           = 600
$CheckBoxSFCScanNow.height          = 20
$CheckBoxSFCScanNow.AutoSize        = $false
$CheckBoxSFCScanNow.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSFCScanNow.checked         = $false
$CheckBoxSFCScanNow.Visible         = $false
$CheckBoxSFCScanNow.Enabled         = $true

$CheckBoxWiFiNamePassword
$CheckBoxWiFiNamePassword                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxWiFiNamePassword.text            = "Display WiFi Name and Password"
$CheckBoxWiFiNamePassword.location        = New-Object System.Drawing.Point(10,330)
$CheckBoxWiFiNamePassword.width           = 600
$CheckBoxWiFiNamePassword.height          = 20
$CheckBoxWiFiNamePassword.AutoSize        = $false
$CheckBoxWiFiNamePassword.Font            = 'Microsoft Sans Serif,10'
$CheckBoxWiFiNamePassword.checked         = $false
$CheckBoxWiFiNamePassword.Visible         = $false
$CheckBoxWiFiNamePassword.Enabled         = $true

$CheckBoxStop11
$CheckBoxStop11                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxStop11.text            = "Stop from updating to Windows 11"
$CheckBoxStop11.location        = New-Object System.Drawing.Point(10,350)
$CheckBoxStop11.width           = 600
$CheckBoxStop11.height          = 20
$CheckBoxStop11.AutoSize        = $false
$CheckBoxStop11.Font            = 'Microsoft Sans Serif,10'
$CheckBoxStop11.checked         = $false
$CheckBoxStop11.Visible         = $false
$CheckBoxStop11.Enabled         = $true

$CheckBoxSetPagingAuto
$CheckBoxSetPagingAuto                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetPagingAuto.text            = "Paging File Auto Size "
$CheckBoxSetPagingAuto.location        = New-Object System.Drawing.Point(10,370)
$CheckBoxSetPagingAuto.width           = 200
$CheckBoxSetPagingAuto.height          = 20
$CheckBoxSetPagingAuto.AutoSize        = $false
$CheckBoxSetPagingAuto.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSetPagingAuto.checked         = $false
$CheckBoxSetPagingAuto.Visible         = $false
$CheckBoxSetPagingAuto.Enabled         = $true

$CheckBoxSetPagingManual
$CheckBoxSetPagingManual                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSetPagingManual.text            = "Initial Size 1x RAM, Max 2x"
$CheckBoxSetPagingManual.location        = New-Object System.Drawing.Point(210,370)
$CheckBoxSetPagingManual.width           = 600
$CheckBoxSetPagingManual.height          = 20
$CheckBoxSetPagingManual.AutoSize        = $false
$CheckBoxSetPagingManual.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSetPagingManual.checked         = $false
$CheckBoxSetPagingManual.Visible         = $false
$CheckBoxSetPagingManual.Enabled         = $true

$CheckBoxBlock60
$CheckBoxBlock60                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxBlock60.text            = "Block 60% of Malware: Enable Virturual Machine, HyperVisore, Core Isolation, Memrory integrity"
$CheckBoxBlock60.location        = New-Object System.Drawing.Point(10,390)
$CheckBoxBlock60.width           = 600
$CheckBoxBlock60.height          = 20
$CheckBoxBlock60.AutoSize        = $false
$CheckBoxBlock60.Font            = 'Microsoft Sans Serif,10'
$CheckBoxBlock60.checked         = $false
$CheckBoxBlock60.Visible         = $false
$CheckBoxBlock60.Enabled         = $true

#--NiteNie--#######################################################################################################################################################################################
$LabelDocuments                   = New-Object system.Windows.Forms.Label
$LabelDocuments.text            = "Documents "
$LabelDocuments.location        = New-Object System.Drawing.Point(10,130)
$LabelDocuments.width           = 200
$LabelDocuments.height          = 20
$LabelDocuments.AutoSize        = $false
$LabelDocuments.Font            = 'Microsoft Sans Serif,10,style=Bold'
$LabelDocuments.Visible         = $false

$CheckBoxFoxitReader                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxFoxitReader.text            = "Foxit Reader "
$CheckBoxFoxitReader.location        = New-Object System.Drawing.Point(10,150)
$CheckBoxFoxitReader.width           = 200
$CheckBoxFoxitReader.height          = 20
$CheckBoxFoxitReader.AutoSize        = $false
$CheckBoxFoxitReader.Font            = 'Microsoft Sans Serif,10'
$CheckBoxFoxitReader.checked         = $false
$CheckBoxFoxitReader.Visible         = $false
$CheckBoxFoxitReader.Enabled         = $true

$CheckBoxSumatraPDF                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSumatraPDF.text            = "Sumatra PDF "
$CheckBoxSumatraPDF.location        = New-Object System.Drawing.Point(210,150)
$CheckBoxSumatraPDF.width           = 200
$CheckBoxSumatraPDF.height          = 20
$CheckBoxSumatraPDF.AutoSize        = $false
$CheckBoxSumatraPDF.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSumatraPDF.checked         = $false
$CheckBoxSumatraPDF.Visible         = $false
$CheckBoxSumatraPDF.Enabled         = $true

$CheckBoxCutePDF                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxCutePDF.text            = "Cute PDF "
$CheckBoxCutePDF.location        = New-Object System.Drawing.Point(410,150)
$CheckBoxCutePDF.width           = 200
$CheckBoxCutePDF.height          = 20
$CheckBoxCutePDF.AutoSize        = $false
$CheckBoxCutePDF.Font            = 'Microsoft Sans Serif,10'
$CheckBoxCutePDF.checked         = $false
$CheckBoxCutePDF.Visible         = $false
$CheckBoxCutePDF.Enabled         = $true

$CheckBoxLebreOffice                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxLebreOffice.text            = "Lebre Office "
$CheckBoxLebreOffice.location        = New-Object System.Drawing.Point(10,170)
$CheckBoxLebreOffice.width           = 200
$CheckBoxLebreOffice.height          = 20
$CheckBoxLebreOffice.AutoSize        = $false
$CheckBoxLebreOffice.Font            = 'Microsoft Sans Serif,10'
$CheckBoxLebreOffice.checked         = $false
$CheckBoxLebreOffice.Visible         = $false
$CheckBoxLebreOffice.Enabled         = $true

$CheckBoxOpenOffice                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxOpenOffice.text            = "Open Office "
$CheckBoxOpenOffice.location        = New-Object System.Drawing.Point(210,170)
$CheckBoxOpenOffice.width           = 200
$CheckBoxOpenOffice.height          = 20
$CheckBoxOpenOffice.AutoSize        = $false
$CheckBoxOpenOffice.Font            = 'Microsoft Sans Serif,10'
$CheckBoxOpenOffice.checked         = $false
$CheckBoxOpenOffice.Visible         = $false
$CheckBoxOpenOffice.Enabled         = $true

$LabelWebBrowsers                 = New-Object system.Windows.Forms.Label
$LabelWebBrowsers.text            = "Web Browsers "
$LabelWebBrowsers.location        = New-Object System.Drawing.Point(10,200)
$LabelWebBrowsers.width           = 200
$LabelWebBrowsers.height          = 20
$LabelWebBrowsers.AutoSize        = $false
$LabelWebBrowsers.Font            = 'Microsoft Sans Serif,10,style=Bold'
$LabelWebBrowsers.Visible         = $false

$CheckBoxFireFox                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxFireFox.text            = "Fire Fox "
$CheckBoxFireFox.location        = New-Object System.Drawing.Point(10,220)
$CheckBoxFireFox.width           = 200
$CheckBoxFireFox.height          = 20
$CheckBoxFireFox.AutoSize        = $false
$CheckBoxFireFox.Font            = 'Microsoft Sans Serif,10'
$CheckBoxFireFox.checked         = $false
$CheckBoxFireFox.Visible         = $false
$CheckBoxFireFox.Enabled         = $true

$CheckBoxChrome                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxChrome.text            = "Chrome "
$CheckBoxChrome.location        = New-Object System.Drawing.Point(210,220)
$CheckBoxChrome.width           = 200
$CheckBoxChrome.height          = 20
$CheckBoxChrome.AutoSize        = $false
$CheckBoxChrome.Font            = 'Microsoft Sans Serif,10'
$CheckBoxChrome.checked         = $false
$CheckBoxChrome.Visible         = $false
$CheckBoxChrome.Enabled         = $true

$CheckBoxOpera                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxOpera.text            = "Opera "
$CheckBoxOpera.location        = New-Object System.Drawing.Point(410,220)
$CheckBoxOpera.width           = 200
$CheckBoxOpera.height          = 20
$CheckBoxOpera.AutoSize        = $false
$CheckBoxOpera.Font            = 'Microsoft Sans Serif,10'
$CheckBoxOpera.checked         = $false
$CheckBoxOpera.Visible         = $false
$CheckBoxOpera.Enabled         = $true

$LabelTools                 = New-Object system.Windows.Forms.Label
$LabelTools.text            = "Tools "
$LabelTools.location        = New-Object System.Drawing.Point(10,250)
$LabelTools.width           = 200
$LabelTools.height          = 20
$LabelTools.AutoSize        = $false
$LabelTools.Font            = 'Microsoft Sans Serif,10,style=Bold'
$LabelTools.Visible         = $false

$CheckBoxFileZilla                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxFileZilla.text            = "FileZilla "
$CheckBoxFileZilla.location        = New-Object System.Drawing.Point(10,270)
$CheckBoxFileZilla.width           = 200
$CheckBoxFileZilla.height          = 20
$CheckBoxFileZilla.AutoSize        = $false
$CheckBoxFileZilla.Font            = 'Microsoft Sans Serif,10'
$CheckBoxFileZilla.checked         = $false
$CheckBoxFileZilla.Visible         = $false
$CheckBoxFileZilla.Enabled         = $true

$CheckBoxNotepad                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxNotepad.text            = "Notepad++ "
$CheckBoxNotepad.location        = New-Object System.Drawing.Point(210,270)
$CheckBoxNotepad.width           = 200
$CheckBoxNotepad.height          = 20
$CheckBoxNotepad.AutoSize        = $false
$CheckBoxNotepad.Font            = 'Microsoft Sans Serif,10'
$CheckBoxNotepad.checked         = $false
$CheckBoxNotepad.Visible         = $false
$CheckBoxNotepad.Enabled         = $true

$CheckBox7Zip                 = New-Object system.Windows.Forms.CheckBox
$CheckBox7Zip.text            = "7-Zip "
$CheckBox7Zip.location        = New-Object System.Drawing.Point(410,270)
$CheckBox7Zip.width           = 200
$CheckBox7Zip.height          = 20
$CheckBox7Zip.AutoSize        = $false
$CheckBox7Zip.Font            = 'Microsoft Sans Serif,10'
$CheckBox7Zip.checked         = $false
$CheckBox7Zip.Visible         = $false
$CheckBox7Zip.Enabled         = $true

$CheckBoxPuTTY                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxPuTTY.text            = "PuTTY "
$CheckBoxPuTTY.location        = New-Object System.Drawing.Point(10,290)
$CheckBoxPuTTY.width           = 200
$CheckBoxPuTTY.height          = 20
$CheckBoxPuTTY.AutoSize        = $false
$CheckBoxPuTTY.Font            = 'Microsoft Sans Serif,10'
$CheckBoxPuTTY.checked         = $false
$CheckBoxPuTTY.Visible         = $false
$CheckBoxPuTTY.Enabled         = $true

$CheckBoxVisualStudioCode                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxVisualStudioCode.text            = "Visual Studio Code "
$CheckBoxVisualStudioCode.location        = New-Object System.Drawing.Point(210,290)
$CheckBoxVisualStudioCode.width           = 200
$CheckBoxVisualStudioCode.height          = 20
$CheckBoxVisualStudioCode.AutoSize        = $false
$CheckBoxVisualStudioCode.Font            = 'Microsoft Sans Serif,10'
$CheckBoxVisualStudioCode.checked         = $false
$CheckBoxVisualStudioCode.Visible         = $false
$CheckBoxVisualStudioCode.Enabled         = $true

$CheckBoxWinRAR                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxWinRAR.text            = "WinRAR "
$CheckBoxWinRAR.location        = New-Object System.Drawing.Point(410,290)
$CheckBoxWinRAR.width           = 200
$CheckBoxWinRAR.height          = 20
$CheckBoxWinRAR.AutoSize        = $false
$CheckBoxWinRAR.Font            = 'Microsoft Sans Serif,10'
$CheckBoxWinRAR.checked         = $false
$CheckBoxWinRAR.Visible         = $false
$CheckBoxWinRAR.Enabled         = $true

$CheckBoxTeamViewer                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxTeamViewer.text            = "Team Viewer "
$CheckBoxTeamViewer.location        = New-Object System.Drawing.Point(10,310)
$CheckBoxTeamViewer.width           = 200
$CheckBoxTeamViewer.height          = 20
$CheckBoxTeamViewer.AutoSize        = $false
$CheckBoxTeamViewer.Font            = 'Microsoft Sans Serif,10'
$CheckBoxTeamViewer.checked         = $false
$CheckBoxTeamViewer.Visible         = $false
$CheckBoxTeamViewer.Enabled         = $true

$CheckBoxImgBurn                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxImgBurn.text            = "ImgBurn "
$CheckBoxImgBurn.location        = New-Object System.Drawing.Point(210,310)
$CheckBoxImgBurn.width           = 200
$CheckBoxImgBurn.height          = 20
$CheckBoxImgBurn.AutoSize        = $false
$CheckBoxImgBurn.Font            = 'Microsoft Sans Serif,10'
$CheckBoxImgBurnchecked         = $false
$CheckBoxImgBurn.Visible         = $false
$CheckBoxImgBurn.Enabled         = $true

$CheckBoxWinDirStat                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxWinDirStat.text            = "WinDirStat "
$CheckBoxWinDirStat.location        = New-Object System.Drawing.Point(410,310)
$CheckBoxWinDirStat.width           = 200
$CheckBoxWinDirStat.height          = 20
$CheckBoxWinDirStat.AutoSize        = $false
$CheckBoxWinDirStat.Font            = 'Microsoft Sans Serif,10'
$CheckBoxWinDirStat.checked         = $false
$CheckBoxWinDirStat.Visible         = $false
$CheckBoxWinDirStat.Enabled         = $true

$LabelMedia                 = New-Object system.Windows.Forms.Label
$LabelMedia.text            = "Media "
$LabelMedia.location        = New-Object System.Drawing.Point(10,340)
$LabelMedia.width           = 200
$LabelMedia.height          = 20
$LabelMedia.AutoSize        = $false
$LabelMedia.Font            = 'Microsoft Sans Serif,10,style=Bold'
$LabelMedia.Visible         = $false

$CheckBoxVLC                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxVLC.text            = "VLC "
$CheckBoxVLC.location        = New-Object System.Drawing.Point(10,360)
$CheckBoxVLC.width           = 200
$CheckBoxVLC.height          = 20
$CheckBoxVLC.AutoSize        = $false
$CheckBoxVLC.Font            = 'Microsoft Sans Serif,10'
$CheckBoxVLC.checked         = $false
$CheckBoxVLC.Visible         = $false
$CheckBoxVLC.Enabled         = $true

$CheckBoxAudacity                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxAudacity.text            = "Audacity "
$CheckBoxAudacity.location        = New-Object System.Drawing.Point(210,360)
$CheckBoxAudacity.width           = 200
$CheckBoxAudacity.height          = 20
$CheckBoxAudacity.AutoSize        = $false
$CheckBoxAudacity.Font            = 'Microsoft Sans Serif,10'
$CheckBoxAudacity.checked         = $false
$CheckBoxAudacity.Visible         = $false
$CheckBoxAudacity.Enabled         = $true

$CheckBoxSpotify                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSpotify.text            = "Spotify "
$CheckBoxSpotify.location        = New-Object System.Drawing.Point(410,360)
$CheckBoxSpotify.width           = 200
$CheckBoxSpotify.height          = 20
$CheckBoxSpotify.AutoSize        = $false
$CheckBoxSpotify.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSpotify.checked         = $false
$CheckBoxSpotify.Visible         = $false
$CheckBoxSpotify.Enabled         = $true

$LabelMessaging                 = New-Object system.Windows.Forms.Label
$LabelMessaging.text            = "Messaging "
$LabelMessaging.location        = New-Object System.Drawing.Point(10,390)
$LabelMessaging.width           = 200
$LabelMessaging.height          = 20
$LabelMessaging.AutoSize        = $false
$LabelMessaging.Font            = 'Microsoft Sans Serif,10,style=Bold'
$LabelMessaging.Visible         = $false

$CheckBoxZoom                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxZoom.text            = "Zoom "
$CheckBoxZoom.location        = New-Object System.Drawing.Point(10,410)
$CheckBoxZoom.width           = 200
$CheckBoxZoom.height          = 20
$CheckBoxZoom.AutoSize        = $false
$CheckBoxZoom.Font            = 'Microsoft Sans Serif,10'
$CheckBoxZoom.checked         = $false
$CheckBoxZoom.Visible         = $false
$CheckBoxZoom.Enabled         = $true

$CheckBoxDiscord                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxDiscord.text            = "Discord "
$CheckBoxDiscord.location        = New-Object System.Drawing.Point(210,410)
$CheckBoxDiscord.width           = 200
$CheckBoxDiscord.height          = 20
$CheckBoxDiscord.AutoSize        = $false
$CheckBoxDiscord.Font            = 'Microsoft Sans Serif,10'
$CheckBoxDiscord.checked         = $false
$CheckBoxDiscord.Visible         = $false
$CheckBoxDiscord.Enabled         = $true

$CheckBoxSkype                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxSkype.text            = "Skype "
$CheckBoxSkype.location        = New-Object System.Drawing.Point(410,410)
$CheckBoxSkype.width           = 200
$CheckBoxSkype.height          = 20
$CheckBoxSkype.AutoSize        = $false
$CheckBoxSkype.Font            = 'Microsoft Sans Serif,10'
$CheckBoxSkype.checked         = $false
$CheckBoxSkype.Visible         = $false
$CheckBoxSkype.Enabled         = $true

$LabelSecurity                 = New-Object system.Windows.Forms.Label
$LabelSecurity.text            = "Security "
$LabelSecurity.location        = New-Object System.Drawing.Point(10,440)
$LabelSecurity.width           = 200
$LabelSecurity.height          = 20
$LabelSecurity.AutoSize        = $false
$LabelSecurity.Font            = 'Microsoft Sans Serif,10,style=Bold'
$LabelSecurity.Visible         = $false

$CheckBoxMailwarebytes                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxMailwarebytes.text            = "Mailwarebytes "
$CheckBoxMailwarebytes.location        = New-Object System.Drawing.Point(10,460)
$CheckBoxMailwarebytes.width           = 200
$CheckBoxMailwarebytes.height          = 20
$CheckBoxMailwarebytes.AutoSize        = $false
$CheckBoxMailwarebytes.Font            = 'Microsoft Sans Serif,10'
$CheckBoxMailwarebytes.checked         = $false
$CheckBoxMailwarebytes.Visible         = $false
$CheckBoxMailwarebytes.Enabled         = $true

$CheckBoxAvast                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxAvast.text            = "Avast "
$CheckBoxAvast.location        = New-Object System.Drawing.Point(210,460)
$CheckBoxAvast.width           = 200
$CheckBoxAvast.height          = 20
$CheckBoxAvast.AutoSize        = $false
$CheckBoxAvast.Font            = 'Microsoft Sans Serif,10'
$CheckBoxAvast.checked         = $false
$CheckBoxAvast.Visible         = $false
$CheckBoxAvast.Enabled         = $true

$CheckBoxKeePass                 = New-Object system.Windows.Forms.CheckBox
$CheckBoxKeePass.text            = "KeePass "
$CheckBoxKeePass.location        = New-Object System.Drawing.Point(410,460)
$CheckBoxKeePass.width           = 200
$CheckBoxKeePass.height          = 20
$CheckBoxKeePass.AutoSize        = $false
$CheckBoxKeePass.Font            = 'Microsoft Sans Serif,10'
$CheckBoxKeePass.checked         = $false
$CheckBoxKeePass.Visible         = $false
$CheckBoxKeePass.Enabled         = $true
#######################################################################

$FormBackupTool.controls.AddRange(@($CheckBoxAutoSelect,$CheckBoxAdvancedSelect,$CheckBoxServer,$CheckBoxQuickClean,$CheckBoxDeepClean,$CheckBoxNewComputer,$ButtonStart,$CheckBoxAdvancedSection,$CheckBoxDisableTelemetry,$CheckBoxEnableTelemetry,$CheckBoxDisableWiFiSense,$CheckBoxEnableWiFiSense,$CheckBoxDisableSmartScreen,$CheckBoxEnableSmartScreen,$CheckBoxDisableWebSearch,$CheckBoxEnableWebSearch,$CheckBoxDisableAppSuggestions,$CheckBoxEnableAppSuggestions,$CheckBoxDisableBackgroundApps,$CheckBoxEnableBackgroundApps,$CheckBoxDisableLockScreenSpotlight,$CheckBoxEnableLockScreenSpotlight,$CheckBoxDisableLocationTracking,$CheckBoxEnableLocationTracking,$CheckBoxDisableMapUpdates,$CheckBoxEnableMapUpdates,$CheckBoxDisableFeedback,$CheckBoxEnableFeedback,$CheckBoxDisableAdvertisingID,$CheckBoxEnableAdvertisingID,$CheckBoxDisableCortana,$CheckBoxEnableCortana,$CheckBoxDisableErrorReporting,$CheckBoxEnableErrorReporting,$CheckBoxDisableAutoLogger,$CheckBoxEnableAutoLogger,$CheckBoxDisableDiagTrack,$CheckBoxEnableDiagTrack,$CheckBoxDisableWAPPush,$CheckBoxEnableWAPPush,$CheckBoxP2PUpdateLocal,$CheckBoxP2PUpdateInternet,$CheckBoxAdvancedSectionNiNite,$CheckBoxAdvancedSectionServer,$CheckBoxAdvancedSectionApp,$CheckBoxAdvancedSectionUI,$CheckBoxAdvancedSectionServices,$CheckBoxAdvancedSectionPrivace,$CheckBoxSetUACLow,$CheckBoxSetUACHigh,$CheckBoxEnableSharingMappedDrives,$CheckBoxDisableSharingMappedDrives,$CheckBoxDisableAdminShares,$CheckBoxEnableAdminShares,$CheckBoxDisableSMB1,$CheckBoxEnableSMB1,$CheckBoxCurrentNetworkPrivate,$CheckBoxCurrentNetworkPublic,$CheckBoxUnknownNetworksPrivate,$CheckBoxUnknownNetworksPublic,$CheckBoxEnableCtrldFolderAccess,$CheckBoxDisableCtrldFolderAccess,$CheckBoxDisableFirewall,$CheckBoxEnableFirewall,$CheckBoxDisableDefender,$CheckBoxEnableDefender,$CheckBoxDisableDefenderCloud,$CheckBoxEnableDefenderCloud,$CheckBoxDisableUpdateMSRT,$CheckBoxEnableUpdateMSRT,$CheckBoxDisableUpdateDriver,$CheckBoxEnableUpdateDriver,$CheckBoxDisableUpdateRestart,$CheckBoxEnableUpdateRestart,$CheckBoxDisableHomeGroups,$CheckBoxEnableHomeGroups,$CheckBoxDisableSharedExperiences,$CheckBoxEnableSharedExperiences,$CheckBoxDisableRemoteAssistance,$CheckBoxEnableRemoteAssistance,$CheckBoxDisableRemoteDesktop,$CheckBoxEnableRemoteDesktop,$CheckBoxDisableAutoplay,$CheckBoxEnableAutoplay,$CheckBoxDisableAutorun,$CheckBoxEnableAutorun,$CheckBoxDisableStorageSense,$CheckBoxEnableStorageSense,$CheckBoxDisableDefragmentation,$CheckBoxEnableDefragmentation,$CheckBoxDisableSuperfetch,$CheckBoxEnableSuperfetch,$CheckBoxDisableIndexing,$CheckBoxEnableIndexing,$CheckBoxSetBIOSTimeUTC,$CheckBoxSetBIOSTimeLocal,$CheckBoxDisableHibernation,$CheckBoxEnableHibernation,$CheckBoxDisableFastStartup,$CheckBoxEnableFastStartup,$CheckBoxDisableActionCenter,$CheckBoxEnableActionCenter,$CheckBoxDisableLockScreen,$CheckBoxEnableLockScreen,$CheckBoxHideNetworkOnLockScreen,$CheckBoxShowNetworkOnLockScreen,$CheckBoxHideShutdownFromLockScreen,$CheckBoxShowShutdownOnLockScreen,$CheckBoxDisableStickyKeys,$CheckBoxEnableStickyKeys,$CheckBoxShowTaskManagerDetails,$CheckBoxHideTaskManagerDetails,$CheckBoxShowFileOperationsDetails,$CheckBoxHideFileOperationsDetails,$CheckBoxDisableFileDeleteConfirm,$CheckBoxEnableFileDeleteConfirm,$CheckBoxShowTaskbarSearchBox,$CheckBoxHideTaskbarSearchBox,$CheckBoxShowTaskView,$CheckBoxHideTaskView,$CheckBoxSmallTaskbarIcons,$CheckBoxLargeTaskbarIcons,$CheckBoxShowTaskbarTitles,$CheckBoxHideTaskbarTitles,$CheckBoxShowTaskbarPeopleIcon,$CheckBoxHideTaskbarPeopleIcon,$CheckBoxShowTrayIcons,$CheckBoxHideTrayIcons,$CheckBoxShowKnownExtensions,$CheckBoxHideKnownExtensions,$CheckBoxShowHiddenFiles,$CheckBoxHideHiddenFiles,$CheckBoxShowSyncNotifications,$CheckBoxHideSyncNotifications,$CheckBoxShowRecentShortcuts,$CheckBoxHideRecentShortcuts,$CheckBoxSetExplorerQuickAccess,$CheckBoxSetExplorerThisPC,$CheckBoxShowThisPCOnDesktop,$CheckBoxHideThisPCFromDesktop,$CheckBoxShowUserFolderOnDesktop,$CheckBoxHideUserFolderFromDesktop,$CheckBoxShowDesktopInThisPC,$CheckBoxHideDesktopFromThisPC,$CheckBoxShowDocumentsInThisPC,$CheckBoxHideDocumentsFromThisPC,$CheckBoxShowDownloadsInThisPC,$CheckBoxHideDownloadsFromThisPC,$CheckBoxShowMusicInThisPC,$CheckBoxHideMusicFromThisPC,$CheckBoxShowPicturesInThisPC,$CheckBoxHidePicturesFromThisPC,$CheckBoxShowVideosInThisPC,$CheckBoxHideVideosFromThisPC,$CheckBoxShow3DObjectsInThisPC,$CheckBoxHide3DObjectsFromThisPC,$CheckBoxSetVisualFXPerformance,$CheckBoxSetVisualFXAppearance,$CheckBoxEnableThumbnails,$CheckBoxDisableThumbnails,$CheckBoxDisableThumbsDB,$CheckBoxEnableThumbsDB,$CheckBoxAddENKeyboard,$CheckBoxRemoveENKeyboard,$CheckBoxDisableNumlock,$CheckBoxEnableNumlock,$CheckBoxDisableOneDrive,$CheckBoxEnableOneDrive,$CheckBoxUninstallOneDrive,$CheckBoxInstallOneDrive,$CheckBoxUninstallMsftBloat,$CheckBoxInstallMsftBloat,$CheckBoxUninstallThirdPartyBloat,$CheckBoxInstallThirdPartyBloat,$CheckBoxUninstallWindowsStore,$CheckBoxInstallWindowsStore,$CheckBoxDisableXboxFeatures,$CheckBoxEnableXboxFeatures,$CheckBoxDisableAdobeFlash,$CheckBoxEnableAdobeFlash,$CheckBoxUninstallMediaPlayer,$CheckBoxInstallMediaPlayer,$CheckBoxUninstallWorkFolders,$CheckBoxInstallWorkFolders,$CheckBoxUninstallLinuxSubsystem,$CheckBoxInstallLinuxSubsystem,$CheckBoxUninstallHyperV,$CheckBoxInstallHyperV,$CheckBoxSetPhotoViewerAssociation,$CheckBoxUnsetPhotoViewerAssociation,$CheckBoxAddPhotoViewerOpenWith,$CheckBoxRemovePhotoViewerOpenWith,$CheckBoxDisableSearchAppInStore,$CheckBoxEnableSearchAppInStore,$CheckBoxDisableNewAppPrompt,$CheckBoxEnableNewAppPrompt,$CheckBoxDisableF8BootMenu,$CheckBoxEnableF8BootMenu,$CheckBoxSetDEPOptIn,$CheckBoxSetDEPOptOut,$CheckBoxHideServerManagerOnLogin,$CheckBoxShowServerManagerOnLogin,$CheckBoxDisableShutdownTracker,$CheckBoxEnableShutdownTracker,$CheckBoxDisablePasswordPolicy,$CheckBoxEnablePasswordPolicy,$CheckBoxDisableCtrlAltDelLogin,$CheckBoxEnableCtrlAltDelLogin,$CheckBoxDisableIEEnhancedSecurity,$CheckBoxEnableIEEnhancedSecurity,$CheckBoxClearAll,$CheckBoxAdvancedSectionOther,$CheckBoxDisableAutoMaintenance,$CheckBoxEnableAutoMaintenance,$TextBoxOutput,$CheckBoxDeleteTempFiles,$CheckBoxCleanWinSXS,$CheckBoxDiskCleanup,$CheckBoxSetEasternTime,$CheckBoxSetCentralTime,$CheckBoxSetMountainTime,$CheckBoxSetPacificTime,$CheckBoxSyncTimeToInternet,$LabelDocuments,$CheckBoxFoxitReader,$CheckBoxSumatraPDF,$CheckBoxCutePDF,$CheckBoxLebreOffice,$CheckBoxOpenOffice,$LabelWebBrowsers,$CheckBoxFireFox,$CheckBoxChrome,$CheckBoxOpera,$CheckBoxSFCScanNow,$LabelTools,$CheckBoxFileZilla,$CheckBoxNotepad,$CheckBox7Zip,$CheckBoxPuTTY,$CheckBoxVisualStudioCode,$CheckBoxWinRAR,$CheckBoxTeamViewer,$CheckBoxImgBurn,$CheckBoxWinDirStat,$CheckBoxSpotify,$CheckBoxAudacity,$CheckBoxVLC,$LabelMedia,$LabelSecurity,$CheckBoxMailwarebytes,$CheckBoxAvast,$CheckBoxKeePass,$LabelMessaging,$CheckBoxZoom,$CheckBoxDiscord,$CheckBoxSkype,$CheckBoxWiFiNamePassword,$CheckBoxStop11,$CheckBoxEnableMulticasting,$CheckBoxDisableMulticasting,$CheckBoxSetPagingAuto,$CheckBoxSetPagingManual,$CheckBoxEnableIPV6,$CheckBoxDisableIPV6,$CheckBoxBlock60))

$ButtonStart.Add_Click({FunctionStart})
$CheckBoxAutoSelect.Add_Click({FunctionAutoSelect})
$CheckBoxAdvancedSelect.Add_Click({FunctionAdvancedSelect})
$CheckBoxServer.Add_Click({FunctionServer})
$CheckBoxQuickClean.Add_Click({FuctionQuickClean})
$CheckBoxDeepClean.Add_Click({FunctionDeepClean})
$CheckBoxNewComputer.Add_Click({FunctionNewComputer})
$CheckBoxAdvancedSectionNiNite.Add_Click({FunctionAdvancedSectionNiNite})
$CheckBoxAdvancedSectionServer.Add_Click({FunctionAdvancedSectionServer})
$CheckBoxAdvancedSectionApp.Add_Click({FunctionAdvancedSectionApp})
$CheckBoxAdvancedSectionUI.Add_Click({FunctionAdvancedSectionUI})
$CheckBoxAdvancedSectionServices.Add_Click({FunctionAdvancedSectionServices})
$CheckBoxAdvancedSectionPrivace.Add_Click({FunctionAdvancedSectionPrivace})
$CheckBoxDisableTelemetry.Add_Click({FunctionDisableTelemetry})
$CheckBoxEnableTelemetry.Add_Click({FunctionEnableTelemetry})
$CheckBoxDisableWiFiSense.Add_Click({FunctionDisableWiFiSense})
$CheckBoxEnableWiFiSense.Add_Click({FunctionEnableWiFiSense})
$CheckBoxDisableSmartScreen.Add_Click({FunctionDisableSmartScreen})
$CheckBoxEnableSmartScreen.Add_Click({FunctionEnableSmartScreen})
$CheckBoxDisableWebSearch.Add_Click({FunctionDisableWebSearch})
$CheckBoxEnableWebSearch.Add_Click({FunctionEnableWebSearch})
$CheckBoxDisableAppSuggestions.Add_Click({FunctionDisableAppSuggestions})
$CheckBoxEnableAppSuggestions.Add_Click({FunctionEnableAppSuggestions})
$CheckBoxDisableBackgroundApps.Add_Click({FunctionDisableBackgroundApps})
$CheckBoxEnableBackgroundApps.Add_Click({FunctionEnableBackgroundApps})
$CheckBoxDisableLockScreenSpotlight.Add_Click({FunctionDisableLockScreenSpotlight})
$CheckBoxEnableLockScreenSpotlight.Add_Click({FunctionEnableLockScreenSpotlight})
$CheckBoxDisableLocationTracking.Add_Click({FunctionDisableLocationTracking})
$CheckBoxEnableLocationTracking.Add_Click({FunctionEnableLocationTracking})
$CheckBoxDisableMapUpdates.Add_Click({FunctionDisableMapUpdates})
$CheckBoxEnableMapUpdates.Add_Click({FunctionEnableMapUpdates})
$CheckBoxDisableFeedback.Add_Click({FunctionDisableFeedback})
$CheckBoxEnableFeedback.Add_Click({FunctionEnableFeedback})
$CheckBoxDisableAdvertisingID.Add_Click({FunctionDisableAdvertisingID})
$CheckBoxEnableAdvertisingID.Add_Click({FunctionEnableAdvertisingID})
$CheckBoxDisableCortana.Add_Click({FunctionDisableCortana})
$CheckBoxEnableCortana.Add_Click({FunctionEnableCortana})
$CheckBoxDisableErrorReporting.Add_Click({FunctionDisableErrorReporting})
$CheckBoxEnableErrorReporting.Add_Click({FunctionEnableErrorReporting})
$CheckBoxDisableAutoLogger.Add_Click({FunctionDisableAutoLogger})
$CheckBoxEnableAutoLogger.Add_Click({FunctionEnableAutoLogger})
$CheckBoxDisableDiagTrack.Add_Click({FunctionDisableDiagTrack})
$CheckBoxEnableDiagTrack.Add_Click({FunctionEnableDiagTrack})
$CheckBoxDisableWAPPush.Add_Click({FunctionDisableWAPPush})
$CheckBoxEnableWAPPush.Add_Click({FunctionEnableWAPPush})
$CheckBoxP2PUpdateLocal.Add_Click({FunctionP2PUpdateLocal})
$CheckBoxP2PUpdateInternet.Add_Click({FunctionP2PUpdateInternet})
$CheckBoxSetUACLow.Add_Click({FunctionSetUACLow})
$CheckBoxSetUACHigh.Add_Click({FunctionSetUACHigh})
$CheckBoxEnableSharingMappedDrives.Add_Click({FunctionEnableSharingMappedDrives})
$CheckBoxDisableSharingMappedDrives.Add_Click({FunctionDisableSharingMappedDrives})
$CheckBoxDisableAdminShares.Add_Click({FunctionDisableAdminShares})
$CheckBoxEnableAdminShares.Add_Click({FunctionEnableAdminShares})
$CheckBoxDisableSMB1.Add_Click({FunctionDisableSMB1})
$CheckBoxEnableSMB1.Add_Click({FunctionEnableSMB1})
$CheckBoxCurrentNetworkPrivate.Add_Click({FunctionCurrentNetworkPrivate})
$CheckBoxCurrentNetworkPublic.Add_Click({FunctionCurrentNetworkPublic})
$CheckBoxUnknownNetworksPrivate.Add_Click({FunctionUnknownNetworksPrivate})
$CheckBoxUnknownNetworksPublic.Add_Click({FunctionUnknownNetworksPublic})
$CheckBoxEnableCtrldFolderAccess.Add_Click({FunctionEnableCtrldFolderAccess})
$CheckBoxDisableCtrldFolderAccess.Add_Click({FunctionDisableCtrldFolderAccess})
$CheckBoxDisableFirewall.Add_Click({FunctionDisableFirewall})
$CheckBoxEnableFirewall.Add_Click({FunctionEnableFirewall})
$CheckBoxDisableDefender.Add_Click({FunctionDisableDefender})
$CheckBoxEnableDefender.Add_Click({FunctionEnableDefender})
$CheckBoxDisableDefenderCloud.Add_Click({FunctionDisableDefenderCloud})
$CheckBoxEnableDefenderCloud.Add_Click({FunctionEnableDefenderCloud})
$CheckBoxDisableUpdateMSRT.Add_Click({FunctionDisableUpdateMSRT})
$CheckBoxEnableUpdateMSRT.Add_Click({FunctionEnableUpdateMSRT})
$CheckBoxDisableUpdateDriver.Add_Click({FunctionDisableUpdateDriver})
$CheckBoxEnableUpdateDriver.Add_Click({FunctionEnableUpdateDriver})
$CheckBoxDisableUpdateRestart.Add_Click({FunctionDisableUpdateRestart})
$CheckBoxEnableUpdateRestart.Add_Click({FunctionEnableUpdateRestart})
$CheckBoxDisableHomeGroups.Add_Click({FunctionDisableHomeGroups})
$CheckBoxEnableHomeGroups.Add_Click({FunctionEnableHomeGroups})
$CheckBoxDisableSharedExperiences.Add_Click({FunctionDisableSharedExperiences})
$CheckBoxEnableSharedExperiences.Add_Click({FunctionEnableSharedExperiences})
$CheckBoxDisableRemoteAssistance.Add_Click({FunctionDisableRemoteAssistance})
$CheckBoxEnableRemoteAssistance.Add_Click({FunctionEnableRemoteAssistance})
$CheckBoxDisableRemoteDesktop.Add_Click({FunctionDisableRemoteDesktop})
$CheckBoxEnableRemoteDesktop.Add_Click({FunctionEnableRemoteDesktop})
$CheckBoxDisableAutoplay.Add_Click({FunctionDisableAutoplay})
$CheckBoxEnableAutoplay.Add_Click({FunctionEnableAutoplay})
$CheckBoxDisableAutorun.Add_Click({FunctionDisableAutorun})
$CheckBoxEnableAutorun.Add_Click({FunctionEnableAutorun})
$CheckBoxDisableStorageSense.Add_Click({FunctionDisableStorageSense})
$CheckBoxEnableStorageSense.Add_Click({FunctionEnableStorageSense})
$CheckBoxDisableDefragmentation.Add_Click({FunctionDisableDefragmentation})
$CheckBoxEnableDefragmentation.Add_Click({FunctionEnableDefragmentation})
$CheckBoxDisableSuperfetch.Add_Click({FunctionDisableSuperfetch})
$CheckBoxEnableSuperfetch.Add_Click({FunctionEnableSuperfetch})
$CheckBoxDisableIndexing.Add_Click({FunctionDisableIndexing})
$CheckBoxEnableIndexing.Add_Click({FunctionEnableIndexing})
$CheckBoxSetBIOSTimeUTC.Add_Click({FunctionSetBIOSTimeUTC})
$CheckBoxSetBIOSTimeLocal.Add_Click({FunctionSetBIOSTimeLocal})
$CheckBoxDisableHibernation.Add_Click({FunctionDisableHibernation})
$CheckBoxEnableHibernation.Add_Click({FunctionEnableHibernation})
$CheckBoxDisableFastStartup.Add_Click({FunctionDisableFastStartup})
$CheckBoxEnableFastStartup.Add_Click({FunctionEnableFastStartup})
$CheckBoxDisableActionCenter.Add_Click({FunctionDisableActionCenter})
$CheckBoxEnableActionCenter.Add_Click({FunctionEnableActionCenter})
$CheckBoxDisableLockScreen.Add_Click({FunctionDisableLockScreen})
$CheckBoxEnableLockScreen.Add_Click({FunctionEnableLockScreen})
$CheckBoxHideNetworkOnLockScreen.Add_Click({FunctionHideNetworkOnLockScreen})
$CheckBoxShowNetworkOnLockScreen.Add_Click({FunctionShowNetworkOnLockScreen})
$CheckBoxHideShutdownFromLockScreen.Add_Click({FunctionHideShutdownFromLockScreen})
$CheckBoxShowShutdownOnLockScreen.Add_Click({FunctionShowShutdownOnLockScreen})
$CheckBoxDisableStickyKeys.Add_Click({FunctionDisableStickyKeys})
$CheckBoxEnableStickyKeys.Add_Click({FunctionEnableStickyKeys})
$CheckBoxShowTaskManagerDetails.Add_Click({FunctionShowTaskManagerDetails})
$CheckBoxHideTaskManagerDetails.Add_Click({FunctionHideTaskManagerDetails})
$CheckBoxShowFileOperationsDetails.Add_Click({FunctionShowFileOperationsDetails})
$CheckBoxHideFileOperationsDetails.Add_Click({FunctionHideFileOperationsDetails})
$CheckBoxDisableFileDeleteConfirm.Add_Click({FunctionDisableFileDeleteConfirm})
$CheckBoxEnableFileDeleteConfirm.Add_Click({FunctionEnableFileDeleteConfirm})
$CheckBoxShowTaskbarSearchBox.Add_Click({FunctionShowTaskbarSearchBox})
$CheckBoxHideTaskbarSearchBox.Add_Click({FunctionHideTaskbarSearchBox})
$CheckBoxShowTaskView.Add_Click({FunctionShowTaskView})
$CheckBoxHideTaskView.Add_Click({FunctionHideTaskView})
$CheckBoxSmallTaskbarIcons.Add_Click({FunctionSmallTaskbarIcons})
$CheckBoxLargeTaskbarIcons.Add_Click({FunctionLargeTaskbarIcons})
$CheckBoxShowTaskbarTitles.Add_Click({FunctionShowTaskbarTitles})
$CheckBoxHideTaskbarTitles.Add_Click({FunctionHideTaskbarTitles})
$CheckBoxShowTaskbarPeopleIcon.Add_Click({FunctionShowTaskbarPeopleIcon})
$CheckBoxHideTaskbarPeopleIcon.Add_Click({FunctionHideTaskbarPeopleIcon})
$CheckBoxShowTrayIcons.Add_Click({FunctionShowTrayIcons})
$CheckBoxHideTrayIcons.Add_Click({FunctionHideTrayIcons})
$CheckBoxShowKnownExtensions.Add_Click({FunctionShowKnownExtensions})
$CheckBoxHideKnownExtensions.Add_Click({FunctionHideKnownExtensions})
$CheckBoxShowHiddenFiles.Add_Click({FunctionShowHiddenFiles})
$CheckBoxHideHiddenFiles.Add_Click({FunctionHideHiddenFiles})
$CheckBoxShowSyncNotifications.Add_Click({FunctionShowSyncNotifications})
$CheckBoxHideSyncNotifications.Add_Click({FunctionHideSyncNotifications})
$CheckBoxShowRecentShortcuts.Add_Click({FunctionShowRecentShortcuts})
$CheckBoxHideRecentShortcuts.Add_Click({FunctionHideRecentShortcuts})
$CheckBoxSetExplorerQuickAccess.Add_Click({FunctionSetExplorerQuickAccess})
$CheckBoxSetExplorerThisPC.Add_Click({FunctionSetExplorerThisPC})
$CheckBoxShowThisPCOnDesktop.Add_Click({FunctionShowThisPCOnDesktop})
$CheckBoxHideThisPCFromDesktop.Add_Click({FunctionHideThisPCFromDesktop})
$CheckBoxShowUserFolderOnDesktop.Add_Click({FunctionShowUserFolderOnDesktop})
$CheckBoxHideUserFolderFromDesktop.Add_Click({FunctionHideUserFolderFromDesktop})
$CheckBoxShowDesktopInThisPC.Add_Click({FunctionShowDesktopInThisPC})
$CheckBoxHideDesktopFromThisPC.Add_Click({FunctionHideDesktopFromThisPC})
$CheckBoxShowDocumentsInThisPC.Add_Click({FunctionShowDocumentsInThisPC})
$CheckBoxHideDocumentsFromThisPC.Add_Click({FunctionHideDocumentsFromThisPC})
$CheckBoxShowDownloadsInThisPC.Add_Click({FunctionShowDownloadsInThisPC})
$CheckBoxHideDownloadsFromThisPC.Add_Click({FunctionHideDownloadsFromThisPC})
$CheckBoxShowMusicInThisPC.Add_Click({FunctionShowMusicInThisPC})
$CheckBoxHideMusicFromThisPC.Add_Click({FunctionHideMusicFromThisPC})
$CheckBoxShowPicturesInThisPC.Add_Click({FunctionShowPicturesInThisPC})
$CheckBoxHidePicturesFromThisPC.Add_Click({FunctionHidePicturesFromThisPC})
$CheckBoxShowVideosInThisPC.Add_Click({FunctionShowVideosInThisPC})
$CheckBoxHideVideosFromThisPC.Add_Click({FunctionHideVideosFromThisPC})
$CheckBoxShow3DObjectsInThisPC.Add_Click({FunctionShow3DObjectsInThisPC})
$CheckBoxHide3DObjectsFromThisPC.Add_Click({FunctionHide3DObjectsFromThisPC})
$CheckBoxSetVisualFXPerformance.Add_Click({FunctionSetVisualFXPerformance})
$CheckBoxSetVisualFXAppearance.Add_Click({FunctionSetVisualFXAppearance})
$CheckBoxEnableThumbnails.Add_Click({FunctionEnableThumbnails})
$CheckBoxDisableThumbnails.Add_Click({FunctionDisableThumbnails})
$CheckBoxDisableThumbsDB.Add_Click({FunctionDisableThumbsDB})
$CheckBoxEnableThumbsDB.Add_Click({FunctionEnableThumbsDB})
$CheckBoxAddENKeyboard.Add_Click({FunctionAddENKeyboard})
$CheckBoxRemoveENKeyboard.Add_Click({FunctionRemoveENKeyboard})
$CheckBoxDisableNumlock.Add_Click({FunctionDisableNumlock})
$CheckBoxEnableNumlock.Add_Click({FunctionEnableNumlock})
$CheckBoxDisableOneDrive.Add_Click({FunctionxDisableOneDrive})
$CheckBoxEnableOneDrive.Add_Click({FunctionoxEnableOneDrive})
$CheckBoxUninstallOneDrive.Add_Click({FunctionUninstallOneDrive})
$CheckBoxInstallOneDrive.Add_Click({FunctionInstallOneDrive})
$CheckBoxUninstallMsftBloat.Add_Click({FunctionUninstallMsftBloat})
$CheckBoxInstallMsftBloat.Add_Click({FunctionInstallMsftBloat})
$CheckBoxUninstallThirdPartyBloat.Add_Click({FunctionUninstallThirdPartyBloat})
$CheckBoxInstallThirdPartyBloat.Add_Click({FunctionInstallThirdPartyBloat})
$CheckBoxUninstallWindowsStore.Add_Click({FunctionUninstallWindowsStore})
$CheckBoxInstallWindowsStore.Add_Click({FunctionInstallWindowsStore})
$CheckBoxDisableXboxFeatures.Add_Click({FunctionDisableXboxFeatures})
$CheckBoxEnableXboxFeatures.Add_Click({FunctionEnableXboxFeatures})
$CheckBoxDisableAdobeFlash.Add_Click({FunctionDisableAdobeFlash})
$CheckBoxEnableAdobeFlash.Add_Click({FunctionEnableAdobeFlash})
$CheckBoxUninstallMediaPlayer.Add_Click({FunctionUninstallMediaPlayer})
$CheckBoxInstallMediaPlayer.Add_Click({FunctionInstallMediaPlayer})
$CheckBoxUninstallWorkFolders.Add_Click({FunctionUninstallWorkFolders})
$CheckBoxInstallWorkFolders.Add_Click({FunctionInstallWorkFolders})
$CheckBoxUninstallLinuxSubsystem.Add_Click({FunctionUninstallLinuxSubsystem})
$CheckBoxInstallLinuxSubsystem.Add_Click({FunctionInstallLinuxSubsystem})
$CheckBoxUninstallHyperV.Add_Click({FunctionUninstallHyperV})
$CheckBoxInstallHyperV.Add_Click({FunctionInstallHyperV})
$CheckBoxSetPhotoViewerAssociation.Add_Click({FunctionSetPhotoViewerAssociation})
$CheckBoxUnsetPhotoViewerAssociation.Add_Click({FunctionUnsetPhotoViewerAssociation})
$CheckBoxAddPhotoViewerOpenWith.Add_Click({FunctionAddPhotoViewerOpenWith})
$CheckBoxRemovePhotoViewerOpenWith.Add_Click({FunctionRemovePhotoViewerOpenWith})
$CheckBoxDisableSearchAppInStore.Add_Click({FunctionDisableSearchAppInStore})
$CheckBoxEnableSearchAppInStore.Add_Click({FunctionEnableSearchAppInStore})
$CheckBoxDisableNewAppPrompt.Add_Click({FunctionDisableNewAppPrompt})
$CheckBoxEnableNewAppPrompt.Add_Click({FunctionEnableNewAppPrompt})
$CheckBoxDisableF8BootMenu.Add_Click({FunctionDisableF8BootMenu})
$CheckBoxEnableF8BootMenu.Add_Click({FunctionEnableF8BootMenu})
$CheckBoxSetDEPOptIn.Add_Click({FunctionSetDEPOptIn})
$CheckBoxSetDEPOptOut.Add_Click({FunctionSetDEPOptOut})
$CheckBoxHideServerManagerOnLogin.Add_Click({FunctionHideServerManagerOnLogin})
$CheckBoxShowServerManagerOnLogin.Add_Click({FunctionShowServerManagerOnLogin})
$CheckBoxDisableShutdownTracker.Add_Click({FunctionDisableShutdownTracker})
$CheckBoxEnableShutdownTracker.Add_Click({FunctionEnableShutdownTracker})
$CheckBoxDisablePasswordPolicy.Add_Click({FunctionDisablePasswordPolicy})
$CheckBoxEnablePasswordPolicy.Add_Click({FunctionEnablePasswordPolicy})
$CheckBoxDisableCtrlAltDelLogin.Add_Click({FunctionDisableCtrlAltDelLogin})
$CheckBoxEnableCtrlAltDelLogin.Add_Click({FunctionEnableCtrlAltDelLogin})
$CheckBoxDisableIEEnhancedSecurity.Add_Click({FunctionDisableIEEnhancedSecurity})
$CheckBoxEnableIEEnhancedSecurity.Add_Click({FunctionEnableIEEnhancedSecurity})
$CheckBoxClearAll.Add_Click({FunctionClearAll})
$CheckBoxAdvancedSectionOther.Add_Click({FunctionAdvancedSectionOther})
$CheckBoxDisableAutoMaintenance.Add_Click({FunctionDisableAutoMaintenance})
$CheckBoxEnableAutoMaintenance.Add_Click({FunctionEnableAutoMaintenance})
$CheckBoxSetEasternTime.Add_Click({FunctionSetEasternTime})
$CheckBoxSetCentralTime.Add_Click({FunctionSetCentralTime})
$CheckBoxSetMountainTime.Add_Click({FunctionSetMountainTime})
$CheckBoxSetPacificTime.Add_Click({FunctionSetPacificTime})
$CheckBoxEnableMulticasting.Add_Click({FunctionEnableMulticasting})
$CheckBoxDisableMulticasting.Add_Click({FunctionDisableMulticasting})
$CheckBoxSetPagingAuto.Add_Click({FunctionSetPagingAuto})
$CheckBoxSetPagingManual.Add_Click({FunctionSetPagingManual})
$CheckBoxEnableIPV6.Add_Click({FunctionEnableIPV6})
$CheckBoxDisableIPV6.Add_Click({FunctionDisableIPV6})

FuctionQuickClean

[void]$FormBackupTool.ShowDialog()