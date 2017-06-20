$LogFile = $env:TEMP + "\" + "MITAzureVMPostDeploymentScript.Log"
<#
    .SYNOPSIS
        Write to Log File
    
    .DESCRIPTION
        Write to Log File
    
    .PARAMETER Message
        [string] Provide message to write to log
    
    .EXAMPLE
        		PS C:\> Write-Log -Message 'Important Message'
    
    .NOTES
        Additional information about the function.
#>
function Write-Log {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
                   Position = 1,
                   HelpMessage = '[string] Provide message to write to log')]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    
    $TimeStamp = Get-Date -format "yyyy-MM-dd HH:mm:ss"
    ($TimeStamp + " " + $Message) | Out-File -FilePath $LogFile -Append    
}

Write-Log "`n----> Log start <----"
# Disable UAC
$UACKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (Test-Path $UACKey)
{
    Write-Log "Registry path found, checking EnableLUA value..."
    $val=$null
    $val = Get-ItemProperty -Path $UACKey -Name "EnableLUA"
    if($val.EnableLUA -ne 0)
    {
        Write-Log "Setting EnableLUA to 0..."
        Set-ItemProperty -Path $UACKey -Name "EnableLUA" -value 0
    }
    else
    {
        Write-Log "UAC already disabled"
    }
}
else
{
    Write-Log "Disabling UAC"
    New-Item $UACKey -Force|Out-Null
    New-ItemProperty -Path $UACKey -Name EnableLUA -PropertyType DWord -Value 0 -Force|Out-Null
}

# Disable the logon prompt "Do you want to find PCs, devices, and content on this network, and automatically connect to devices like printers and TVs?"
if (Test-Path HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff)
{
    Write-Log "Network Wizard already disabled"
}
else
{
    Write-Log "Disabling Network Wizard"
    New-Item -Path HKLM:\System\CurrentControlSet\Control\Network -Name NewNetworkWindowOff –Force
}


# Disable IE Enahcned Security for both user and admin
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
if (Test-Path $AdminKey)
{
    Write-Log "IESec Admin Key path found"
    $val=$null
    $val = Get-ItemProperty -Path $AdminKey -Name "IsInstalled"
    if($val.IsInstalled -ne 0)
    {
        Write-Log "Setting IESec Admin key"
        Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
        Stop-Process -Name Explorer -Force
        Write-Log "IE Enhanced Security Configuration (ESC) has been disabled for admin."
        Start-Process Explorer
    }
    else
    {
        Write-Log "IESec Admin Key already set"
    }
}
else
{
    Write-Log "IESec Admin Key path NOT found, creating..."
    New-Item $AdminKey -Force|Out-Null
    New-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force|Out-Null
    Stop-Process -Name Explorer -Force
    Write-Log "IE Enhanced Security Configuration (ESC) has been disabled for admin."
    Start-Process Explorer
}

if (Test-Path $UserKey)
{
    Write-Log "IESec Admin Key path found"
    $val=$null
    $val = Get-ItemProperty -Path $UserKey -Name "IsInstalled"
    if($val.IsInstalled -ne 0)
    {
        Write-Log "Setting IESec Admin key"
        Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
        Stop-Process -Name Explorer -Force
        Write-Log "IE Enhanced Security Configuration (ESC) has been disabled for user."
        Start-Process Explorer
    }
    else
    {
        Write-Log "IESec User Key already set"
    }
}
else
{
    Write-Log "IESec User Key path NOT found, creating..."
    New-Item $UserKey -Force|Out-Null
    New-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force|Out-Null
    Stop-Process -Name Explorer -Force
    Write-Log "IE Enhanced Security Configuration (ESC) has been disabled for user."
    Start-Process Explorer
}



# Disable IPv6 binding on all NICs, and change Adapter name to match it's IP

$NICs=Get-NetAdapter
foreach ($NIC in $NICs)
{
    # Disable IPv6 binding
    $IPv6Binding=$null
    $IPv6Binding=Get-NetAdapterBinding -Name $NIC.name -ComponentID ms_tcpip6
    if ($IPv6Binding -and $IPv6Binding.Enabled)
    {
        Write-Log ("Disabling IPv6 binding on " + $NIC.Name)
        Disable-NetAdapterBinding -Name $NIC.Name -ComponentID ms_tcpip6
    }
    else
    {
        Write-Log ("IPv6 already disabled on " + $NIC.Name)
    }

    # Rename NIC name
    $PreferredName=(Get-NetIPAddress -InterfaceIndex $NIC.ifIndex).IPAddress
    if ($NIC.Name -ne $PreferredName)
    {
        Write-Log ("Changing NIC name from: "+ $NIC.Name + " to " + $PreferredName)
        Rename-NetAdapter -Name $NIC.Name -NewName $PreferredName
    }
    else
    {
        Write-Log "NIC name is already $PreferredName"
    }
}

# Disable Chimney offloading

if (((Get-NetOffloadGlobalSetting).Chimney).tostring() -ne "disabled")
{
    Write-Log "Disabling Chimney offloading"
    Set-NetOffloadGlobalSetting -Chimney Disabled
}
else
{
    Write-Log "Chimney offloading already disabled"
}


# Disable Auto-Tunning
if ((((Get-NetTCPSetting -SettingName DatacenterCustom).AutoTuningLevelLocal).tostring()) -ne "Disabled")
{
    Write-Log "Disabling Auto-Tuning"
    Set-NetTCPSetting -SettingName DatacenterCustom -AutoTuningLevelLocal Disabled
}
else
{
    Write-Log "Auto-Tuning already disabled"
}

# Disable Windows Update
$WUKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

if (Test-Path $WUKey) {
    Write-Log "Windows Update Key path found"
    $val = $null
    $val = Get-ItemProperty -Path $WUKey -Name "NoAutoUpdate"
    if ($val.NoAutoUpdate -ne 1) {
        Write-Log "Disabling Windows Update"
        Set-ItemProperty -Path $WUKey -Name "NoAutoUpdate" -Value 1
        Write-Log "Windows Update Disabled"
    } else {
        Write-Log "Windows Update already disabled"
    }
} else {
    Write-Log "Windows Update Key path NOT found, creating..."
    New-Item $WUKey -Force | Out-Null
    New-ItemProperty -Path $WUKey -Name "NoAutoUpdate" -Value 1 -Force | Out-Null
    Write-Log "Windows Update Disabled"
}

# Disable Windows Firewall on all profiles
if ((Get-NetFirewallProfile).Enabled -contains "true") {
    Write-Log "Disabling Windows Firewall on all profiles"
    Set-NetFirewallProfile -Profile * -Enabled False
} else {
    Write-Log "Windows Firewall is already disabled on all profiles"
}

# Activate Windows
function Get-ActivationStatus {
[CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$DNSHostName = $Env:COMPUTERNAME
    )
    process {
        try {
            $wpa = Get-WmiObject SoftwareLicensingProduct -ComputerName $DNSHostName `
            -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" `
            -Property LicenseStatus -ErrorAction Stop
        } catch {
            $status = New-Object ComponentModel.Win32Exception ($_.Exception.ErrorCode)
            $wpa = $null    
        }
        $out = New-Object psobject -Property @{
            ComputerName = $DNSHostName;
            Status = [string]::Empty;
        }
        if ($wpa) {
            :outer foreach($item in $wpa) {
                switch ($item.LicenseStatus) {
                    0 {$out.Status = "Unlicensed"}
                    1 {$out.Status = "Licensed"; break outer}
                    2 {$out.Status = "Out-Of-Box Grace Period"; break outer}
                    3 {$out.Status = "Out-Of-Tolerance Grace Period"; break outer}
                    4 {$out.Status = "Non-Genuine Grace Period"; break outer}
                    5 {$out.Status = "Notification"; break outer}
                    6 {$out.Status = "Extended Grace"; break outer}
                    default {$out.Status = "Unknown value"}
                }
            }
        } else {$out.Status = $status.Message}
        $out
    }
}

if ((Get-ActivationStatus -DNSHostName $env:COMPUTERNAME).Status -ne "Licensed")
{
    Write-Log "Computer is not activated, trying activation..."

    $OSversion = (Get-WmiObject -class Win32_OperatingSystem).Caption

    switch -Regex ($OSversion) {
        'Windows 8.1 Professional N'             {$key = 'HMCNV-VVBFX-7HMBH-CTY9B-B4FXY';break}
        'Windows 8.1 Professional'               {$key = 'GCRJD-8NW9H-F2CDX-CCM8D-9D6T9';break}
        'Windows 8.1 Enterprise N'               {$key = 'TT4HM-HN7YT-62K67-RGRQJ-JFFXW';break}
        'Windows 8.1 Enterprise'                 {$key = 'MHF9N-XY6XB-WVXMC-BTDCT-MKKG7';break}
        'Windows Server 2012 R2 Standard'        {$key = 'D2N9P-3P6X9-2R39C-7RTCD-MDVJX';break}
        'Windows Server 2012 R2 Datacenter'      {$key = 'W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9';break}
    }
    Write-Log "Installing KMS key"
    cscript c:\windows\system32\slmgr.vbs /ipk $key
    Write-Log "Clean up KMS server cache"
    cscript c:\windows\system32\slmgr.vbs /ckms
    Write-Log "Activate Windows"
    cscript c:\windows\system32\slmgr.vbs /ato
    Write-Log "Current Activation information"
    cscript c:\windows\system32\slmgr.vbs /dli
}
else
{
    Write-Log "Computer is already activated"
}





