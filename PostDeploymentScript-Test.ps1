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
