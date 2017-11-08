#Requires -Version 2
<#
.SYNOPSIS
Get System Report
Create html report with selected level of events and time from windows eventlog. Basic system report.
Script supports run locally.

.DESCRIPTION
Get System Report
(c) 2016-2017 Michal Zobec, ZOBEC Consulting. All Rights Reserved.
web: www.michalzobec.cz, mail: michal@zobec.net
License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) https://creativecommons.org/licenses/by-sa/4.0/

Documentation is in file readme.md.
Release notes is in file changelog.md.

.OUTPUTS
HTML table with selected level of events in filename format <HOSTNAME>-<DATE>-<TIME>.html.

.EXAMPLE
C:\> get-systemreport.ps1

.LINK
http://www.michalzobec.cz/

#>
Set-StrictMode -Version Latest


######
$ScriptName = "Get System Report"
$ScriptVersion = "17.11.08.1"
######


######
# External configuration file
$ConfigurationFileName = "get-systemreport-config-zobec.ps1"
######

$ScriptDir = (Split-Path $myinvocation.MyCommand.Path)

Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False,
            HelpMessage = "Select log level.")]
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
        [String]
        $Level = "INFO",

        [Parameter(Mandatory = $True,
            HelpMessage = "Information text to logfile.")]
        [string]
        $Message,

        [Parameter(Mandatory = $False,
            HelpMessage = "Logfilename and path.")]
        [string]
        $LogFile
    )

    $Stamp = Get-Date -Format "yyyy\/MM\/dd HH:mm:ss.fff"
    $Line = "[$Stamp] [$Level] $Message"
    If ($LogFile) {
        Add-Content $LogFile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}


# Header
Write-Host ""
Write-Host "$ScriptName"
Write-Host "Version $ScriptVersion"
Write-Host "(c) 2016-2017 Michal Zobec, ZOBEC Consulting. All Rights Reserved."
Write-Host "License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)"
Write-Host "https://creativecommons.org/licenses/by-sa/4.0/"
Write-Host ""
Write-Host "Initializing script"

# Definition of the log file - save method without subdirectory
$LogDate = Get-Date -Format "yyyyMMdd"
$LogFile = $ScriptDir + "\get-systemreport-log-$LogDate.txt"

$LogFileDir = $ScriptDir + "\logs"
if (!(Test-Path $LogFileDir -pathType container)) {
    Write-Verbose "Directory $LogFileDir was not found, creating."
    Write-Log -LogFile $LogFile -Message "  Directory $LogFileDir was not found, creating."
    New-Item $LogFileDir -type directory | Out-Null
    if (!(Test-Path $LogFileDir -pathType container)) {
        Write-Verbose "Directory $LogFileDir still not exist! Exiting."
        Write-Log -LogFile $LogFile -Message "  Directory $LogFileDir still not exist! Exiting."
        exit
    }
}

# Redefinition of the log file with LogFileDir
$LogFile = $LogFileDir + "\get-systemreport-log-$LogDate.txt"

$CfgFilePath = $ScriptDir + "\config\$ConfigurationFileName"
if (!(Test-Path $CfgFilePath)) {
    Write-Warning "File $ConfigurationFileName is required for run of this script! Exiting."
    Write-Log -LogFile $LogFile -Message "  File $ConfigurationFileName is missing." -Level ERROR
    Write-Log -LogFile $LogFile -Message "  Unexpected exit." -Level ERROR
    exit
}
. $CfgFilePath

# Environment
$StartTime = (Get-Date).AddHours( - $Hours)
$ReportStartDateTime = (Get-Date).AddHours( - $Hours).ToString("dd.MM.yyyy HH:mm:ss")
$ReportActualDateTime = (Get-Date).ToString("dd.MM.yyyy HH:mm:ss")
$ReportDate = Get-Date -Format "yyyyMMdd-HHmmss"
$ShortDate = Get-Date -Format "dd.MM.yyyy"
$DateTime = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
$HostName = (Get-Wmiobject win32_computersystem).__server
$FullDNSName = (Get-WmiObject win32_computersystem).Name + "." + (Get-WmiObject win32_computersystem).Domain
$HtmlFile = $LogFileDir + "\$HostName-$ReportDate.html"
$ExtPsCheckSslFile = $ScriptDir + "\lib\Check-SSL.ps1"
$ExtPsWinPkFile = $ScriptDir + "\lib\ConvertTo-ProductKey.ps1"
$EmailSubject = "System Report $HostName $ShortDate"
$Spacer = "<br />"
$HtmlBody = @()
$EventLogProps = @("TimeCreated", "RecordId", "ProviderName", "LevelDisplayName", "ID", "Message")
$ServicesProps = @("DisplayName", "Name", "StartType", "Status")
$WmiOs = Get-WmiObject Win32_OperatingSystem -ComputerName $HostName -ErrorAction Stop
$TimeZone = [TimeZoneInfo]::Local.DisplayName

# LogFile header
Write-Log -LogFile $LogFile -Message "--------------"
Write-Log -LogFile $LogFile -Message "$ScriptName"
Write-Log -LogFile $LogFile -Message "Version $ScriptVersion"
Write-Log -LogFile $LogFile -Message "  Initializing script"

# UpTime
$Temptime = ([wmi]'').ConvertToDateTime($WmiOs.LocalDateTime)
$SystemTime = "$($Temptime.ToShortDateString()) $($Temptime.ToShortTimeString())"
$Temptime = ([wmi]'').ConvertToDateTime($WmiOs.LastBootUptime)
$OsLastBoot = "$($Temptime.ToShortDateString()) $($Temptime.ToShortTimeString())"
$UpTime = New-TimeSpan -Start $OsLastBoot -End $SystemTime
$UpTime = "$($UpTime.days) days $($Uptime.hours) hours $($Uptime.minutes) minutes"
$PSVersion = $PSVersionTable.PSVersion.Major


######
# Diagnostic information to log file
Write-Log -LogFile $LogFile -Message "  HostName: $HostName" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  Generated: $DateTime" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  OsLastBoot: $OsLastBoot" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  SystemTime: $SystemTime" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  UpTime: $UpTime" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  Report filename: $HtmlFile" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  Log filename: $LogFile" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  PowerShell version: $PSVersion" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  ExtPsWinPkFile: $ExtPsWinPkFile" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  Send email: $sendmail" -Level DEBUG
Write-Log -LogFile $LogFile -Message "  Used account: $env:USERDOMAIN\$env:USERNAME" -Level DEBUG


######
# Check configuration variables
try {
    Get-Variable WindowsPkInReport, ApplicationCritical, ApplicationError, ApplicationWarning, SystemCritical, SystemError, SystemWarning, Hours, CriticalFreeDiskSpace, SkipEventIDlist, SkipServicesName, SkipTaskName, SendMail -Scope Global -ErrorAction Stop | Out-Null
}
catch [System.Management.Automation.ItemNotFoundException] {
    Write-Warning $_
    Write-Warning "Please check file $CfgFilePath"
    break
}

# Device Role
$DeviceRole = ($WmiOs).Description

Write-Host "Processing $HostName"
Write-Log -LogFile $LogFile -Message "  Processing $HostName"
$HtmlBody += "<p>System report for $HostName from $ReportStartDateTime to $ReportActualDateTime.</p>"
$HtmlBody += $Spacer


######
# ConvertTo ProductKey ConvertTo-ProductKey.ps1
if (!(Test-Path $ExtPsWinPkFile)) {
    Write-Warning "File ConvertTo-ProductKey.ps1 is required for run of this script! Exiting."
    Write-Log -LogFile $LogFile -Message "  File ConvertTo-ProductKey.ps1 is missing." -Level ERROR
    Write-Log -LogFile $LogFile -Message "  Unexpected exit." -Level ERROR
    break
}
. $ExtPsWinPkFile


######
# Operating System Information
Write-Host "Collecting Operating System Information"
Write-Log -LogFile $LogFile -Message "  Collecting Operating System Information"
$SubHead = "<h3>Operating System Information</h3>"
$HtmlBody += $SubHead

if ($WindowsPkInReport -eq "True") {
    try {
        $GetPkKey = get-itemproperty -path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion" -name "DigitalProductId4"
        $WinProductKey = ConvertTo-ProductKey $GetPkKey.DigitalProductId4 -x64
    }
    catch {
        Write-Warning $_.Exception.Message
        $WinProductKey = "An error was encountered. $($_.Exception.Message)"
    }
}
else {
    $WinProductKey = "(This feature is off)"
}

try {
    $osinfo = Get-WmiObject Win32_OperatingSystem -ComputerName $HostName -ErrorAction Stop | 
        Select-Object @{Name = 'Operating System'; Expression = {$_.Caption}},
    @{Name = "Architecture"; Expression = {$_.OSArchitecture}},
    Version,
    @{Name = "Install Date"; Expression = {
            $installdate = [datetime]::ParseExact($_.InstallDate.SubString(0, 8), "yyyyMMdd", $null);
            $installdate.ToShortDateString()
        }
    },
    @{Name = "Last Boot"; Expression = {$OsLastBoot}},
    @{Name = "UpTime"; Expression = {$UpTime}},
    @{Name = "Time Zone"; Expression = {$TimeZone}},    
    @{Name = "Device Role (Computer Description)"; Expression = {$DeviceRole}},
    @{Name = "Registered User"; Expression = {$_.RegisteredUser}},
    @{Name = "Registered Organization"; Expression = {$_.Organization}},
    @{Name = "Windows Serial Number"; Expression = {$_.SerialNumber}},
    @{Name = "Product Key"; Expression = {$WinProductKey}}

    $HtmlBody += $osinfo | ConvertTo-Html -Fragment
    $HtmlBody += $Spacer
}
catch {
    Write-Warning $_.Exception.Message
    $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $HtmlBody += $Spacer
}


######
# Stopped Services Information
Write-Host "Collecting Stopped Services Information"
Write-Log -LogFile $LogFile -Message "  Collecting Stopped Services Information"
$SubHead = "<h2>Stopped Services Information</h2>"
$HtmlBody += $SubHead

if ($PSVersionTable.PSVersion.Major -le 2) {
    $HtmlBody += "<p>Unsupported PowerShell version $PSVersion.</p>"
    $HtmlBody += $Spacer
}
if ($PSVersionTable.PSVersion.Major -ge 3) {
    try {
        $StoppedServices = Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Where-Object {$_.Status -eq "stopped"} | Select-Object $ServicesProps
        $StoppedServices = $StoppedServices | Where-Object {$_.Name -notmatch $SkipServicesName}
        
        $HtmlBody += $StoppedServices | ConvertTo-Html -Fragment
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning $_.Exception.Message
        $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}    


######
# Windows Firewall Status
Write-Host "Collecting Windows Firewall Status"
Write-Log -LogFile $LogFile -Message "  Collecting Windows Firewall Status"
$SubHead = "<h2>Windows Firewall Status</h2>"
$HtmlBody += $SubHead

if ($PSVersionTable.PSVersion.Major -le 2) {
    $HtmlBody += "<p>Unsupported PowerShell version $PSVersion.</p>"
    $HtmlBody += $Spacer
}
if ($PSVersionTable.PSVersion.Major -ge 3) {
    try {
        $FirewallStatus = Get-NetFirewallProfile -ErrorAction Stop | 
        Select-Object @{Name = "Firewall Profile Name"; Expression = {$_.Name}},
        Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogIgnored
        

        $HtmlBody += $FirewallStatus | ConvertTo-Html -Fragment
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning $_.Exception.Message
        $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}    


######
# Windows Firewall Status
Write-Host "Collecting AntiVirus Status"
Write-Log -LogFile $LogFile -Message "  Collecting AntiVirus Status"
$SubHead = "<h2>AntiVirus Status</h2>"
$HtmlBody += $SubHead

if ($PSVersionTable.PSVersion.Major -le 2) {
    $HtmlBody += "<p>Unsupported PowerShell version $PSVersion.</p>"
    $HtmlBody += $Spacer
}
if ($PSVersionTable.PSVersion.Major -ge 3) {
    try {
        $AntiVirusProduct = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ComputerName $HostName -ErrorAction Stop

        #Switch to determine the status of antivirus definitions and real-time protection. 
        #Write-Output $AntiVirusProduct.productState
        switch ($AntiVirusProduct.ProductState) { 
            "262144" {$DStatus = "Up to date" ;$RTPStatus = "Disabled"} 
            "262160" {$DStatus = "Out of date" ;$RTPStatus = "Disabled"} 
            "266240" {$DStatus = "Up to date" ;$RTPStatus = "Enabled"} 
            "266256" {$DStatus = "Out of date" ;$RTPStatus = "Enabled"} 
            "393216" {$DStatus = "Up to date" ;$RTPStatus = "Disabled"} 
            "393232" {$DStatus = "Out of date" ;$RTPStatus = "Disabled"} 
            "393488" {$DStatus = "Out of date" ;$RTPStatus = "Disabled"} 
            "397312" {$DStatus = "Up to date" ;$RTPStatus = "Enabled"} 
            "397328" {$DStatus = "Out of date" ;$RTPStatus = "Enabled"} 
            "397584" {$DStatus = "Out of date" ;$RTPStatus = "Enabled"} 
            "397568" {$DStatus = "Up to date"; $RTPStatus = "Enabled"}
            "393472" {$DStatus = "Up to date" ;$RTPStatus = "Disabled"}
        default {$DStatus = "Unknown" ;$RTPStatus = "Unknown"} 
        }
        
        $AntiVirusStatus = New-Object PSObject
        $AntiVirusStatus | Add-Member NoteProperty -Name "Antivirus name" -Value $AntiVirusProduct.DisplayName
        $AntiVirusStatus | Add-Member NoteProperty -Name "Definition status" -Value $DStatus
        $AntiVirusStatus | Add-Member NoteProperty -Name "Real-time protection status" -Value $RTPStatus
        
        $HtmlBody += $AntiVirusStatus | ConvertTo-Html -Fragment
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning $_.Exception.Message
        $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}    


######
# Windows Task Scheduler Failed Tasks
Write-Host "Collecting Windows Task Scheduler Failed Tasks"
Write-Log -LogFile $LogFile -Message "  Collecting Windows Task Scheduler Failed Tasks"
$SubHead = "<h2>Windows Task Scheduler Failed Tasks</h2>"
$Comment = "<p>Following tasks last run failed and maybe needs your attention.</p>"
$HtmlBody += $SubHead
$HtmlBody += $Comment

if ($PSVersionTable.PSVersion.Major -le 2) {
    $HtmlBody += "<p>Unsupported PowerShell version $PSVersion.</p>"
    $HtmlBody += $Spacer
}
if ($PSVersionTable.PSVersion.Major -ge 3) {
    try {
        $FailedTasks = Get-ScheduledTask | Where State -ne "Disabled" | Get-ScheduledTaskInfo | Where LastTaskResult -gt "0" | Select-Object TaskName,TaskPath,LastRunTime,LastTaskResult,NextRunTime,NumberofMissedRuns
        $FailedTasks = $FailedTasks | Where-Object {$_.TaskName -notmatch $SkipTaskName}

        $HtmlBody += $FailedTasks | ConvertTo-Html -Fragment
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning $_.Exception.Message
        $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}    


######
# Network Information
Write-Host "Collecting Network Information"
Write-Log -LogFile $LogFile -Message "  Collecting Network Information"
$SubHead = "<h2>Network Information</h2>"
$HtmlBody += $SubHead
try {
    $HWInfo = Get-WmiObject Win32_ComputerSystem -ComputerName $HostName -ErrorAction Stop |
        Select-Object Name,
    @{Name = "DnsHostName"; Expression = {$FullDNSName}},
    Domain

    $HtmlBody += $HWInfo | ConvertTo-Html -Fragment
    $HtmlBody += $Spacer
}
catch {
    Write-Warning $_.Exception.Message
    $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $HtmlBody += $Spacer
}

$SubHead = "<h2>Device Information</h2>"
$HtmlBody += $SubHead


######
# Hardware Information
Write-Host "Collecting Hardware Information"
Write-Log -LogFile $LogFile -Message "  Collecting Hardware Information"
$SubHead = "<h3>Hardware Information</h3>"
$HtmlBody += $SubHead
try {
    $HWInfo = Get-WmiObject Win32_ComputerSystem -ComputerName $HostName -ErrorAction Stop |
        Select-Object Manufacturer, Model,
    @{Name = "Serial Number"; Expression = {(Get-WmiObject win32_bios).SerialNumber}},
    @{Name = "CPU Name"; Expression = {(Get-WmiObject win32_Processor).Name}},
    @{Name = "Physical Processors"; Expression = {$_.NumberOfProcessors}},
    @{Name = "Physical Cores"; Expression = {(Get-WmiObject win32_Processor).NumberOfCores}},
    @{Name = "All Cores"; Expression = {$_.NumberOfLogicalProcessors}},
    @{Name = "Physical Memory (MB)"; Expression = {
            $tpm = $_.TotalPhysicalMemory / 1MB;
            "{0:F0}" -f $tpm
        }
    }

    $HtmlBody += $HWInfo | ConvertTo-Html -Fragment
    $HtmlBody += $Spacer
}
catch {
    Write-Warning $_.Exception.Message
    $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $HtmlBody += $Spacer
}


######
# Disk Information
Write-Host "Collecting Disk Information"
Write-Log -LogFile $LogFile -Message "  Collecting Disk Information"
$SubHead = "<h3>Disk Information</h3>"
$HtmlBody += $SubHead
try {
    $DiskDriveInfo = Get-WmiObject -Class Win32_DiskDrive -filter "MediaType='Fixed hard disk media' or MediaType='External hard disk media'" -Namespace "root\CIMV2" -ComputerName $HostName -ErrorAction Stop |
        Select-Object Caption, InterfaceType, MediaType, SerialNumber, Name, SCSILogicalUnit, SCSIPort, Partitions,
    @{Label = "Total Size (GB)"; Expression = {[math]::round(($_.Size / 1073741824), 2)}} |
        Sort-Object Name

    $HtmlBody += $DiskDriveInfo | ConvertTo-Html -Fragment
    $HtmlBody += $Spacer
}
catch {
    Write-Warning $_.Exception.Message
    $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $HtmlBody += $Spacer
}


######
# Volume Information
Write-Host "Collecting Volume Information"
Write-Log -LogFile $LogFile -Message "  Collecting Volume Information"
$SubHead = "<h3>Volume Information</h3>"
$HtmlBody += $SubHead
# Identification of the data block in table/html code
$HtmlBody += "<div id=`"volume`">"
try {
    $VolumeInfo = Get-WmiObject -Class Win32_Volume -filter "drivetype = 3" -ComputerName $HostName -ErrorAction Stop | 
        Select-Object Label, Name, SystemVolume,
    @{Expression = {[math]::round(($_.Capacity / 1073741824), 2)}; Label = "Total Size (GB)"},
    @{Expression = {[math]::round(($_.FreeSpace / 1073741824), 2)}; Label = "Free Space (GB)"},
    @{Expression = {[math]::round(((($_.FreeSpace / 1073741824) / ($_.Capacity / 1073741824)) * 100), 0)}; Label = "Free space (%)"} |
        Sort-Object Name

    $HtmlBody += $VolumeInfo | ConvertTo-Html -Fragment
    $HtmlBody += $Spacer
}
catch {
    Write-Warning $_.Exception.Message
    $HtmlBody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $HtmlBody += $Spacer
}
$HtmlBody += "</div>"

$SubHead = "<h2>Eventlogs</h2>"
$HtmlBody += $SubHead


######
# Security events
# StartTime last 14 days?
# Get-WinEvent -FilterHashtable @{logname='security';id=4740}
# filtered id
# 4740 account was locked
# Get-EventLog Security -EntryType FailureAudit
if ($ApplicationWarning -eq "True") {
    try {
        Write-Host "Collecting Security events"
        Write-Log -LogFile $LogFile -Message "  Collecting Security events"
        $SubHead = "<h3>Eventlog Security events</h3>"
        $HtmlBody += $SubHead
        $EventlogSystemErrors = Get-WinEvent -FilterHashtable @{Logname = "Security"; EntryType = "FailureAudit"; StartTime = $StartTime} -ComputerName $HostName -ErrorAction Stop | Select-Object $EventLogProps
        foreach ($SkipEventID in $SkipEventIDlist) {
            $EventlogSystemErrors = $EventlogSystemErrors | Where-Object {$_.Id -notmatch $SkipEventID}
        }
        $HtmlBody += $EventlogSystemErrors | ConvertTo-Html -Fragment
    }
    catch [System.Exception] {
        $HtmlBody += "<p>No events were found that match the specified selection criteria.</p>"
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        $HtmlBody += "<p>An error was encountered: $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}


######
# Application Critical events
if ($ApplicationCritical -eq "True") {
    try {
        Write-Host "Collecting Application Critical events"
        Write-Log -LogFile $LogFile -Message "  Collecting Application Critical events"
        $SubHead = "<h3>Eventlog Application Critical events</h3>"
        $HtmlBody += $SubHead
        $EventlogSystemErrors = Get-WinEvent -FilterHashtable @{Logname = "application"; Level = "1"; StartTime = $StartTime} -ComputerName $HostName -ErrorAction Stop | Select-Object $EventLogProps
        foreach ($SkipEventID in $SkipEventIDlist) {
            $EventlogSystemErrors = $EventlogSystemErrors | Where-Object {$_.Id -notmatch $SkipEventID}
        }
        $HtmlBody += $EventlogSystemErrors | ConvertTo-Html -Fragment
    }
    catch [System.Exception] {
        $HtmlBody += "<p>No events were found that match the specified selection criteria.</p>"
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        $HtmlBody += "<p>An error was encountered: $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}


######
# Application Error events
if ($ApplicationError -eq "True") {
    try {
        Write-Host "Collecting Application Error events"
        Write-Log -LogFile $LogFile -Message "  Collecting Application Error events"
        $SubHead = "<h3>Eventlog Application Error events</h3>"
        $HtmlBody += $SubHead
        $EventlogSystemErrors = Get-WinEvent -FilterHashtable @{Logname = "application"; Level = "2"; StartTime = $StartTime} -ComputerName $HostName -ErrorAction Stop | Select-Object $EventLogProps
        foreach ($SkipEventID in $SkipEventIDlist) {
            $EventlogSystemErrors = $EventlogSystemErrors | Where-Object {$_.Id -notmatch $SkipEventID}
        }
        $HtmlBody += $EventlogSystemErrors | ConvertTo-Html -Fragment
    }
    catch [System.Exception] {
        $HtmlBody += "<p>No events were found that match the specified selection criteria.</p>"
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        $HtmlBody += "<p>An error was encountered: $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}


######
# Application Warning events
if ($ApplicationWarning -eq "True") {
    try {
        Write-Host "Collecting Application Warning events"
        Write-Log -LogFile $LogFile -Message "  Collecting Application Warning events"
        $SubHead = "<h3>Eventlog Application Warning events</h3>"
        $HtmlBody += $SubHead
        $EventlogSystemErrors = Get-WinEvent -FilterHashtable @{Logname = "application"; Level = "3"; StartTime = $StartTime} -ComputerName $HostName -ErrorAction Stop | Select-Object $EventLogProps
        foreach ($SkipEventID in $SkipEventIDlist) {
            $EventlogSystemErrors = $EventlogSystemErrors | Where-Object {$_.Id -notmatch $SkipEventID}
        }
        $HtmlBody += $EventlogSystemErrors | ConvertTo-Html -Fragment
    }
    catch [System.Exception] {
        $HtmlBody += "<p>No events were found that match the specified selection criteria.</p>"
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        $HtmlBody += "<p>An error was encountered: $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}


######
# System Critical events
if ($SystemCritical -eq "True") {
    try {
        Write-Host "Collecting System Critical events"
        Write-Log -LogFile $LogFile -Message "  Collecting System Critical events"
        $SubHead = "<h3>Eventlog System Critical events</h3>"
        $HtmlBody += $SubHead
        $EventlogSystemErrors = Get-WinEvent -FilterHashtable @{Logname = "system"; Level = "1"; StartTime = $StartTime} -ComputerName $HostName -ErrorAction Stop | Select-Object $EventLogProps
        foreach ($SkipEventID in $SkipEventIDlist) {
            $EventlogSystemErrors = $EventlogSystemErrors | Where-Object {$_.Id -notmatch $SkipEventID}
        }
        $HtmlBody += $EventlogSystemErrors | ConvertTo-Html -Fragment
    }
    catch [System.Exception] {
        $HtmlBody += "<p>No events were found that match the specified selection criteria.</p>"
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        $HtmlBody += "<p>An error was encountered: $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}


######
# Application Error events
if ($SystemError -eq "True") {
    try {
        Write-Host "Collecting Application Error events"
        Write-Log -LogFile $LogFile -Message "  Collecting Application Error events"
        $SubHead = "<h3>Eventlog System Error events</h3>"
        $HtmlBody += $SubHead
        $EventlogSystemErrors = Get-WinEvent -FilterHashtable @{Logname = "system"; Level = "2"; StartTime = $StartTime} -ComputerName $HostName -ErrorAction Stop | Select-Object $EventLogProps
        foreach ($SkipEventID in $SkipEventIDlist) {
            $EventlogSystemErrors = $EventlogSystemErrors | Where-Object {$_.Id -notmatch $SkipEventID}
        }
        $HtmlBody += $EventlogSystemErrors | ConvertTo-Html -Fragment
    }
    catch [System.Exception] {
        $HtmlBody += "<p>No events were found that match the specified selection criteria.</p>"
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        $HtmlBody += "<p>An error was encountered: $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}


######
# Application Warning events
if ($SystemWarning -eq "True") {
    try {
        Write-Host "Collecting Application Warning events"
        Write-Log -LogFile $LogFile -Message "  Collecting Application Warning events"
        $SubHead = "<h3>Eventlog System Warning events</h3>"
        $HtmlBody += $SubHead
        $EventlogSystemErrors = Get-WinEvent -FilterHashtable @{Logname = "system"; Level = "3"; StartTime = $StartTime} -ComputerName $HostName -ErrorAction Stop | Select-Object $EventLogProps
        foreach ($SkipEventID in $SkipEventIDlist) {
            $EventlogSystemErrors = $EventlogSystemErrors | Where-Object {$_.Id -notmatch $SkipEventID}
        }
        $HtmlBody += $EventlogSystemErrors | ConvertTo-Html -Fragment
    }
    catch [System.Exception] {
        $HtmlBody += "<p>No events were found that match the specified selection criteria.</p>"
        $HtmlBody += $Spacer
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        $HtmlBody += "<p>An error was encountered: $($_.Exception.Message)</p>"
        $HtmlBody += $Spacer
    }
}


######
# HTML head and styles
$HtmlHead = "<html>
				    <style>
				    BODY{font-family: Verdana; font-size: 8pt; align: left}
				    H1{font-size: 18px;}
				    H2{font-size: 16px;}
				    H3{font-size: 14px;}
				    H4{font-size: 12px;}
				    TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				    TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
				    TD{border: 1px solid black; padding: 5px; }
				    td.pass{background: #7FFF00;}
				    td.warn{background: #FFE600;}
				    td.fail{background: #FF0000; color: #ffffff;}
				    td.info{background: #85D4FF;}
				    </style>
				    <body>
				    <h1>System Report $FullDNSName</h1>
				    <p>Device role (Computer Description): $DeviceRole</p>
				    <p>Generated: $DateTime</p>"

$HtmlTail = "<p>$Spacer"
$HtmlTail += "This report was generated by$Spacer"
$HtmlTail += "$ScriptName$Spacer"
$HtmlTail += "Version $ScriptVersion$Spacer"
$HtmlTail += "
(c) 2016-2017 Michal Zobec, ZOBEC Consulting. All Rights Reserved.$Spacer
web: www.michalzobec.cz, mail: michal@zobec.net$Spacer
License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) https://creativecommons.org/licenses/by-sa/4.0/
$Spacer"
$HtmlTail += "</p><p>"
$HtmlTail += "<h4>DEBUG INFO</h4>"
$HtmlTail += "Report filename: $HtmlFile $Spacer"
$HtmlTail += "Log filename: $LogFile $Spacer"
$HtmlTail += "Generated: $DateTime $Spacer"
$HtmlTail += "<p>For more informations please check <i>log filename</i>.</p>"
$HtmlTail += "</p></body></html>"

$htmlreport = $HtmlHead + $HtmlBody + $htmltail
$htmlreport | Out-File $htmlfile -Encoding Utf8

Function Test-EmailAdress() {
    param (
        [Parameter(HelpMessage = "Enter email adress for validation.")]
        [String]
        $email
    )

    $validateemailadressresult = $null
	
    if ($email -as [System.Net.Mail.MailAddress]) {
        Write-Host "$email is correct email address"
        $validateemailadressresult = "Success"
    }
    else {
        Write-Warning "$email is not correct email address"
        Write-Warning "report was not sended"
        $validateemailadressresult = "Fail"
        break
    }
    
    Write-Host "Mail flow test: $validateemailadressresult"
    return $validateemailadressresult
}


if ($sendmail -eq "True") {
    Write-Log -LogFile $LogFile -Message "  Validating $EmailSender"
    Test-EmailAdress -email $EmailSender
    Write-Log -LogFile $LogFile -Message "  Processing $EmailRecipient"
    Test-EmailAdress -email $EmailRecipient
    if ($EmailRecipientCC -ne "") {
        Write-Log -LogFile $LogFile -Message "  Processing $EmailRecipientCC"
        Test-EmailAdress -email $EmailRecipientCC
    }
    if ($EmailRecipientCC -eq "") {
        $SMTPsettings = @{
            To         = "$EmailRecipient"
            From       = "$EmailSender"
            Subject    = "$EmailSubject"
            SmtpServer = "$EmailRelay"
        }
    }
    else {
        $SMTPsettings = @{
            To         = "$EmailRecipient"
            Cc         = "$EmailRecipientCC"
            From       = "$EmailSender"
            Subject    = "$EmailSubject"
            SmtpServer = "$EmailRelay"
        }
    }
    try {
        Write-Host "Sending email"
        Write-Log -LogFile $LogFile -Message "  Sending email"
        # Definition of type encoding System.Text.utf8encoding
        $Enc = New-Object System.Text.utf8encoding
        Send-MailMessage @SMTPsettings -Body $htmlreport -BodyAsHtml -Encoding $Enc -ErrorAction Stop
    }
    catch {
        Write-Warning "An error was encountered: $_.Exception.Message"
        Write-Log -LogFile $LogFile -Message "  An error was encountered: $_.Exception.Message" -Level ERROR
        break
    }
    
}


Write-Host "Exit"
Write-Log -LogFile $LogFile -Message "  Exit"
