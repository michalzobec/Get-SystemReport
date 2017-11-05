#Requires -Version 3
#Requires -RunAsAdministrator
<#

.SYNOPSIS
Create Job
Create job in Windows Task Scheduler for script Get System Report.
Script supports run locally.

.DESCRIPTION
Create Job
Create job in Windows Task Scheduler for script Get System Report.

FEATURES
* create new job;

KNOWNPROBLEMS
* (none);

SYSTEMREQUIREMENTS
* Windows Pro, or
* Windows Enterprise, or
* Windows Server
* Windows PowerShell v3+

Developed and tested on 
* Windows 7, Windows Server 2008 R2,
* Windows 10, Windows Server 2016.

.OUTPUTS
.

.EXAMPLE
C:\> get-systemreport.ps1

.LINK
http://www.michalzobec.cz/

.NOTES
Create Job
(c) 2016-2017 Michal Zobec, ZOBEC Consulting. All Rights Reserved.
web: www.michalzobec.cz, mail: obchod@zobec.net
License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) https://creativecommons.org/licenses/by-sa/4.0/

.HISTORY
version 17.08.20.1;
	* init version;
version 17.08.28.1;
	* verified on PSv2, minimal requirements is PSv3;
version 17.09.08.1;
	* added trigger with run of script after Windows start;
	* add support for older systems Windows 7, Windows Server 2008 R2;
version 17.09.18.1;
	* added Requires RunAsAdministrator statement;
version 17.10.18.1;
	* changed settings for used account;

.TODO
	* (none);

#>

$DateTime = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
$Revision = Get-Date -Format "yy.MM.dd-HH.mm"
$Scriptfile = (split-path $myinvocation.mycommand.path) + "\get-systemreport.ps1"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$Scriptfile`""
$Triggers = @()
$Triggers += New-ScheduledTaskTrigger -Daily -At 06:00
$Triggers += New-ScheduledTaskTrigger -AtStartup
# $Principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
# $Principal = New-ScheduledTaskPrincipal -RunLevel Highest -LogonType S4U -UserId $env:USERDOMAIN\$env:USERNAME
$Principal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $env:USERDOMAIN\$env:USERNAME
$TaskName = "Get System Report (inst $Revision)"
$Description = "Get System Report PS daily script`ninstalled $DateTime"
$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($Task -ne $null)
{
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$False
}
Register-ScheduledTask -Action $Action -Principal $Principal -Trigger $Triggers -TaskName $TaskName -Description $Description