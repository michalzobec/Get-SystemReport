#Requires -Version 2
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
* Windows Server 2012,
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
version 17.10.17.1;
	* changed used account to SYSTEM;

.TODO
	* (none);
	
#>

$DateTime = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
$Revision = Get-Date -Format "yy.MM.dd-HH.mm"
$Scriptfile = (split-path $myinvocation.mycommand.path) + "\get-systemreport.ps1"
$TaskName = "Get System Report (inst $Revision)"
if ($Task -ne $null)
{
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$False
}
# write-host "schtasks /Create /SC daily /TN $TaskName /ST 6:00 /TR "powershell.exe -ExecutionPolicy Bypass -File `"$Scriptfile`"" /RU $env:USERDOMAIN\$env:USERNAME"
schtasks /Create /SC daily /TN "$TaskName" /ST 06:00 /TR "powershell.exe -ExecutionPolicy Bypass -File `"$Scriptfile`"" /RU $env:USERDOMAIN\$env:USERNAME
