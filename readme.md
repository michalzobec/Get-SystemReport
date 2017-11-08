# Get System Report Readme
(c) 2016-2017 Michal Zobec, ZOBEC Consulting. All Rights Reserved.  
web: www.michalzobec.cz, mail: michal@zobec.net  
License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)  
https://creativecommons.org/licenses/by-sa/4.0/

# HISTORY
Release notes can find in file changelog.md.

# FEATURES
- integrated basic system report: Hardware Information, Windows Information, Network Information;
- Windows product key (in Windows Information Section) is now possibly not include to report;
- Windows Information: uptime, last boot time;
- collect of windows eventlog from defined time (from 24 hours back to actual time);
- collect of windows eventlog from selected logs: Application, System;
- collect of windows eventlog of the selected level: Critical, Error, Warning;
- collect of disk drives connected to device with ISCSI/SAN LUN ID;
- collect of disk volumes connected to device;
- collect of defined websited and check of expiration of SSL certificate;
- write all collected information to HTML report in filename format <HOSTNAME>-<DATE>-<TIME>.html;
- send of HTML report by email; you can use CC; all email adress are validated;
- switch (true/false) for check of expiration of SSL certificate;
- support for local and remote run of script;
- check remote device before run of main part of script;
- report still saved to same path as script;
- support for logging to file with format get-systemreport-<DATE>.txt;
- script runs only locally;
- support script create-job.ps1 for creation of job in windows task scheduler;

# QUICK START
- check and change settings in custom variables;
- test run with or without sending of mail;
- "install" as job in Windows Task Scheduler via create-job.ps1 suport script;

# KNOWN PROBLEMS
- (none);

# SYSTEM REQUIREMENTS
- Windows Pro, or
- Windows Enterprise, or
- Windows Server,
- with Windows PowerShell v2+

## Developed and tested on 
- Clients: Windows 7, Windows 10,
- Servers: Windows Server 2008 R2, Windows Server 2016,
- Languages: English, Czech, Russian.

# OUTPUTS
HTML table with selected level of events in filename format <HOSTNAME>-<DATE>-<TIME>.html.

# EXAMPLE
C:\> get-systemreport.ps1

# THANKS
- Detection of AntiVirus #1 https://www.404techsupport.com/2015/04/27/powershell-script-detect-antivirus-product-and-status/
- Detection of AntiVirus #2 http://neophob.com/2010/03/wmi-query-windows-securitycenter2/