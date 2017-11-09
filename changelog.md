# Get System Report Release History
(c) 2016-2017 Michal Zobec, ZOBEC Consulting. All Rights Reserved.  
web: www.michalzobec.cz, mail: michal@zobec.net  
License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)  
https://creativecommons.org/licenses/by-sa/4.0/

# DOCUMENTATION
Documentation you can find in file [ReadMe.md](https://github.com/michalzobec/PowerShell/blob/master/Get-SystemReport/readme.md).

# Release History

## version 17.07.27.1
- init version;

## version 17.07.27.2
- todo list created;

## version 17.07.27.3
- columns are filtered;
- report file name writed in format <HOSTNAME>-<DATE>-<TIME>.html;
- feature list in script description;

## version 17.07.27.4
- better code logic - included information to event block if output data does not exist (try & catch);
- better code logic - included information about code exception or another bug (try & catch);
- extended event level from Critical, Error to Critical, Error, Warning;
- added configuration value $sendmail for turn on for sending of email;
- solved problem with email sending;

## version 17.07.27.5
- added volume list with full disk size and free space size;

## version 17.07.28.1
- added support for mail CC (carbon copy);
- added validation for entered email addresses in custom values;

## version 17.08.01.1
- added eventlog id (eventid) to windows eventlog table;
- added option for turn on/off application/system events with levels critical/error/warning;
- added custom ignore list for Windows EventLog Event id;
- added hidding of hidden/service partitions in list of volumes;
- code refactoring, variables optimization and minor changes;

## version 17.08.07.1;
- renamed script to "Get System Report";
- added support for check of expiration of SSL certificate;

## version 17.08.12.1;
- added support for list of disks with ISCSI/SAN LUN ID;
- added sorting by name in tables for Disks and Volumes;

## version 17.08.13.1;
- fixed minor bugs;
- minor improvments in get-systemreport.cmd script;

## version 17.08.15.1;
- added SCSIPort, InterfaceType column for list of disks;

## version 17.08.15.2;
- added switch (true/false) for check of expiration of SSL certificate;
- new default settings of script - warning level off, check of ssl off;

## version 17.08.17.1;
- hardcoded filtering of unwanted events and partitions;
- support for local and remote run of script;

## version 17.08.21.1;
- added "installation" script for simple creation of job in windows task scheduler - create-job.cmd;
- report still saved to same path as script;
- added information on screen about path of the report;
- disk partitions filtering removed;

## version 17.08.28.1;
- email subject changed from "Daily Eventlog Report $ShortDate $HostName" to "System Report $HostName $ShortDate";
- added support for logging to file with format get-systemreport-<DATE>.txt;
- fixed problems with custom ignore list for Windows EventLog Event id

## version 17.08.28.2;
- code optimalisation for PowerShell v2;

## version 17.09.08.1;
- script now support local run only, remote run support was removed;
- more detailed information in log file;
- more detailed information in text output for manual run;
- integrated basic system report: Hardware Information, Windows Information, Network Information;
- Windows product key (in Windows Information Section) is now possibly not include to report;
- Windows Information: uptime, last boot time;
- custom variables are now in two section for custom settings and email settings;
- code refactoring, reorganization of parts of code, minor changes;

## version 17.09.08.2;
- fixed problem with loading of external libraries;
- extended logging in log file;
- extended DEBUG level logging in log file;
- extended debug information in report file;

## version 17.09.09.1;
- added Windows Computer Description for definition of device role in Report;
- extended DEBUG level logging in log file;
- extended debug information in report file;

## version 17.09.17.1;
- added time zone to Windows Information section;
- reduced DEBUG Info in Report;

## version 17.09.17.2;
- code refactoring, minor changes;
- added new section Quick Start;

## version 17.09.17.3;
- code refactoring, renamed function with unapproved verb from Validate-EmailAdress to Test-EmailAdress;

## version 17.09.17.4;
- code refactoring, added StrictMode;

## version 17.09.18.1
- improved output information;
- improved logging;
- code refactoring, detection of required script files;
- code refactoring, cleaned some parts of code;
- code refactoring, minor changes;

## version 17.09.19.1
- size will shown in GB with two decimal digits;
- physical and logical disks now filtered for "Fixed hard disk media" and "External hard disk media";
- added column free disk space in percents to Volume Information section;
- list stopped services with automatic run after start of Windows;

## version 17.10.02.1
- changed of file name format of the logfile to get-systemreport-log-<DATE>.txt;
- external libraries (ConvertTo-ProductKey, Check-SSL) was moved to subdirectory .\lib\;
- all custom variables was moved to external configuration file to subdirectory .\config\;
- HTML report will be now saved to subdirectory .\logs\;
- log file will be now saved to subdirectory .\logs\;
- example configuration file get-systemreport-config-example.ps1;

## version 17.10.03.1
- renamed configuration value SkipCheckSSL to CheckSSL;

## version 17.10.17.1
- removed CheckSSL feature;

## version 17.10.18.1
- code refactoring, better part of code for sending of email, error message to log file;
- added DEBUG information about used account to log file;

## version 17.11.05.1 (Public version on GitHub)
- code refactoring, check if exist configuration variables;
- code refactoring, checked PowerShell version for check of stopped services due incopatibility with PS 2.0;
- code refactoring, cleaned some parts of code;
- header content from PS script was moved to separate files readme.md and changelog.md;

## version 17.11.08.1 (Public version on GitHub)
- added new section Windows Firewall Status;
- added new section AntiVirus Status;
- added new section Windows Task Scheduler Failed Tasks;
- fixed bug in Stopped Services section; bad PowerShell version detection;
- fixed bug in log file; bad PowerShell version detection;
- code refactoring, minor changes;
- small updates in files readme.md and changelog.md;

## version 17.11.09.1 (Public version on GitHub)
- fixed bug in public release of script to configuration file;
- added information about used configuration file to script output;
- added information about used configuration file to log file;
- added two example reports to /examples/ folder; more information about example reports you can find in [ReadMe.md](https://github.com/michalzobec/PowerShell/blob/master/Get-SystemReport/readme.md);
- updated/extended example configuration file;
- documentation update in files readme.md and changelog.md;

# TODO
- added Security Windows Eventlog (failed only);
- fix problem with detection of Domain & WorkGroup;
- fixed format for date and time;
- red cell for uptime if uptime is not longer than 3 days;
- add check of all required variables, if exists and content of variables (text, numbers, etc);
- list of failed jobs in Windows Task Scheduler;
- integrate create-job.ps1/create-job-old.ps1 scripts as function;
- disk free space warning under defined size;
- empty values "" replaced by text label "(none)";
- check ssl output integration to html report (list of certificates, date of expiration);
- check and report of state of installed certificates on device;
- validation of run of sending of the email (try&catch);
- highlight selected events, like Exchange components errors;
- dynamic generation of content - just enter list of required levels;
- external configuration file in JSON;
