######
# custom variables - begin
# Include Windows product key in report
$WindowsPkInReport = "True"
# ApplicationCritical
$ApplicationCritical = "True"
# ApplicationError
$ApplicationError = "True"
# ApplicationWarning
$ApplicationWarning = "True"
# SystemCritical
$SystemCritical = "True"
# ApplicationCritical
$SystemError = "True"
# SystemWarning
$SystemWarning = "True"
# hours for collect of eventlogs
$Hours = "24"
# critical free disk space in GB
$CriticalFreeDiskSpace = "22"
# skip events with event id
# Event ID 400, Message text "Exchange Server, cross-forest Availability service that can fill request for mailbox";
# Event ID 4999, Message text "Exchange Server, Watson report about to be sent to dw20.exe";
$SkipEventIDlist = (400, 4999)
######

######
# mail settings - begin
# send email?
$SendMail = "False"
# sender email
$EmailSender = "sender@domain.ext"
# recipient email
$EmailRecipient = "recipient@domain.ext"
# carbon copy (CC) email
$EmailRecipientCC = "recipient.copy@domain.ext"
# relay mail server
$EmailRelay = "mail.relay.domain.ext"
# mail settings - end
######
