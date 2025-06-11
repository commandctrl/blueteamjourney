<#
This script utilizes Outlook to send an email to a list of users based on UserName, MachineName, ProcessName from a csv file. This script only works on Windows OS due to -com dependencies
#>

function SendNotification
{
$outlook = New-Object -comObject  Outlook.Application
$mail = $outlook.CreateItem(0)
$subject = " "
$mail.importance = 2
$mail.To = $ToAddress
$mail.Body = $Body
$mail.Subject = $subject
$mail.Send()
}

#IMPORT EMAILS FROM .CSV FILE
$users = Import-Csv "C:\Users\<user>\Desktop\UserList.csv"

foreach ($user in $users)
{
$ToAddress = $user.UserName 
$MachineName = $user.MachineName 
$ProcessName = $user.ProcessName
   
     
$Body = " \\$MachineName : 

$ProcessName 

  
Action Required:

1.	The system \\$MachineName 


Write-Host "Sending notification to $ToAddress" -ForegroundColor Yellow 
SendNotification
}




    
