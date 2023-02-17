#  Script Name: Kerberoasting Detector
#  Description: This script helps in detecting Kerberoasting attack with less false positives
#

Set-Variable -Name EventAgeDays -Value 5     # taking events for the latest 7 days
Set-Variable -Name LogName -Value "Security"  # Checking security logs
Set-Variable -Name InstanceId -Value 4769  # To find specific security Event ID
Set-Variable -Name Message -Value "*0x17*"  # Specific word in Event message field
Set-Variable -name Honeypot_accounts -Value  @("sql", "dbadmin", "mssql") # Fill this with your honeypot accounts

$now = get-date
$startdate = $now.adddays(-$EventAgeDays)


Write-Host -ForegroundColor yellow [-] Processing $LogName logs
$sl = Get-EventLog -LogName $LogName -InstanceId $InstanceId -After $startdate -Message $Message


$sl_sorted = $sl | Sort-Object TimeGenerated  #sort by time

# Display filtered and sorted results of important info regarding Event ID 4769 with RC4 encryption - printing 
if ($sl_sorted -ne $null)
{
    Write-Host -ForegroundColor yellow [-] Here is the result of $LogName Event ID $InstanceId with RC4 encryption
    $sl_sorted_all = $sl_sorted | select TimeGenerated, @{ n='AccountName'; e={ ($_.message -replace '\n', ' ') -replace '.*?account name:\t+([^\s]+).*', '$1' } }, @{ n='ServiceName'; e={ ($_.message -replace '\n', ' ') -replace '.*Service Name:\t+([^\s]+).*', '$1' } }
    $sl_sorted_all | Format-Table -Wrap
}

# Start analysing if the account name is repeated multiple times and having the same TimeGenerated
Write-Host -ForegroundColor yellow [-] Analysing results ..`n`n
$sl_sorted_account_time = $sl_sorted | select TimeGenerated, @{ n='AccountName'; e={ ($_.message -replace '\n', ' ') -replace '.*?account name:\t+([^\s]+).*', '$1' } }
$sl_sorted_account_time_unique = $sl_sorted_account_time | Get-Unique -AsString


foreach ($entry in $sl_sorted_account_time_unique)
{
    if (($sl_sorted_account_time -match $entry).Count -gt 2)
    {
        Write-Host -ForegroundColor Yellow [+] Same account name repeated multiple times within very short amount of time:
        $entry | Format-Table -Wrap
        
        # Start checking if the Honeypot service accounts got hit or not to confirm the attack
        $suspected_accounts = $sl_sorted | select @{ n='ServiceName'; e={ ($_.message -replace '\n', ' ') -replace '.*Service Name:\t+([^\s]+).*', '$1' } }
        
        foreach ($account in $Honeypot_accounts)
        {
            if ($suspected_accounts -match $account)
            {
                $result1 = $result1 + 1
            }else{
                $result2 = $result2 + 1
            }
        }
        if ($result1 -ge 3)
        {
            Write-Host -ForegroundColor Yellow [+] There is hit on the following Honeypote accounts`n
            foreach($account in $Honeypot_accounts){if ($suspected_accounts -match $account) {$account}}
            Write-Host -ForegroundColor red [+] Warning: Potential Kerberoasting attack
            Write-Host -ForegroundColor white `n.`n.`n.`n.`n
            $voice = New-Object -ComObject Sapi.spvoice

                    # Set the speed - positive numbers are faster, negative numbers, slower
            $voice.rate = 0

                  # Say something
            $voice.speak("Attention please, Potential Kerberoasting attack!")
            $wshell = New-Object -ComObject Wscript.Shell

            $wshell.Popup("Potential Kerberoasting attack",0,"Done",0x0)
        }else{
            Write-Host -ForegroundColor yellow [+] Something suspecious! Please conduct further investigation
        }
    }else{
        Write-Host -ForegroundColor green [+] Everything is OK about this account:
        $entry | Format-Table -Wrap
       # $resource = Get-EventLog "Windows PowerShell"  -InstanceId $InstanceId -After $startdate -Message "rubeus" | Format-Table -GroupBy EventID
    }
}

Write-Host -ForegroundColor green [-] Done!