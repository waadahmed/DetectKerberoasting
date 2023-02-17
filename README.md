# DetectingKerberoasting
This Powershell script helps in detecting Kerberoasting attack with less false positives in Active Directory.

We will use the script to collect, check and notify if there was any potential kerberoasting attack on the domain. The script will be running on the domain controller machine and will check all the machines logs on the domain. The detection is based on the following elements: 

   * Event ID 4769 (Kerberos TGS was requested) 
   * Ticket Encryption Type RC4 (0x17)
   * Repeated Account Name 
   * Fixed Amount of Time
   * Honeypot Services  
   
   
   
   _________
   
   
  **Requirements:** 
* Create Honeypot services account with SPN using the following command:

***net user sql password P@ssw0rd! /add /domain*** 

* Add SPN to the  Honeypot services account 

***setspn –A sqlserver/CST.LAB***

***sql1 setspn –Q */* | findstr sql***

and then add it to the script **under Set-Variable -name Honeypot_accounts -Value @(**


* You need to run the scrip as admin on the DC server. 

   _________
   
   The script will detect the normal kerbrerasting attack , to do keberoasying attack in your enviroment tou can use any tool such as Rubeus using the following command: 
   

