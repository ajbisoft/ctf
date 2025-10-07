# Active Reconnaissance

## Host discovery

### Host discovery via ARP Scan

Scan hosts in local subnet:

#### Use arp-scan

`arp-scan -l`

`arp-scan -l -I eth0`

#### Use nmap

`nmap -sn -PR <targets>`

### Host discovery via ICMP scan

#### ICMP Ping scan (ICMP Type8/0):

`nmap -sn -PE <targets>`

#### ICMP Timestamp (ICMP Type 13/14):

`nmap -sn -PP <targets>`

#### ICMP Address Mask (ICMP Type 17/18):

`nmap -sn -PM <targets>`

### Host discovery via TCP/UDP

#### TCP SYN ping (<ports> optional; port 80 by default):

`nmap -sn -PS<ports> <targets>`

#### TCP ACK ping (<ports> optional; port 80 by default, needs root priv):

`nmap -sn -PA<ports> <targets>`

#### UDP ping

`nmap -sn -PU <targets>`

#### masscan

To use masscan as host discovery we limit ports with `-p`:

`masscan -p<port> <targets>`

### Host discovery via Reverse-DNS Lookup

Query DNS server even for offline hosts:

`nmap -sn -R <targets>`

## Port scan

### TCP SYN scan

#### Regular scans

- Scan 100 most common ports in random order:

  `nmap -sS -F <target>`

- Scan 1000 most common ports in random order:

  `nmap -sS <target>`

- Scan all ports in random order:

  `nmap -sS -p- <target>`

- Scan 100 most common ports (-F) in paranoid mode (-T0):

  `namp -sS -F -T0 <target>`

#### Advanced scans

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

### UDP scan

Scan 100 most common ports in random order:

`nmap -sU -F <target>`

## Service/OS enumeration

### Service detection

Full connect port scan with version detection. You can control the intensity with --version-intensity LEVEL where the level ranges between 0, the lightest, and 9, the most complete. -sV --version-light has an intensity of 2, while -sV --version-all has an intensity of 9. 

`nmap -sV --version-light <target>`

### OS detection

`nmap -sS -O <target>`

## Vulnerability detection

### Nmap custom scripts

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

### Output handling

- Normal - on screen, output:

  `nmap -sS -oN <target>`

- Gepable - one line for Up/Down, one line for ports report:

  `nmap -sS -oG <target>`

- XML - XML format:

  `nmap -sS -oX <target>`

- Script Kiddie special 31337 mode, just for laughs:
  
  `nmap -sS -oS <target>`

### Nessus

**Nessus** is a scanner that helps identify vulnerabilities, misconfigurations, and compliance issues. It is used to scan networks for known vulnerabilities and generate detailed reports for remediation.
Source: https://www.tenable.com/

### OpenVAS

OpenVAS is a highly capable and powerful vulnerability testing solution.

#### Installation

Installing OpenVAS is very straightforward. Run the apt install and then run the configure script.

```
root@kali:~# apt-get install openvas
root@kali:~# openvas-setup
/var/lib/openvas/private/CA created
/var/lib/openvas/CA created

[i] This script synchronizes an NVT collection with the 'OpenVAS NVT Feed'.
[i] Online information about this feed: 'https://www.openvas.org/openvas-nvt-feed
...
sent 1052 bytes received 64342138 bytes 99231.26 bytes/sec
total size is 64342138 speedup is 1.00
[i] Initializing scap database
[i] Updating CPEs
[i] Updating /var/lib/openvas/scap-data/nvdcve-2.0-2002.xml
[i] Updating /var/lib/openvas/scap-data/nvdcve-2.0-2003.xml
...
Write out database with 1 new entries
Data Base Updated
Restarting Greenbone Security Assistant: gsad.
User created with password '* password that looks like uuid *'.
```

#### Accessing the OpenVAS Web Interface

The OpenVAS Web Interface (gsad) runs on TCP port 9392. However depending on your installation it could also be listening on TCP 443. After installation this can be confirmed by checking the listening ports on your system.

```
root@localhost:/# netstat -alnp | grep LISTEN

Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      3692/redis-server 1
tcp        0      0 0.0.0.0:9391            0.0.0.0:*               LISTEN      13806/openvassd: Wa
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      3656/sshd
tcp6       0      0 :::9390                 :::*                    LISTEN      13804/openvasmd
tcp6       0      0 :::443                  :::*                    LISTEN      28020/gsad
```
#### OpenVAS NVT Updates

The key command for updating NVT's on the system is openvas-nvt-sync. Ensure the full process below is followed. However, as without the rebuilding of the NVT cache /var/cache/openvas/, the new updated checks will not be used by the scanner.

`root@localhost:~/# openvas-nvt-sync`

After syncing the latest NVT's, it is necessary to have the OpenVAS manager update its NVT cache. This is done with the following:
`openvasmd --update` if the manager is running
or
`openvasmd --rebuild` with the manager stopped. This second option is much faster.

```
root@localhost:~/# ps -ef | grep openvas
** get the pid **
root@localhost:~/# kill $pid_of_openvassd
root@localhost:~/# kill $pid_of_openvasmd
root@localhost:~/# openvasmd --rebuild
root@localhost:~/# openvasmd
root@localhost:~/# openvassd
root@localhost:~/# ps -ef | grep openvas
root     13804     1  7 Nov10 ?        05:56:12 openvasmd
root     13806     1  0 Nov10 ?        00:02:12 openvassd: Waiting for incoming connections
```

With the above process output we can see that the update has been successful. The Scanner and Manager are ready to start scanning.

#### More info:

https://hackertarget.com/openvas-tutorial-tips/
