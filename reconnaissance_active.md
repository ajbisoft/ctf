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

### Custom scripts / vulnerability detection

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
