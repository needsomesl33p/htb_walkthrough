## Trick
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


