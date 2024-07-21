import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

url = input("Input url: ")

sql_payloads = list()

with open('SQLINJECTION.txt','r') as file:
    for line in file:
        line = line.strip()
        sql_payloads.append(line)



def get_forms(url):
    try:
        res = requests.get(url,timeout=10)
        res.raise_for_status()
        soup = BeautifulSoup(res.content,"lxml")
        return soup.find_all('form')
    except requests.RequestException as e:
        print(f"[-] Error forms from {url}: {e}")
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


scan_sql_injection(url)
# form = get_forms(url)

# get_form_details(form)
