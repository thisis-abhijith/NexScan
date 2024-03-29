import requests
import time
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import concurrent.futures

# Define patterns for sensitive data
SENSITIVE_DATA_PATTERNS = {
    'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Password': r'(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}',
    'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',
    'Social Security Number': r'\b\d{3}-\d{2}-\d{4}\b',
    'Phone Number': r'\b(?:\d[ -]*?){9,}\b',
    # Add more patterns for other types of sensitive data
}

def analyze_content(html_content):
    sensitive_data = {}
    for pattern_name, pattern in SENSITIVE_DATA_PATTERNS.items():
        matches = re.findall(pattern, html_content)
        if matches:
            sensitive_data[pattern_name] = matches
    return sensitive_data

def scan_website(url):
    try:
        start_time = time.time()
        response = requests.get(url)
        end_time = time.time()
        
        if response.status_code == 200:
            print(f"[+] {url} - {response.status_code}")
            html_content = response.text
            extract_links(html_content, url)
            sensitive_data = analyze_content(html_content)
            if sensitive_data:
                print("Sensitive data found:")
                for data_type, data in sensitive_data.items():
                    print(f"- {data_type}: {data}")
            
            # Perform cookie security analysis
            analyze_cookies(response.cookies)
            
            # Perform header analysis
            analyze_headers(response.headers)
            
            # Perform CSP analysis
            analyze_csp(response.headers.get("Content-Security-Policy"))
            
            # Perform XSS testing
            test_xss(url)
            
            # Perform SQL Injection testing
            test_sql_injection(url)
            
            # Performance Analysis
            response_time = end_time - start_time
            print(f"Response time: {response_time:.2f} seconds")
            
            # You can add more analysis here based on the response content
        elif response.status_code == 404:
            print(f"[-] {url} - {response.status_code} (Not Found)")
        else:
            print(f"[!] {url} - {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[x] {url} - Error: {e}")

def extract_links(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        absolute_url = urljoin(base_url, href)
        print(f"Found link: {absolute_url}")

def test_parameterized_urls(base_url, parameters):
    for param in parameters:
        test_url = f"{base_url}?{param}=test"
        print(f"Testing URL: {test_url}")
        scan_website(test_url)

def enumerate_subdomains(domain):
    subdomains = set()
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            subdomains.add(rdata)
    except Exception as e:
        print(f"Error enumerating subdomains for {domain}: {e}")
    return subdomains

def analyze_cookies(cookies):
    print("Cookie security analysis:")
    for cookie in cookies:
        print(f"- Name: {cookie.name}, Value: {cookie.value}")
        print(f"  HttpOnly: {cookie.get('httponly', False)}")
        print(f"  Secure: {cookie.secure}")
        print(f"  SameSite: {cookie.get('samesite', None)}")
        print(f"  Expiry: {cookie.expires}")
        # You can add more checks here as needed

def analyze_headers(headers):
    print("Header analysis:")
    for header, value in headers.items():
        print(f"- {header}: {value}")

def analyze_csp(csp_header):
    print("Content Security Policy (CSP) analysis:")
    if csp_header:
        print(f"- Content-Security-Policy: {csp_header}")
        # Implement analysis of CSP directives here
    else:
        print("- Content-Security-Policy header not found")

def test_xss(url):
    print("Cross-Site Scripting (XSS) testing:")
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg onload=alert('XSS')>"]
    for payload in payloads:
        try:
            response = requests.post(url, data={"input_field": payload}, timeout=5)
            if response.status_code == 200 and payload in response.text:
                print(f"[+] XSS Vulnerability Found with payload: {payload}")
            else:
                print(f"[-] Payload {payload} not reflected")
        except requests.exceptions.RequestException as e:
            print(f"[x] Error while testing payload {payload}: {e}")

def test_sql_injection(url):
    print("SQL Injection testing:")
    payloads = ["' OR 1=1 --", "'; DROP TABLE users; --"]
    for payload in payloads:
        try:
            response = requests.post(url, data={"input_field": payload}, timeout=5)
            if response.status_code == 200 and "error" in response.text:
                print(f"[+] SQL Injection Vulnerability Found with payload: {payload}")
            else:
                print(f"[-] Payload {payload} not reflected")
        except requests.exceptions.RequestException as e:
            print(f"[x] Error while testing payload {payload}: {e}")

def main():
    target_url = input("Enter the target URL: ")
    parameters = input("Enter the parameters (comma-separated, e.g., param1,param2): ").split(",")
    test_parameterized_urls(target_url, parameters)

    # Enumerate subdomains
    domain = target_url.split("//")[-1].split("/")[0]
    subdomains = enumerate_subdomains(domain)
    print("Subdomains found:")
    for subdomain in subdomains:
        print(subdomain)

if __name__ == "__main__":
    main()
    