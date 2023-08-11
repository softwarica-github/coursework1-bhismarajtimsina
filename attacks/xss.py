import requests
from urllib.parse import quote
from tqdm import tqdm
from pystyle import *

def check_xss_vulnerability(url_filename, payload_filename, output_file):
    with open(url_filename, 'r') as url_file:
        urls = list(set(url_file.read().splitlines()))

    with open(payload_filename, 'r') as payload_file:
        payloads = payload_file.read().splitlines()

    vulnerable_urls = set()

    def check_xss(url, payload, method='GET'):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            data = None
            if method == 'POST':
                data = {payload: payload}
                response = requests.post(url, headers=headers, data=data)
            else:
                url_with_payload = f"{url}{quote(payload)}"
                response = requests.get(url_with_payload, headers=headers)

            if payload in response.text:
                vulnerable_urls.add((url, payload, method))
                return True
        except requests.RequestException as e:
            print(f"An error occurred while checking {url}: {str(e)}")
        return False

    total_combinations = len(payloads) * len(urls)
    progress_bar = tqdm(total=total_combinations, desc="Checking XSS Vulnerability")

    for payload in payloads:
        for url in urls:
            if url in vulnerable_urls:
                continue

            # Check XSS for different HTTP methods
            methods = ['GET', 'POST']
            for method in methods:
                vulnerability_found = check_xss(url, payload, method)
                if vulnerability_found:
                    break  # No need to continue checking other methods for this URL

            progress_bar.update(1)

    if progress_bar.n < progress_bar.total:
        progress_bar.update(progress_bar.total - progress_bar.n)
    progress_bar.close()

    if len(vulnerable_urls) == 0:
        print(Colors.red + "[*] No vulnerable URLs found.\n")
    else:
        print(Colors.green + "[+] Vulnerable URLs:")
        with open(output_file, 'w') as f:
            f.write('''Cross Site Scripting:
Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

Mitigation:-
Filter input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input. Encode data on output

Vulnerable URLs:
''')
        with open(output_file, "a") as f:
            for url, payload, method in vulnerable_urls:
                f.write(f"{method} {url} [VULNERABLE] {payload}\n")
                print(f"{method} {url} [VULNERABLE] {payload}")
        print(Colors.green + f'[-] XSS Vulnerable URLs saved to: {output_file}\n')
