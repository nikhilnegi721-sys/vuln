
import socket

print("=" * 45)
print("       VULNERABILITY SCANNER")
print("=" * 45)

# Only scan your own computer
target = "127.0.0.1"

print("\nTarget:", target)
print("\nStarting Port Scan...\n")

# Common ports for practice
ports = [21, 22, 80, 443, 3306, 8080]

for port in ports:

    scanner = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    scanner.settimeout(0.5)

    result = scanner.connect_ex((target, port))

    if result == 0:
        print(f"[+] Port {port}: OPEN")
    else:
        print(f"[-] Port {port}: CLOSED")

    scanner.close()

print("\nScan Completed!")
print("=" * 45)

import requests

print("\nSECURITY HEADER CHECKER")
print("=" * 45)

url = input("Enter authorized website URL: ").strip()

if not url.startswith(("http://", "https://")):
    url = "https://" + url

try:
    response = requests.get(url, timeout=10)

    headers = response.headers

    security_headers = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    print("\nWebsite:", url)
    print("HTTP Status:", response.status_code)
    print("\nSecurity Header Results:\n")

    for header in security_headers:
        if header in headers:
            print("[+] PRESENT:", header)
        else:
            print("[-] MISSING:", header)

except requests.exceptions.RequestException as error:
    print("\nUnable to connect:", error)

# SOFTWARE VERSION CHECKER

print("\nSOFTWARE VERSION CHECKER")
print("=" * 45)

version_url = input("Enter authorized website URL: ").strip()

if not version_url.startswith(("http://", "https://")):
    version_url = "https://" + version_url

try:
    version_response = requests.get(
        version_url,
        timeout=10
    )

    print("\nWebsite:", version_url)

    server = version_response.headers.get("Server")
    powered_by = version_response.headers.get("X-Powered-By")

    print("\nSoftware Information:")

    if server:
        print("[+] Server Software:", server)
    else:
        print("[-] Server Version: Not Disclosed")

    if powered_by:
        print("[+] Technology:", powered_by)
    else:
        print("[-] Technology: Not Disclosed")

    if not server and not powered_by:
        print("\nNo software version information disclosed.")

except requests.exceptions.RequestException as error:
    print("\nConnection Error:", error)

