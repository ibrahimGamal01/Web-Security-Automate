import subprocess
import json
import re

# Run Sublist3r and retrieve a list of subdomains for the inherited domain
subdomains = subprocess.run(['sublist3r', '-d', 'inheriteddomain.com'], stdout=subprocess.PIPE).stdout.decode('utf-8').split('\n')

# Initialize a list to store the results of the checks
results = []

# Iterate through the list of subdomains and check each one for vulnerabilities
for subdomain in subdomains:
    # Check for vulnerabilities using ZAP
    zap_output = subprocess.run(['zap-cli', '--api-key', '<API_KEY>', '-p', '8080', 'active-scan', subdomain], stdout=subprocess.PIPE).stdout.decode('utf-8')
    zap_results = re.findall(r'alerts":\[(.*?)\]', zap_output)
    if zap_results:
        results.append({'subdomain': subdomain, 'tool': 'ZAP', 'vulnerabilities': zap_results})
    else:
        results.append({'subdomain': subdomain, 'tool': 'ZAP', 'vulnerabilities': 'None detected'})
    
    # Check for vulnerabilities using ffuf
    ffuf_output = subprocess.run(['ffuf', '-w', 'wordlist.txt', '-u', f'http://{subdomain}/FUZZ'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    ffuf_results = re.findall(r'{subdomain}/(.*?)/', ffuf_output)
    if ffuf_results:
        results.append({'subdomain': subdomain, 'tool': 'ffuf', 'vulnerabilities': ffuf_results})
    else:
        results.append({'subdomain': subdomain, 'tool': 'ffuf', 'vulnerabilities': 'None
