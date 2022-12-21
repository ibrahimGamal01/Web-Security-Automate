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

    # Check for web application firewalls using wafw00f
    wafw00f_output = subprocess.run(['wafw00f', '-v', subdomain], stdout=subprocess.PIPE).stdout.decode('utf-8')
    wafw00f_results = re.findall(r'(WAF detected: .*)', wafw00f_output)
    if wafw00f_results:
        results.append({'subdomain': subdomain, 'tool': 'wafw00f', 'vulnerabilities': wafw00f_results})
    else:
        results.append({'subdomain': subdomain, 'tool': 'wafw00f', 'vulnerabilities': 'None detected'})
    
    # Check for cross-site scripting vulnerabilities using kxss
    kxss_output = subprocess.run(['kxss', '-u', f'http://{subdomain}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    kxss_results = re.findall(r'(XSS vulnerabilities detected: .*)', kxss_output)
    if kxss_results:
        results.append({'subdomain': subdomain, 'tool': 'kxss', 'vulnerabilities': kxss_results})
    else:
        results.append({'subdomain': subdomain, 'tool': 'kxss', 'vulnerabilities': 'None detected'})
     
    # Check for vulnerabilities using IronWASP
    ironwasp_output = subprocess.run(['ironwasp', '-u', f'http://{subdomain}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    ironwasp_results = re.findall(r'(Vulnerability detected: .*)', ironwasp_output)
    if ironwasp_results:
        results.append({'subdomain': subdomain, 'tool': 'IronWASP', 'vulnerabilities': ironwasp_results})
    else:
        results.append({'subdomain': subdomain, 'tool': 'IronWASP', 'vulnerabilities': 'None detected'})
    
    # Check for web application vulnerabilities using Wfuzz
    wfuzz_output = subprocess.run(['wfuzz', '-c', '-z', 'file,wordlist.txt', '-d', f"url={subdomain}/FUZZ"], stdout=subprocess.PIPE).stdout.decode('utf-8')
    wfuzz_results = re.findall(r'(200.*)', wfuzz_output)
    if wfuzz_results:
        results.append({'subdomain': subdomain, 'tool': 'Wfuzz', 'vulnerabilities': wfuzz_results})
    else:
        results.append({'subdomain': subdomain, 'tool': 'Wfuzz', 'vulnerabilities': 'None detected'})
    
    # Check for vulnerabilities using Wapiti
    wapiti_output = subprocess.run(['wapiti', '-u', f'http://{subdomain}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    wapiti_results = re.findall(r'(Vulnerability detected: .*)', wapiti_output)
    if wapiti_results:
        results.append({'subdomain': subdomain, 'tool': 'Wapiti', 'vulnerabilities': wapiti_results})
    else:
        results.append({'subdomain': subdomain, 'tool': 'Wapiti', 'vulnerabilities': 'None detected'})

# Print the results of the checks
print(json.dumps(results, indent=4))                        
