import concurrent.futures
import requests
from bs4 import BeautifulSoup
import csv
import json
import subprocess

# take a domain as input
domain = input("Enter a domain to perform the tests on: ")

# get the subdomains using sublist3r
subdomains = subprocess.run(['sublist3r', '-d', domain], stdout=subprocess.PIPE).stdout.decode('utf-8').split('\n')

results = []

def check_vulnerabilities(subdomain):
    try:
        # Check for vulnerabilities using ZAP
        zap_response = requests.get(f'http://zap-cli:8080/JSON/core/view/alerts/', params={'baseurl':subdomain})
        zap_results = json.loads(zap_response.text)
        if zap_results:
            results.append({'subdomain': subdomain, 'tool': 'ZAP', 'vulnerabilities': zap_results})
        else:
            results.append({'subdomain': subdomain, 'tool': 'ZAP', 'vulnerabilities': 'None detected'})

        # Check for vulnerabilities using ffuf
        ffuf_response = requests.get(f'http://ffuf:8000/', params={'wordlist':'wordlist.txt', 'target':subdomain})
        ffuf_results = BeautifulSoup(ffuf_response.text, 'html.parser').find_all("a")
        if ffuf_results:
            results.append({'subdomain': subdomain, 'tool': 'ffuf', 'vulnerabilities': ffuf_results})
        else:
            results.append({'subdomain': subdomain, 'tool': 'ffuf', 'vulnerabilities': 'None detected'})

        # Check for web application firewalls using wafw00f
        wafw00f_response = requests.get(f'http://wafw00f:5000/', params={'target':subdomain})
        wafw00f_results = BeautifulSoup(wafw00f_response.text, 'html.parser').find("p")
        if wafw00f_results:
            results.append({'subdomain': subdomain, 'tool': 'wafw00f', 'vulnerabilities': wafw00f_results})
        else:
            results.append({'subdomain': subdomain, 'tool': 'Wapiti', 'vulnerabilities': 'None detected'})
    except Exception as e:
        print(f'Error: {e}')
    

# Use concurrent.futures to run the vulnerability checks in parallel
with concurrent.futures.ThreadPoolExecutor() as executor:
    # Define a list to store the futures
    futures = []
    for subdomain in subdomains:
    # Use the submit method to add the vulnerability check function to the thread pool
        futures.append(executor.submit(check_vulnerabilities, subdomain))

# Use the as_completed method to iterate through the completed futures
for future in concurrent.futures.as_completed(futures):
    # Get the result of the future and append it to the results list
    result = future.result()
    if result:
        results.append(result)

with open('vulnerability_scan_results.csv', 'w', newline='') as csvfile:
    fieldnames = ['subdomain', 'tool', 'vulnerabilities']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for result in results:
        writer.writerow(result)
    print(f'Vulnerability scan results for {domain} have been written to vulnerability_scan_results.csv')


##############################################
############### Another Method ############### 


# import subprocess
# import json
# import re

# # Run Sublist3r and retrieve a list of subdomains for the inherited domain
# subdomains = subprocess.run(['sublist3r', '-d', 'inheriteddomain.com'], stdout=subprocess.PIPE).stdout.decode('utf-8').split('\n')

# # Initialize a list to store the results of the checks
# results = []

# # Iterate through the list of subdomains and check each one for vulnerabilities
# for subdomain in subdomains:
#     # Check for vulnerabilities using ZAP
#     zap_output = subprocess.run(['zap-cli', '--api-key', '<API_KEY>', '-p', '8080', 'active-scan', subdomain], stdout=subprocess.PIPE).stdout.decode('utf-8')
#     zap_results = re.findall(r'alerts":\[(.*?)\]', zap_output)
#     if zap_results:
#         results.append({'subdomain': subdomain, 'tool': 'ZAP', 'vulnerabilities': zap_results})
#     else:
#         results.append({'subdomain': subdomain, 'tool': 'ZAP', 'vulnerabilities': 'None detected'})
    
#     # Check for vulnerabilities using ffuf
#     ffuf_output = subprocess.run(['ffuf', '-w', 'wordlist.txt', '-u', f'http://{subdomain}/FUZZ'], stdout=subprocess.PIPE).stdout.decode('utf-8')
#     ffuf_results = re.findall(r'{subdomain}/(.*?)/', ffuf_output)
#     if ffuf_results:
#         results.append({'subdomain': subdomain, 'tool': 'ffuf', 'vulnerabilities': ffuf_results})
#     else:
#         results.append({'subdomain': subdomain, 'tool': 'ffuf', 'vulnerabilities': 'None detected'})

#     # Check for web application firewalls using wafw00f
#     wafw00f_output = subprocess.run(['wafw00f', '-v', subdomain], stdout=subprocess.PIPE).stdout.decode('utf-8')
#     wafw00f_results = re.findall(r'(WAF detected: .*)', wafw00f_output)
#     if wafw00f_results:
#         results.append({'subdomain': subdomain, 'tool': 'wafw00f', 'vulnerabilities': wafw00f_results})
#     else:
#         results.append({'subdomain': subdomain, 'tool': 'wafw00f', 'vulnerabilities': '
    
#     # Check for cross-site scripting vulnerabilities using kxss
#     kxss_output = subprocess.run(['kxss', '-u', f'http://{subdomain}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
#     kxss_results = re.findall(r'(XSS vulnerabilities detected: .*)', kxss_output)
#     if kxss_results:
#         results.append({'subdomain': subdomain, 'tool': 'kxss', 'vulnerabilities': kxss_results})
#     else:
#         results.append({'subdomain': subdomain, 'tool': 'kxss', 'vulnerabilities': 'None detected'})
     
#     # Check for vulnerabilities using IronWASP
#     ironwasp_output = subprocess.run(['ironwasp', '-u', f'http://{subdomain}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
#     ironwasp_results = re.findall(r'(Vulnerability detected: .*)', ironwasp_output)
#     if ironwasp_results:
#         results.append({'subdomain': subdomain, 'tool': 'IronWASP', 'vulnerabilities': ironwasp_results})
#     else:
#         results.append({'subdomain': subdomain, 'tool': 'IronWASP', 'vulnerabilities': 'None detected'})
    
#     # Check for web application vulnerabilities using Wfuzz
#     wfuzz_output = subprocess.run(['wfuzz', '-c', '-z', 'file,wordlist.txt', '-d', f"url={subdomain}/FUZZ"], stdout=subprocess.PIPE).stdout.decode('utf-8')
#     wfuzz_results = re.findall(r'(200.*)', wfuzz_output)
#     if wfuzz_results:
#         results.append({'subdomain': subdomain, 'tool': 'Wfuzz', 'vulnerabilities': wfuzz_results})
#     else:
#         results.append({'subdomain': subdomain, 'tool': 'Wfuzz', 'vulnerabilities': 'None detected'})
    
#     # Check for vulnerabilities using Wapiti
#     wapiti_output = subprocess.run(['wapiti', '-u', f'http://{subdomain}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
#     wapiti_results = re.findall(r'(Vulnerability detected: .*)', wapiti_output)
#     if wapiti_results:
#         results.append({'subdomain': subdomain, 'tool': 'Wapiti', 'vulnerabilities': wapiti_results})
#     else:
#         results.append({'subdomain': subdomain, 'tool': 'Wapiti', 'vulnerabilities': 'None detected'})

# # Print the results of the checks
# print(json.dumps(results, indent=4))   
