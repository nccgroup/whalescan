
#The nmap library is used, which allows you to scan network ports 
#and run NSE scripts (Nmap Scripting Engine) to detect vulnerabilities.

#Also the check_password_strength function, which uses zxcvbn to evaluate 
#password strength. The check_container_passwords function then checks for 
#passwords in the container's environment variables and calls 
#check_password_strength for each password found.

import nmap
import requests
from bs4 import BeautifulSoup
import re
from prettytable import PrettyTable
from time import sleep
from tabulate import tabulate
import docker
import json
import pprint
import zxcvbn

pp = pprint.PrettyPrinter(indent=4)

def check_password_strength(password):
    result = zxcvbn.zxcvbn(password)
    score = result['score']
    feedback = result['feedback']

    if score < 3:
        print(f"Password strength: {score}/4 (Weak)")
        print("Suggestions for password improvement:")
        for suggestion in feedback['suggestions']:
            print(f"- {suggestion}")
    else:
        print(f"Password strength: {score}/4 (Strong)")

def main(image):

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    pp = pprint.PrettyPrinter(indent=4)
    images = client.images.list()

    # get list of images
    cli = docker.APIClient(base_url='')
    client = docker.from_env()

    def dotnetCVEs(version):

        # Parse CVEs from advisory page
        url = 'https://github.com/dotnet/announcements/issues?q=is%3Aopen+is%3Aissue+label%3A%22.NET+Core+' + version[0:3] + '%22+label%3ASecurity'
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')

        main_content = soup.find('div', attrs={'class': 'Box mt-3 Box--responsive hx_Box--firstRowRounded0'})
        content = str(main_content.find('div', attrs={'aria-label': 'Issues'}))

        name_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4}')
        #initialise dict of CVE ID and relevant information
        CVEs = dict(dict.fromkeys(name_pattern.findall(content)))

        if CVEs != None:
            print(bcolors.FAIL + "Found following CVEs for .NET version " + version + bcolors.ENDC)

            #get more detail for the CVEs and save it to a dict [CVE: {cve info}]
            for c in CVEs:
                #query nvd advisory for information relating to CVE IS
                url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + c
                response = requests.get(url)
                json_data = json.loads(response.text)

                #parse severity, score and summary, save to dict
                try:
                    severity = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                except:
                    severity = 'Unknown'

                try:
                    riskScore = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                except:
                    riskScore = 'Unknown'

                try:
                    summary = json_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
                except:
                    summary = 'Unknown'

                CVEs[c] = [severity, riskScore, summary]

                #initialise table of CVEs
                t = PrettyTable(['CVE ID', 'Severity', 'Summary'])
                t._max_width = {"Summary": 60}

            # create a row in the table for each CVE
            for c in CVEs:
                severity = str(CVEs[c][0]) + ' (' + str(CVEs[c][1]) + ")"
                summary = str(CVEs[c][2])
                t.add_row([c, severity, summary])

            print(t)
            sleep(2)

    def checkifEOL(versionUsed):

        # check if it is end of life
        EOLversions = []
        url = 'https://github.com/dotnet/core/blob/master/microsoft-support.md'
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')

        main_content = soup.findAll('table')[1]
        tbody = main_content.findAll('tbody')

        #get array of EOL versions
        for tr in tbody:
            tr = tr.findAll("tr")
            # print(tr)
            for each_tr in tr:
                versionString = each_tr.findAll("td")[0].text
                version = versionString[-3:]
                EOLversions.append(version)

        #print warning if current version is EOL
        if versionUsed in EOLversions:
            print("Using end of life .NET version!")

    def test(container):
        print(container.id[:12] + "aaaaaaaaaaaaaaa")

    if(cli.inspect_image(image.id)['Config']['Env'] != None):
        if ('DOTNET_RUNNING_IN_CONTAINER=true' in cli.inspect_image(image.id)['Config']['Env']):

            # Check if it is DOTNET_SDK
            if re.search('DOTNET_SDK_VERSION', str(cli.inspect_image(image.id)['Config']['Env'])):
                # get .net sdk version
                print('\n[#] Dotnet running, checking version...')
                r = re.compile(".*DOTNET_SDK_VERSION.*")
                sdk_version = str(list(filter(r.match, cli.inspect_image(image.id)['Config']['Env'])))
                start = "DOTNET_SDK_VERSION="
                end = "'"
                s = sdk_version
                sdk_version = (s.split(start))[1].split(end)[0][0:3]
                checkifEOL(sdk_version)
                dotnetCVEs(sdk_version)

            # Check if it is DOTNET
            if re.search('DOTNET_VERSION', str(cli.inspect_image(image.id)['Config']['Env'])):
                # get .net version being used
                print('\n[#] Dotnet running, checking version...')
                r = re.compile(".*DOTNET_VERSION.*")
                version = str(list(filter(r.match, cli.inspect_image(image.id)['Config']['Env'])))
                start = "DOTNET_VERSION="
                end = "'"
                s = version
                version = (s.split(start))[1].split(end)[0][0:3]
                checkifEOL(version)
                dotnetCVEs(version)


    def check_network_security(container):
        print(f"\n[#] Checking network security for container {container.id[:12]}")

        # Get container IP address
        container_info = container.attrs
        network_settings = container_info['NetworkSettings']
        ip_address = network_settings['IPAddress']

        # Scan container's open ports
        nm = nmap.PortScanner()
        scan_results = nm.scan(ip_address, arguments='-p-')  # Scan all ports

        # Print open ports
        open_ports = []
        for port, info in scan_results['scan'][ip_address]['tcp'].items():
            if info['state'] == 'open':
                open_ports.append(port)

        if open_ports:
            print(f"Open ports: {', '.join(map(str, open_ports))}")
        else:
            print("No open ports found")

        # Perform vulnerability scanning on open ports
        vulnerability_scan_results = []
        for port in open_ports:
            vulnerabilities = vulnerability_scan(port)
            vulnerability_scan_results.append([port, vulnerabilities])

        # Print vulnerability scan results
        print("\nVulnerability scan results:")
        table_headers = ['Port', 'Vulnerabilities']
        print(tabulate(vulnerability_scan_results, headers=table_headers))

    def vulnerability_scan(port):
        # Perform vulnerability scanning on the specified port
        # You can use Nmap scripts, OpenVAS, or other vulnerability scanning tools

        # Example: Using Nmap NSE scripts
        nm = nmap.PortScanner()
        script_results = nm.scan('localhost', port, arguments='--script vuln')

        # Collect vulnerability scan results
        vulnerabilities = []
        if script_results['scaninfo']:
            for script, result in script_results['scaninfo'][0]['services'][port]['script'].items():
                vulnerabilities.append(f"{script}: {result}")
        
        return vulnerabilities

    # Create Docker client
    client = docker.from_env()

    # Check network security for containers
    for container in client.containers.list():
        check_network_security(container)
except Exception as e:
    print("An error occurred:", str(e))
