import requests
import sys
from bs4 import BeautifulSoup
from docker import APIClient
import re
from prettytable import PrettyTable
import ares
from ares import CVESearch
import pprint
import tabulate
import json
from tabulate import tabulate

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    CGREENBG = '\33[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

pp = pprint.PrettyPrinter(indent=4)

def dotnetCVEs(image, version):

    imagestr = str(image)
    imagestr = re.findall(r"'(.*?)'", imagestr, re.DOTALL)
    print("\n################## Checking image " + str(imagestr[0]) + " for vulnerabilities ##################")

    # check .net version for CVEs
    url = 'https://github.com/dotnet/announcements/issues?q=is%3Aopen+is%3Aissue+label%3A%22.NET+Core+' + version[0:3] + '%22+label%3ASecurity'
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    # print(soup)

    main_content = soup.find('div', attrs={'class': 'Box mt-3 Box--responsive hx_Box--firstRowRounded0'})
    # get latest version
    content = str(main_content.find('div', attrs={'aria-label': 'Issues'}))

    name_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4}')

    #create dict of CVE ID and relevant information
    CVEs = dict(dict.fromkeys(name_pattern.findall(content)))

    if CVEs != None:
        print(bcolors.WARNING + "Found following CVEs for .net version " + version + bcolors.ENDC)

        #get more detail for the CVEs and save it to a dict [CVE: {cve info}
        for c in CVEs:
            url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + c
            response = requests.get(url)
            json_data = json.loads(response.text)

            severity = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            riskScore = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
            summary = json_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']

            CVEs[c] = [severity, riskScore, summary]

    t = PrettyTable(['CVE ID', 'Severity', 'Summary'])
    t._max_width = {"Summary": 60}

    pp.pprint(CVEs)
    # create a row in the table for each CVE
    for c in CVEs:
        severity = str(CVEs[c][0]) + ' (' + str(CVEs[c][1]) + ")"
        summary = str(CVEs[c][2])
        t.add_row([c, severity, summary])

    print(t)



