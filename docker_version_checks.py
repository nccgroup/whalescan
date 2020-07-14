import json
import command
import os
import docker
import pprint
import re
import prettytable
import sys
import os.path
import cve_check
from os import path
from docker import APIClient
from packaging import version
from bs4 import BeautifulSoup
from selenium import webdriver
import pandas as pd
import requests

pp = pprint.PrettyPrinter(indent=4)

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

def main():

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    cli = docker.APIClient(base_url='')

    def checkForOutdatedDockerVersion():
        # Get version of docker client
        docker_version = client.version()
        current_version = str(docker_version.get('Version'))

        platform_name = (docker_version.get('Platform')).get('Name')

        # if docker engine is running, compare with latest version from docker engine releases
        if 'Engine' in platform_name:
            url = 'https://docs.docker.com/engine/release-notes/'
            page = requests.get(url)
            soup = BeautifulSoup(page.content, 'html.parser')

            # get latest version
            versions = soup.find_all('h2')
            latest_version = versions[0].text

            #if version being used is out of date, print warning and check for CVEs
            if version.parse(current_version) < version.parse(latest_version):
                print(bcolors.WARNING + "\nOutdated version of Docker: Update Docker Engine to get latest security patches." + bcolors.ENDC)

                # get release data from docker release page
                url = 'https://docs.docker.com/engine/release-notes/'
                page = requests.get(url)
                soup = BeautifulSoup(page.content, 'html.parser')

                main_content = soup.find('main', attrs={'class': 'col-content content'})
                main_content = str(main_content.find('section', attrs={'class': 'section'}))

                #get CVE information for newer releases only
                sep = current_version
                release_info = main_content.split(sep, 1)[0]

                #save release info to txt file so we can process it
                f = open("releaseinfo.txt", "w")
                f.write(release_info)

                #regex to find CVEs
                cve_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4,5}')

                # Search for CVEs, and save to dict
                CVEs = dict(dict.fromkeys(cve_pattern.findall(release_info)))

                if CVEs != None:
                    t = prettytable.PrettyTable(['CVE ID', 'Severity', 'Summary'])

                    print(bcolors.WARNING + "Found following CVEs for docker engine" + bcolors.ENDC)

                    # get more detail for the CVEs and save it to a dict [CVE: {cve info}]
                    for c in CVEs:
                        # query nvd advisory for information relating to CVE
                        url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + c
                        response = requests.get(url)
                        json_data = json.loads(response.text)


                        # parse severity, score and summary, save to dict
                        severity = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        riskScore = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                        summary = json_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']

                        CVEs[c] = [severity, riskScore, summary]

                        # initialise table of CVEs
                        t = prettytable.PrettyTable(['CVE ID', 'Severity', 'Summary'])
                        t._max_width = {"Summary": 60}

                    for c in CVEs:
                        severity = str(CVEs[c][0]) + ' (' + str(CVEs[c][1]) + ")"
                        summary = str(CVEs[c][2])
                        t.add_row([c, severity, summary])
                    print(t)

    checkForOutdatedDockerVersion()
