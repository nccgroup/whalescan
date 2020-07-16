import json
import re
import urllib
from urllib.request import urlopen
import nltk
import requests
from bs4 import BeautifulSoup

import cve_check
import command
import os
import docker
import pprint
import sys
import subprocess
from docker import APIClient

pp = pprint.PrettyPrinter(indent=4)

def main(container):
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

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    cli = docker.APIClient(base_url='')

    # Check whether container can acquire new privileges
    def checkNewPrivileges(container):
        print("\n[#] Checking if container can gain new privileges...")

        host_config = APIClient.inspect_container(container.id)['HostConfig']
        #pp.pprint(host_config)

        sec_op_value = host_config.get("SecurityOpt")
        if sec_op_value == None:
            print(bcolors.WARNING + "   Privilege escalation: Security options not set - processes are able to gain additional privileges" + bcolors.ENDC)

    #check whether docker services are mapped to any sensitive ports
    def checkDockerPortMappings(container):

        cli = docker.APIClient(base_url='')

        port_mappings = cli.port(container.id, 80)
        if port_mappings != None:
            for p in port_mappings:
                if((p['HostIp'] == '0.0.0.0') & ([p['HostPort'] == '2375'])):
                    print(bcolors.WARNING + "Docker daemon is listening on " + p['HostPort'] + bcolors.ENDC)


    #check logical drives storing containers
    def checkContainerStorage(container):
        print("\n[#] Checking container storage... ")

        container_info = client.info()
        logical_drive = container_info.get('DockerRootDir')[0:3]
        if(logical_drive == "C:\\"):
            print(bcolors.WARNING + "   Potential DoS: Under attack, the C: drive could fill up, causing containers and the host itself to become unresponsive" + bcolors.ENDC)

    def checkIsolation(container):

        string = 'docker inspect --format={{.HostConfig.Isolation}} ' + container.id[:12]
        result = subprocess.getoutput(string)
        if result == 'process':
            print(bcolors.WARNING + "\n   Container " + container.id[:12] + ' running as process' + bcolors.ENDC)

    def checkPendingUpdates(container):
        print("\n[#] Checking if there are any pending updates... ")

        pending_updates = []

        #copy update scanning script to container
        copy = 'docker cp update-scan.ps1 ' + container.id + ':\\update-scan.ps1'
        subprocess.getoutput(copy)

        #run script
        run = 'docker exec ' + container.id + ' powershell.exe ".\\update-scan.ps1"'
        subprocess.getoutput(run)

        #copy result to host for analysis
        copy = 'docker cp ' + container.id + ':\\result.txt ./result.txt'
        subprocess.getoutput(copy)

        #regex to identify pending updates
        update_pattern = re.compile(r'[(]KB[0-9]{7}[)]')

        #converting file to readable format
        fread = open('result.txt', 'rb').read()
        mytext = fread.decode('utf-16')
        mytext = mytext.encode('ascii', 'ignore')

        #write decoded result to new file
        fwrite = open('result2.txt', 'wb')
        fwrite.write(mytext)
        fwrite.close()

        #search file for pending updates
        for i, line in enumerate(open('result2.txt')):
            for match in re.finditer(update_pattern, line):
                if match not in pending_updates:
                    update = match.group().replace('(', '')
                    update = update.replace(')', '')
                    pending_updates.append(update)

        os.remove("result.txt")
        os.remove("result2.txt")

        #if there are pending updates available, print warning and search for related CVEs
        if pending_updates:
            print(bcolors.WARNING + "\n   Following updates are pending in container " + container.id[:12] + ": " + ', '.join(pending_updates) + bcolors.ENDC)
            print(bcolors.WARNING + "\n   To update, run following commands in the container: " + bcolors.ENDC)
            print(bcolors.WARNING + "   $ci = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession" + \
                                            "\n   Invoke-CimMethod -InputObject $ci -MethodName ApplyApplicableUpdates" + \
                                            "\n   Restart-Computer; exit" + bcolors.ENDC)
            #print(bcolors.WARNING + "\n   " + bcolors.ENDC)
            #print(bcolors.WARNING + "\n   " + bcolors.ENDC)



    checkContainerStorage(container)
    checkDockerPortMappings(container)
    checkIsolation(container)
    checkPendingUpdates(container)
