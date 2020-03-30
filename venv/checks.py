import json
import command
import os
import docker
import pprint
import checks
import sys
from docker import APIClient

pp = pprint.PrettyPrinter(indent=4)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def main(containerID):

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')

    # Check whether container can acquire new privileges
    def checkNewPrivileges(containerID):
        host_config = APIClient.inspect_container(containerID)['HostConfig']
        #pp.pprint(host_config)

        sec_op_value = host_config.get("SecurityOpt")
        print(sec_op_value)
        if sec_op_value == None:
            print(bcolors.WARNING + "Privilege escalation: Security options not set - processes are able to gain additional privileges" + bcolors.ENDC)

    def checkPortMapping(containerID):
        cli = docker.APIClient(base_url='')
        print(containerID)
        print(cli.port(containerID, 80))

    checkPortMapping(containerID)
    checkNewPrivileges(containerID)
