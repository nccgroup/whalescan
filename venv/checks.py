import json
import command
import os
import docker
import pprint
import checks
import sys

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

    # Check whether container can acquire new privileges
    def checkNewPrivileges(containerID):
        client = docker.from_env()
        APIClient = docker.APIClient(base_url='')

        for container in client.containers.list():
            print(container.id)
            host_config = APIClient.inspect_container(container.id)['HostConfig']
            pp.pprint(host_config)

            sec_op_value = host_config.get("SecurityOpt")
            print(sec_op_value)
            if sec_op_value == None:
                print(bcolors.WARNING + "Potential privilege escalation: Security options not set - processes are able to gain additional privileges" + bcolors.ENDC)



    checkNewPrivileges(containerID)
