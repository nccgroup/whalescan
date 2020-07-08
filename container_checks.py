import json
import command
import os
import docker
import pprint
import sys
from docker import APIClient

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

def main(containerID):

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    cli = docker.APIClient(base_url='')

    # Check whether container can acquire new privileges
    def checkNewPrivileges(containerID):
        print("\n[#] Checking if container can gain new privileges...")

        host_config = APIClient.inspect_container(containerID)['HostConfig']
        #pp.pprint(host_config)

        sec_op_value = host_config.get("SecurityOpt")
        if sec_op_value == None:
            print(bcolors.WARNING + "   Privilege escalation: Security options not set - processes are able to gain additional privileges" + bcolors.ENDC)

    #check whether docker services are mapped to any sensitive ports
    def checkDockerPortMappings(containerID):
        print("\n[#] Checking port mappings for container... ")

        cli = docker.APIClient(base_url='')
        print(containerID)

        port_mappings = cli.port(containerID, 80)
        if port_mappings != None:
            for p in port_mappings:
                if((p['HostIp'] == '0.0.0.0') & ([p['HostPort'] == '2375'])):
                    print("Root access: Docker daemon is listening on ")


    #check logical drives storing containers
    def checkContainerStorage(containerID):
        print("\n[#] Checking container storage... ")

        container_info = client.info()
        logical_drive = container_info.get('DockerRootDir')[0:3]
        if(logical_drive == "C:\\"):
            print(bcolors.WARNING + "   Potential DoS: Under attack, the C: drive could fill up, causing containers and the host itself to become unresponsive" + bcolors.ENDC)

    #def healthCheckVerification(containerID):
    #TODO


    checkNewPrivileges(containerID)
    checkContainerStorage(containerID)
    #healthCheckVerification(containerID)