import json
import command
import os
import docker
import pprint
import checks


client = docker.from_env()
APIClient = docker.APIClient(base_url='')

for container in client.containers.list():
     containerID = container.id[:12]
     print("Running checks for container "  + containerID)
     checks.main(containerID)
