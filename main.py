import json
from itertools import count

import command
import os
import docker
import pprint
import checks


client = docker.from_env()
APIClient = docker.APIClient(base_url='')

count = 0
for container in client.containers.list():
     count+=1
     containerID = container.id[:12]
     print("\n################## Running checks for container " + containerID + " (" + str(count) + "/" + str(len(client.containers.list())) + ") ##################")
     checks.main(containerID)
