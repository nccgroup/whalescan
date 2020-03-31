import docker
import container_checks
import config_file_checks

client = docker.from_env()
APIClient = docker.APIClient(base_url='')

#Running checks for containers
count = 0
for container in client.containers.list():
     count+=1
     containerID = container.id[:12]
     print("\n################## Running checks for container " + containerID + " (" + str(count) + "/" + str(len(client.containers.list())) + ") ##################")
     container_checks.main(containerID)

#Checking configuration files for vulnerabilties
print("\n################## Checking config files ################## ")
config_file_checks.main()