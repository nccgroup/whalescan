import docker
import container_checks
import config_file_checks
import docker_history_checks

client = docker.from_env()
APIClient = docker.APIClient(base_url='')

#Running checks for containers
count = 0

for container in client.containers.list():
     count+=1
     containerID = container.id[:12]
     print("\n################## Running checks for container " + containerID + " (" + str(count) + "/" + str(len(client.containers.list())) + ") ##################")
     container_checks.main(containerID)

#Running checks on docker history
print("\n################## Checking docker history ################## ")
docker_history_checks.main()

#Checking configuration files for vulnerabilities
print("\n################## Checking config files ################## ")
config_file_checks.main()

