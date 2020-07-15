# Whalescan

Vulnerability scanner for windows containers.

## Getting Started


```
git clone 

pip install -r requirements.txt
```

## Overview

Whalescan performs several benchmark checks, as well as checking for CVEs.

* Container checks 

    * Checks if containers are stored under C: drive - this could raise issues if there is a DoS attack, 
    filling up the C: drive and making the host unresponsive
    * Checks if container is running as a process or hyper-v. Hyper-v isolation offers enhanced security of containers
    * Checks if there are any pending updates in the containers, and if so, how to update.
    
    ![Container checks](demo/containercheck.png?raw=true "Title")
    
* Image checks
    * Checks for unsafe commands being used in the dockerfile, for example docker ADD instead of docker COPY. 
    * Checks if hash verification is being performed on any files downloaded.
    * Checks if any vulnerable packages are on the container, and pulls relevant CVE information
    * Checks if .NET version being used is End Of Life
    * Checks if Docker Engine is updated, and if not, gathers a list of CVEs for the version being used
    
    ![CVE check demo](demo/cvedemo.gif)
    
* Checks permissions of docker configuration files 
* Checks if additional devices have been mapped to containers

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details


