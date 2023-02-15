'''
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Saira Hassan, @saiii_h

https://www.github.com/nccgroup/whalescan

Released under Apache license 2.0, see LICENSE for more information

'''


import json
from lib2to3.pgen2.grammar import line

import command
import os
import docker
import pprint

import requests
import sys
from bs4 import BeautifulSoup
from docker import APIClient
import re

import cve_check
import get_versions

def main(image):
    

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    pp = pprint.PrettyPrinter(indent=4)
    images = client.images.list()

    def checkDockerHistory(image):

        print("\n[#] Checking for unsafe commands in dockerfile...")
        add_used = 0
        iwr_used = 0
        image_history = image.history()
        image = str(image)
        image = re.findall(r"'(.*?)'", image, re.DOTALL)

        # check if ADD command is used in docker history
        for layer in image_history:
            docker_commands = layer.get('CreatedBy')
            if 'ADD' in docker_commands:
                add_used = 1
            if 'Invoke-WebRequest' in docker_commands:
                if docker_commands.find('Invoke-WebRequest') == -1:
                    if 'Get-FileHash' not in docker_commands:
                        iwr_used = 1

            #print(docker_commands)


        if add_used == 1:
            print("Unverified files: Image " + str(image[0]) + " contains ""ADD"" command in docker history, which retrieves and unpacks files from remote URLs. Docker COPY should be used instead.")
        if iwr_used == 1:
            print("Unverified files: Image " + str(image[0]) + " uses ""Invoke-WebRequest"" to download files without any hash verification. ")

    def checkTags(image):

        print("\n[#] Checking tags...")

        #Get all commands used in dockerfile
        image_history = image.history()
        for layer in image_history:
            tag = layer.get('Tags')

            #gets tags being used in container
            if str(tag) != 'None':
                image = str(image)
                image = re.findall(r"'(.*?)'", image, re.DOTALL)
                print("Image " + str(image[0]) + " is using the following tags: " + ', '.join(tag))

    def updateMethod(image):
        print("\n[#] Checking update method...")
        image_history = image.history()
        image = str(image)
        image = re.findall(r"'(.*?)'", image, re.DOTALL)

        # check if ADD command is used in docker history
        for layer in image_history:
            print(layer)
            docker_commands = layer.get('CreatedBy')
            if 'ADD' in docker_commands:
                add_used = 1
            if 'Invoke-WebRequest' in docker_commands:
                if docker_commands.find('Invoke-WebRequest') == -1:
                    if 'Get-FileHash' not in docker_commands:
                        iwr_used = 1





    checkDockerHistory(image)
    checkTags(image)
    #updateMethod(image)





