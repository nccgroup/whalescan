import json
import command
import os
import docker
import pprint
import sys
from docker import APIClient
from packaging import version
from bs4 import BeautifulSoup
from selenium import webdriver
import pandas as pd
import requests

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

def main():

    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    cli = docker.APIClient(base_url='')

    #Get version of docker client
    docker_version = client.version()
    current_version = str(docker_version.get('Version'))

    platform_name = (docker_version.get('Platform')).get('Name')

    #if docker engine is running, compare with latest version from docker engine releases
    if 'Engine' in platform_name:
        url = 'https://docs.docker.com/engine/release-notes/'
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')

        #get latest version
        versions = soup.find_all('h2')
        latest_version = versions[0].text
        if version.parse(current_version) < version.parse(latest_version):
            print(bcolors.WARNING + "\n  Outdated version of Docker: Update Docker Engine to get latest security patches." + bcolors.ENDC)



