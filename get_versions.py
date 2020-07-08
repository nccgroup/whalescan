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

def getCurrentDotnetVersion():
    url = 'https://dotnet.microsoft.com/download'
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    # print(soup)

    version = soup.find_all('h2')
    return version[0].text[-3:]
