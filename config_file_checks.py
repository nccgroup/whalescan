import os
import json
from os import stat
from time import sleep
from numpy import loadtxt
import win32security
import os
import tempfile
import codecs
import win32api
import subprocess
import csv
import sys
import pprint
import pandas as pd

def main():
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

    def checkDockerDaemonJsonFile():
        print("\n[#] Checking IP:port docker daemon is listening on...")

        #if file exists, read docker daemon config
        if os.path.isfile('C:\\ProgramData\\docker\\config\\daemon.json'):
            daemon_config_file = open('C:\\ProgramData\\docker\\config\\daemon.json')
            daemon_config = daemon_config_file.read()

            loaded_json = json.loads(daemon_config)
            for x in loaded_json:
                if (str(loaded_json[x]) == str(['tcp://0.0.0.0:2375'])):
                    print(bcolors.WARNING + "   Root access: Docker daemon can be publicly accessed, root access to host possible" + bcolors.ENDC)
        #file does not exist
        else:
            print(bcolors.WARNING + "     Daemon.json file not found" + bcolors.ENDC)

    def checkFilePermissions():
        #get list of all def files in directory
        def_files = []
        for root, dirs, files in os.walk('C:\\Windows\\System32\\containers'):
            for file in files:
                if file.endswith(".def"):
                    def_files.append(os.path.join(root, file))

        #Check the owner of each file
        for file in def_files:
            print("\n[#] Checking file ownership for " + file + "...")
            f = win32security.GetFileSecurity(file, win32security.OWNER_SECURITY_INFORMATION)
            (username, domain, sid_name_use) = win32security.LookupAccountSid(None, f.GetSecurityDescriptorOwner())

            if username != 'Administrator':
                print(bcolors.WARNING + "   File " + file + " is not owned by Administrator" + bcolors.ENDC)

            #Check who has write permissions using powershell get-acl function, then export to csv
            print("\n[#] Checking file permissions for " + file + "...")
            sleep(3)
            dir = subprocess.Popen('powershell.exe (get-acl ' + file + ').access | Select IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags,access | Sort-Object IdentityReference |  Export-Csv permissions.csv -NoTypeInformation')
            f = open("permissions.csv", "r")

            #Permissions that users other than admin should not have
            disallowed_permissions = ['FullControl','Modify','Write','WriteAttributes','WriteData','WriteExtendedAttributes']

            #Check whether any non-admin users have any permissions they shouldn't have
            dangerous_permissions = 0
            with open('permissions.csv', mode='r') as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    if("Administrator" not in row["IdentityReference"]):
                        if(row["FileSystemRights"] in disallowed_permissions):
                            print(bcolors.WARNING + row["IdentityReference"] + " has " + row["FileSystemRights"] + " rights on " + file + bcolors.ENDC)
                            dangerous_permissions = 1

                #if there are any users with dangerous permissions over the .def file
                if dangerous_permissions == 1:
                    print(bcolors.WARNING + "Only Administrators should be able to modify .def files! " + bcolors.ENDC)



    checkDockerDaemonJsonFile()
    checkFilePermissions()