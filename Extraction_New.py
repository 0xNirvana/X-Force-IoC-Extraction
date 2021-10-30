# FROM OLP
#
# To run the script:
# Place all the json files from which data is to be extracted and this script in the same folder
# When script is executed the count for all IP's, URL's and hashes is printed which can be compared
# with the count on IBM X-Force

# Steps to build exeutable file:
# 1. If there is indentation problem, open file in IDLE and select Format --> Untabify Region after selecting the entire script.
# 2. Open PowerShell and run the command:
#     pip/3 install colorama
#     pyinstaller.exe --onefile --console --hidden-import colorama IOC_Extraction.py

import sys
import re
import os
import csv
from datetime import datetime
import time
from colorama import init, Fore, Style

ipv4_address = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

init(convert=True)
# output_file declared as variable in case if it's name needs to be changed in future
output_file = "./output.csv"
# Function to check if output_file exists and clear it's content
# If file does not exist, then a new output_file is created
# else the data of exisiting CSV file is cleared

def output_check():
        if not os.path.exists(output_file):
                with open(output_file, 'w'):
                        print ("[+] Output File Created: ", output_file)
                pass
        else:
                f = open(output_file, 'w')
                f.truncate(0)
                f.close()
                print ("[+] Cleared content of: ", output_file)

# Function to detect all the json files in the directory
def list_files(directory):
        return (f for f in os.listdir(directory) if f.endswith('.json'))

# Function to add content to next row in output file
def append_as_row(file_name, content):
        with open (file_name, 'a+', newline='') as write_obj:
                write_job = csv.writer(write_obj)
                write_job.writerow(content)

# Function to extract Threat Name.
def extract_threat_name(content):
        t_name=re.search(r'"collectionTitle":"([^"]*)"', content).group(1)
        return t_name

# Function to extract Threat Type.
def extract_threat_type(content):
        t_type=re.search(r"Threat Type\\\\n(.*?)\\\\nOverview", content)
        if t_type:
            return t_type.group(1)
        return None
