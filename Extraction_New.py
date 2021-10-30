# FROM OLP

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

# Function to extract Threat Name
def extract_threat_name(content):
        t_name=re.search(r'"collectionTitle":"([^"]*)"', content).group(1)
        return t_name

# Function to extract Threat Type
def extract_threat_type(content):
        t_type=re.search(r"Threat Type\\\\n(.*?)\\\\nOverview", content)
        if t_type:
            return t_type.group(1)
        return None

# Function to extact Threat Description
def extract_threat_desc(content):
        t_desc=re.search(r"Summary\\\\n(.*?)\\\\nThreat", content)
        if t_desc:
            return t_desc.group(1)
        return None

# Function to extract Collection ID for generating URL
def extract_coll_id(content):
        c_id=re.search(r'"collectionId":"([^"]*)"', content).group(1)
        return c_id

# Function to extract Related Vulnerabilities
def extract_rel_vuln(content):
        r_vuln=re.findall(r'"external_id":"([^"]*)"', content)
        vulns=""
        counter = 0
        if r_vuln:
                for i in range(len(r_vuln)):
                        vulns = vulns + r_vuln[i] + "\n"
                        counter += 1
                return vulns, counter
        return None, counter

# Function to extract Suspicious IP's
def extract_susp_ip(content):
        s_ip=re.findall("IP address ((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))", content)
        # s_ip=re.findall("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))", content)
        ips =""
        counter = 0
        if s_ip:
                for i in range(len(s_ip)):
                        ips = ips + (s_ip[i][0]) + "\n"
                        counter += 1
                return ips.replace(".", "[.]"), counter
        return None, counter

# Function to extract Suspicious URL's
def extract_susp_url(content):
        s_url=re.findall("URL Report for ([^\"]*)", content)
        urls=""
        counter = 0
        if s_url:
                for i in range(len(s_url)):
                        urls = urls + s_url[i] + "\n"
                        counter += 1
                return urls.replace(".", "[.]").replace("http", "hxxp"), counter
        return None, counter

# Function to extract requried data from json file
def data_extraction(file_name):
        # Opening json file and converting it's content to string format
        file_obj = open(file_name, 'r', encoding="utf8")
        content = file_obj.readlines()
        content = str(content)
        print ("[+] Extracting From", file_name)

        # Capturing Threat Name
        threat_name=extract_threat_name(content)
        print ("[+]THREAT NAME: ", threat_name)

        # Capturing Threat Type
        print ("Threat Type: ", end=" ")
        threat_type=extract_threat_type(content)
        if threat_type is None:
            print ("PLEASE CHECK THE WEBPAGE FOR THIS FIELD!")
        else:
            print (threat_type)

        # Capturing Threat Description
        print ("Threat Description: ", end=" ")
        threat_desc=extract_threat_desc(content)
        if threat_desc is None:
            print ("PLEASE CHECK THE WEBPAGE FOR THIS FIELD!")
        else:
            print (threat_desc)

        # Capturing Related Vulnerabilities and print it's count
        print ("Vulnerabilities: ", end=" ")
        rel_vuln, vuln_count=extract_rel_vuln(content)
        print (vuln_count)

        # Creating Reference Link
        print ("Reference Link: ", end=" ")
        collection_id=extract_coll_id(content)
        ref_url= "https://exchange.xforce.ibmcloud.com/collection/" + threat_name.replace(" ", "-") + "-" + collection_id
        print (ref_url)

        # Capturing Related Suspicious IP's and print it's count
        print ("Suspicious IP's: ", end=" ")
        susp_ip, ip_count=extract_susp_ip(content)
        print (ip_count)

        # Capturing Related Suspicious IP's and print it's count
        print ("Suspicious URL's: ", end=" ")
        susp_url, url_count=extract_susp_url(content)
        print (url_count)

        # Capturing Suspicious Hashes and print it's count
        print ("Suspicious Hashes: ", end=" ")
        susp_hash, hash_count=extract_susp_hash(content)
        print (hash_count)

        # Retreiving Today's Date and appending all the captured data to a row in the CSV file
        now = datetime.now()
        row_content=[now.strftime("%d-%m-%Y"), threat_name, threat_type, threat_desc, rel_vuln, ref_url, susp_ip, susp_url, susp_hash]
        append_as_row(output_file, row_content)
