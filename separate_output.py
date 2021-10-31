# To run the script:
# Place all the json files from which data is to be extracted and this script in the same folder
# When script is executed the count for all IP's, URL's and hashes is printed which can be compared
# with the count on IBM X-Force

# Steps to build exeutable file:
# 1. If there is indentation problem, open file in IDLE and select Format --> Untabify Region after selecting the entire script.
# 2. Open PowerShell and run the command:
#     pip/3 install colorama
#     pyinstaller.exe --onefile --console --hidden-import colorama IOC_Extraction.py

import csv
import os
from datetime import datetime
from colorama import init, Fore, Style
import json

init(convert=True)

countURL=0
countIP=0
countHash=0

now = datetime.now()
opIP = now.strftime("%d_%m_%Y") + "_IP.csv"
opURL = now.strftime("%d_%m_%Y") + "_URL.csv"
opHash = now.strftime("%d_%m_%Y") + "_HASH.csv"


def outputFileCheck():
	if not os.path.exists(opIP):
		with open(opIP, 'w'):
			print("[+] IP addresses would be stored in: " + opIP)
	else:
		f = open(opIP, 'w')
		f.truncate(0)
		f.close()
		print("[-] " + opIP + " already exisits.")
		print("[+] Contents of " + opIP + " cleared.")
	
	csvHeadIP = ["Collection Name", "IP Address"]
	append_as_row(opIP, csvHeadIP)

	if not os.path.exists(opURL):
		with open(opURL, 'w'):
			print("[+] IP addresses would be stored in: " + opURL)
	else:
		f = open(opURL, 'w')
		f.truncate(0)
		f.close()
		print("[-] " + opURL + " already exisits.")
		print("[+] Contents of " + opURL + " cleared.")
	csvHeadURL = ["Collection Name", "URL"]
	append_as_row(opURL, csvHeadURL)
	
	if not os.path.exists(opHash):
		with open(opHash, 'w'):
			print("[+] IP addresses would be stored in: " + opHash)
	else:
		f = open(opHash, 'w')
		f.truncate(0)
		f.close()
		print("[-] " + opHash + " already exisits.")
		print("[+] Contents of " + opHash + " cleared.")
	csvHeadHash = ["Collection Name", "Hash Value"]
	append_as_row(opHash, csvHeadHash)