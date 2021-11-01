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

def append_as_row(file, content):
	with open(file, 'a+', newline="") as write_job:
		write_job = csv.writer(write_job)
		write_job.writerow(content)

def addIP(ip, title):
	global countIP
	ip = ip.replace(".", "[.]").replace("'","")
	row_content = [title, ip]
	append_as_row(opIP, row_content)
	countIP+=1
	
def addURL(url, title):
	global countURL
	url = url.replace(".", "[.]").replace("http", "hxxp").replace("'","")
	row_content = [title, url]
	append_as_row(opURL, row_content)
	countURL+=1

def addHash(hash, title):
	global countHash
	hash = hash.replace("'","")
	row_content = [title, hash]
	append_as_row(opHash, row_content)
	countHash+=1

def iocExtraction(file):
	f = open(file, encoding="utf-8",)
	data = json.load(f)
	collectionTitle = data["custom_objects"][0]["collectionTitle"]
	for i in data["objects"]:
		if (i["type"] == "indicator") and ("pattern" in i):
			identifier = i["pattern"].split(" ")[1]
			if identifier == "ipv4-addr:value":
				addIP(i["pattern"].split(" ")[3], collectionTitle)
			elif identifier == "file:hashes.MD5":
				addHash(i["pattern"].split(" ")[3], collectionTitle)
			elif identifier == "url:value":
				addURL(i["pattern"].split(" ")[3], collectionTitle)
		elif i["type"] == "report":
			print("Collection Name: " + i["name"])
		# else:
		# 	print ("Some wierd shit at:" + str(count))

def listFiles(dir):
	return (f for f in os.listdir(dir) if f.endswith('.json'))

if __name__ == '__main__':
	directory = '.'
	outputFileCheck()
	files = listFiles(directory)
	color_count = 0
	for f in files:
		# print (f)
		try:
			if (color_count % 2 == 0):
				print(Fore.GREEN, Style.BRIGHT)
			else:
				print (Fore.MAGENTA, Style.BRIGHT)
			iocExtraction(f)
			print ("URL Count: " + str(countURL))
			print ("IP Count: " + str(countIP))
			print ("Hash Count: " + str(countHash))
			countHash = countIP = countURL = 0
			print (Style.RESET_ALL)
		except  Exception as e:
			print (Fore.RED)
			print ("There is some issue with the file: " + f)
			print (e)
			print ("Contact Nishant Tayade with the file that caused the issue and the error displayed.")
			print (Style.RESET_ALL)
		color_count += 1
	
	# print ("URL Count: " + str(countURL))
	# print ("IP Count: " + str(countIP))
	# print ("Hash Count: " + str(countHash))

	input("Enter any key to exit!")