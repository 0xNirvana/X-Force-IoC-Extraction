# To run the script:
# Place all the json files from which data is to be extracted and this script in the same folder
# When script is executed the count for all IP's, URL's and hashes is printed which can be compared 
# with the count on IBM X-Force

# Some issues
# 1. Unable to extract Threat Type and Threat Description
# 2. As Reference URL is not in the json file, it needs to be entered manually
 
import sys
import re
import os
import csv
from datetime import datetime

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
	t_type=re.search(r"Threat Type\\\\n(.*?)\\\\nOverview", content).group(1)
	return t_type

# Function to extact Threat Description
def extract_threat_desc(content):
	t_name=re.search(r"Summary\\\\n(.*?)\\\\nThreat", content).group(1)
	return t_name

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
	s_ip=re.findall("IP address ((([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))", content)
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

# Function to extract Suspicious Hashes
def extract_susp_hash(content):
	hashes=""
	counter = 0

	# Extracting SHA-256 hashes
	sha256 = re.findall("\"name\":\"File hash indicator for sha256 hash (.{64})", content)
	if sha256:
		for i in range(len(sha256)):
			hashes = hashes + sha256[i] + "\n"
			counter += 1

	# Extracting MD5 hashes
	md5 = re.findall("file:hashes.MD5 = (.{34})", content)
	if md5:
		for i in range(len(md5)):
			hashes = hashes + md5[i] + "\n"
			counter += 1

	# Extracting SHA1 hashes
	sha1 = re.findall("\"name\":\"File hash indicator for sha1 hash (.{40})", content)
	if sha1:
		for i in range(len(sha1)):
			hashes = hashes + sha1[i] + "\n"
			counter += 1

	if hashes:
		return hashes.replace("\\'", ""), counter
	return None, counter		

# Function to extract requried data from json file
def data_extraction(file_name):
	# Opening json file and converting it's content to string format
	file_obj = open(file_name, 'r')
	content = file_obj.readlines()
	content = str(content)
	content = content.replace("\\xa0", " ")
	print ("[+] Extracting From", file_name)
	
	# Capturing Threat Name
	threat_name=extract_threat_name(content)
	print ("[+]THREAT NAME: ", threat_name)

	# Capturing Threat Type
	print ("Threat Type: ", end=" ")
	threat_type=extract_threat_type(content)
	print (threat_type)

	# Capturing Threat Description
	print ("Threat Description: ", end=" ")
	threat_desc=extract_threat_desc(content)
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



#Main function
def main():
	directory = '.'
	# Check if output.csv exists and to clear it
	output_check()		
	# Add Header
	csv_head=["Date", "Threat Name", "Threat Type", "Threat Description", "Releated Vulnerabilities", "Reference Link", "Suspicious IP's", "Suspicious URL's", "Suspicious Hashes"]
	append_as_row(output_file, csv_head)
	# Capture all the .json files in current directory
	files = list_files(directory)
	
	for f in files:
		data_extraction(f)

	input("Press any key to exit!")

	# row_content = ['1', '2', '3', '4', '5']
	# append_as_row(output_file, row_content)

main()