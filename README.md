# X-Force-IoC-Extraction

# Version 1

- [This script](./Extraction_New.py) can extract multiple fields from the Threat Collection such as Threat Name, Threat Type, Threat Description, link to the particular X-Force Collection along with IoCs such as Vulnerabilities, IPs, URLs and hashes.
- The output is generated in a CSV file and each row contains all the IoCs for a single threat collection. (So, if you have multiple threat collections there will be multiple rows where each row would correspond to one threat collection)

>  **For MS Excel: If the character count for a single cell exceeds 32,767 characters then the data might not get represented properly in MS Excel. (But the CSV is generated properly, so open such files in some application other than MS Excel)**

### Known Issues

- Unable to process certain characters.
- Need to implement error handling for values that are not present in the JSON File.

# Version 2

- The [second version](./separate_output.py) of this script is capable of processing the STIX II JSON file and extract mainly 3 fields which as IP addresses, Hashes and URLs. 
- The script then creates 3 separate files for each category of IoC's.

