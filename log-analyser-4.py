"""
APP     : ASA FIREWALL LOG ANALYSER
CREATER : Mike Gannon   mjpgannon@aol.com
DESCRIPTION : This application will read all of the log files in a folder and sub folders.
import the logs into a pandas table and then summarise the instances of traffic flows found in
the folder
NOTES : Current version 4 will generate a MEMORY ERROR if the number of log entries is massive 
, so I have excluded analysing 'DENY' statements from the current output. You can 
enable logging deny entries by uncommenting the elif block at line 172
Memory management is beyond me and I'll add this in future

TO USE THIS APP SIMPLY CHANGE source folder and destination folder and out put file name in lines 130 - 134
"""

import pandas as pd
import re
import os


def updatePandasList(aclListData):
    """Append parsed ACL data to the global variables used by Pandas"""

    aclList.append(aclListData[0])
    actionList.append(aclListData[1])
    protocolList.append(aclListData[2])
    srcintList.append(aclListData[3])
    srcipList.append(aclListData[4])
    srcportList.append(aclListData[5])
    dstintList.append(aclListData[6])
    dstipList.append(aclListData[7])
    dstportList.append(aclListData[8])

def extractDeny(Data):
    """ Get list separated ACL deny statement and place into an ordered list of useful data"""

    acl = str(Data[14]).replace('"','') 
    action = str(Data[6])
    protocol = str(Data[7])

    source = extractDenyIP(Data[9], protocol)
    srcint = source[0]
    srcip = source[1]
    srcport = source[2]
    destination = extractDenyIP(Data[11], protocol)
    dstint = str(destination[0])
    dstip = str(destination[1])
    dstport = str(destination[2])

    # print(acl, "\t", action, "\t", protocol, "\t",srcint, "\t", srcip, "\t", srcport, "\t",dstint, "\t", dstip, "\t", dstport)
    aclData = [acl, action, protocol, srcint, srcip, srcport, dstint, dstip, dstport]
    
    return (aclData)

def extractPermit(Data):
    """ Get list separated ACL permit statement and place into an ordered list of useful data"""
    
    acl = str(Data[8])
    action = str(Data[9])
    protocol = str(Data[10])
    source = extractIP(Data[11], protocol)
    srcint = source[0]
    srcip = source[1]
    srcport = source[2]
    destination = extractIP(Data[13], protocol)
    dstint = str(destination[0])
    dstip = str(destination[1])
    dstport = str(destination[2])

    #print(acl, "\t", action, "\t", protocol, "\t",srcint, "\t", srcip, "\t", srcport, "\t",dstint, "\t", dstip, "\t", dstport)
    aclData = [acl, action, protocol, srcint, srcip, srcport, dstint, dstip, dstport]
    
    return (aclData)

def extractIP(aclString, protocol):
    """Extract port name, IP address and port from combined string
    """
    name = "XXX"
    ip = "XXX"
    port = "XXX"
    stringpattern = re.compile(r'(.+)/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\((\d+)\)')
    match = stringpattern.match(aclString)
    if match:
        name = match.group(1)
        ip = match.group(2)
        # CHECK TO REDUCE INSTANCES OF FLOWS AND EXTRACT HIGH PORTS
        if protocol == "icmp":
            port = "0"
        elif protocol == "tcp" and int(match.group(3)) >= 1024:
            port = "tcp-high-ports"
        elif protocol == "udp" and int(match.group(3)) >= 33434:
            port = "udp-high-ports"
        else:
            port = match.group(3)
        
        return [name, ip, port]
    else:
        # This will probably happen if you screwed up the line item sent to this function
        raise ValueError("Input string is not in the expected format.")

def extractDenyIP(aclString, protocol):
    """Extract port name, IP address and port from combined string
    """
    name = "XXX"
    ip = "XXX"
    port = "XXX"
    stringpattern = re.compile(r'(.+):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)')
    match = stringpattern.match(aclString)
    if match:
        name = match.group(1)
        ip = match.group(2)
        # CHECK TO REDUCE INSTANCES OF FLOWS AND EXTRACT HIGH PORTS
        if protocol == "icmp":
            port = "0"
        elif protocol == "tcp" and int(match.group(3)) >= 1024:
            port = "tcp-high-ports"
        elif protocol == "udp" and int(match.group(3)) >= 33434:
            port = "udp-high-ports"
        else:
            port = match.group(3)
        
        return [name, ip, port]
    else:
        # This will probably happen if you screwed up the line item sent to this function
        raise ValueError("Input string is not in the expected format.")


############################# APPLICATION ###############################


# Source Data Parent Folder
filepath = 'SOURCE FOLDER FOR LOGS'

# Destination Excel Folder / File
filepath2 = 'DESTINATION FOLDER FOR OUTPUT'
outputXl = filepath2 + 'FILE NAME FOR OUTPUT'

os.system('cls')

print("Analysing Log File(s) :: ")

# regex string to fid IP Addresses
ipFormat = re.compile(r"\d+\.\d+\.\d+\.\d+")

# Track line Items checked
permitindex = 0
denyindex = 0
totalindex = 0

## ACLList Data to Build Pandas Data Frame
aclList = []
actionList = []
protocolList = []
srcintList = []
srcipList = []
srcportList = []
dstintList = []
dstipList = []
dstportList = []


all_files = os.listdir(filepath)

for file in all_files:
    filename = filepath + file
    print(" ==== FILE : ", filename, "\t:::")
    with open(filename, 'r') as fileData:
        for line in fileData:
            lineData = line.split(" ")

            if lineData[9] == "permitted":
                # Extract ACL Line Data 
                updatePandasList(extractPermit(lineData))
                permitindex += 1
                
            #elif lineData[6:8] == ["Deny","udp"] or lineData[6:8] == ["Deny","tcp"]:
            #    # Extract ACL Line Data for "Deny" statements whre rule is not allowed by ACL
            #    updatePandasList(extractDeny(lineData))
            #    permitindex += 1

            else:
                denyindex += 1
            totalindex += 1


print("Count Permit Logs : \t ", permitindex)
print("Count Deny Logs : \t ", denyindex)
print("Count Total Log  : \t ", totalindex)
if(permitindex + denyindex) == (totalindex):
    print("=== CHECK SUM OK ===")

print("=== Building Pandas Data Frame Data ===")
permitData = {
    'ACL Name': aclList,
    'Action': actionList,
    'Protocol': protocolList,
    'src-int': srcintList,
    'src-ip': srcipList,
    'src-port': srcportList,
    'dst-int': dstintList,
    'dst-ip': dstipList,
    'dst-port': dstportList
}

print("=== Building Pandas Data Frame ===")
df = pd.DataFrame(permitData)
# PRINT COUNT OF UNIQUE ROWS
totalRows = df.value_counts().reset_index(name='Count')
print("=== Exporting Data to Excel ===")
totalRows.to_excel(outputXl, sheet_name="Permit", index=False)
print("=== Data Exported to :\t", outputXl)
