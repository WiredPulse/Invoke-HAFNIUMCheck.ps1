# Invoke-HAFNIUMCheck.ps1
Collects data from Microsoft Exchange Servers that assist in indentifying if the system was exploited via CVEs 2021-26855, 26857, 26858, and 27065. Some
analysis is automatically done while other parts requires analysis. The data that is collected is zipped for further movement and analysis. 

# Script Execution:
1) Download and execute the script on your Microsoft Exchange server.
2) The script will output data to files located within the Temp directory within Windows. There will be output on the screen and anything of interest will have a yellow '[+]'.
3) Once complete, a zip file will be made within the Temp directory

# Data Collected:
Version
- Contains the version of the Microsoft Exchange server

HTTPproxy
- Contains specific data in regards to proxy information
- Actor’s exploitation of CVE-2021-26855 can be identified within logs in this directory

OABGeneratorLog
- Contains generation of an Offline Address Book (OAB); downloaded to ‘Program Files’ by default
- Actor has been known to download an OAB to a non-standard location
- Based on the actor’s action, artifacts will be resident here

ECPLogs
- Exchange Control Panel (ECP) is use to configure/ modify an array of features
- Based on the actor’s action, artifacts will be resident here

UnifiedMessaging
- Actor’s exploitation of CVE-2021-26857 can be identified within this event log

HashMatch
- Contains the full path and hash of any .aspx file that matches the known adversary web shell hashes

CompressedFiles
- Contains metadata for items that are compressed
- Actor’s tactic is to create compressed items to stage data for exfiltration

Dumps
- Contains items matching the file header associated with dmp files
- Actor has been known to dump LSASS

Sysinternals
- Contains whether ProcDump or PSExec have been used on the system and when it was first used
- Actor has been known to use ProcDump to dump LSASS and PSExec for other actions
- May not be usable if the organization uses these tools

srudb.dat
- Database of historical data including network connectivity and application resource data
- May not be resident
- Will need to parse the database with another tool

# Analysis
Some analysis will be done for the user during execution based on what is known about the actor and resident artifacts. A level of manual analysis is needed for items such as the PowerShell and Process Creation eventlogs. 

# Screenshot
![Alt text](https://raw.githubusercontent.com/WiredPulse/Invoke-HAFNIUMCheck.ps1/main/Screenshots/Image.png?raw=true "Optional Title")
