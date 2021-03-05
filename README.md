# Invoke-HAFNIUMCheck.ps1
Collects data from Microsoft Exchange Servers that assist in indentifying if the system was exploited via CVEs 2021-26855, 26857, 26858, and 27065. Some
analysis is automatically done while other parts requires analysis. The data that is collected is zipped for further movement and analysis. 

# Script Execution:
1) Download and execute the script on your Microsoft Exchange server.
2) The script will output data to files located within the Temp directory within Windows. There will be output on the screen and anything of interest will have a yellow '[+]'.
3) Once complete, a zip file will be made within the Temp directory

# Analysis
Some analysis will be done for the user during execution based on what is known about the actor and resident artifacts. A level of manual analysis is needed for items such as the PowerShell and Process Creation eventlogs. 

# Screenshot
![Alt text](https://raw.githubusercontent.com/WiredPulse/Invoke-HAFNIUMCheck.ps1/main/Screenshots/Image.png?raw=true "Optional Title")
