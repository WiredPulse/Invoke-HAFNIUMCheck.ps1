<#
    .SYNOPSIS  
        Collects data from Microsoft Exchange Servers that assist in indentifying if the system was exploited via CVEs 2021-26855, 26857, 26858, and 27065. Some
        analysis is automatically done while other parts requires analysis. 
    
        Data collected:
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

    .EXAMPLE
        PS C:\> .\Invoke-HAFNIUMCheck.ps1

    .LINKS
        https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
        https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
        https://us-cert.cisa.gov/ncas/alerts/aa21-062a

#>

# Creating data directory
function dirCreate{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Creating the Data Directory ($env:SystemRoot\temp\$env:COMPUTERNAME-exch)..."
    if(-not(test-path $env:SystemRoot\temp\$env:COMPUTERNAME-exch)){
        new-item -Path $env:SystemRoot\temp\$env:COMPUTERNAME-exch -ItemType Directory | out-null
    }
}

# Retrieving version of Exchange
function version{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Retrieving Microsoft Exchange version..."
    $keys = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall).pspath
    foreach($key in $keys){
        $out = Get-ItemProperty $key | Select-Object displayname , displayversion, installdate, installlocation, publisher
        if($out.displayname -eq "Microsoft Exchange Server"){
            $out | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\Version.txt
        }
    }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# CVE-2021-26855
function CVE-2021-26855{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Retrieving data for CVE-2021-26855..."
    if(test-path $env:ExchangeInstallPath\V15\Logging\HttpProxy){
        foreach ($folder in get-ChildItem "${env:ExchangeInstallPath}V15\Logging\HttpProxy"){
            write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Checking $folder Logs"
            $out = Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:ExchangeInstallPath\V15\Logging\HttpProxy\" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox
            if($out){
                $out | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\HTTProxy.txt
                Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Suspicious Data in HTTP Proxy Log"
            }
            else{
                Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor yellow "System Not Affected Based on the HTTP Proxy Log"
                Write-Output "System Not affected" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\httpproxy.txt
            }
        }
    }

    elseif(test-path $env:ExchangeInstallPath\Logging\HttpProxy){
        foreach ($folder in get-ChildItem "${env:ExchangeInstallPath}Logging\HttpProxy"){
            write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Checking $folder Logs"
            $out = Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:ExchangeInstallPath\Logging\HttpProxy\$folder" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox
            if($out){
                $out | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\httpproxy_$folder.txt
                Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Suspicious Data in HTTP Proxy $folder Log"
            }
            else{
                Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "System Not Affected Based on the HTTP Proxy"
                Write-Output "System Not affected" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\httpproxy_$folder.txt
            } 
        }   
    }
    else{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "HTTP Proxy Log Doesn't Exist"
        Write-Output "Log doesn't exist" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\HTTPProxy.txt
    }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# CVE-2021-26857
function CVE-2021-26857{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Retrieving data for CVE-2021-26857..."
    if(test-path "$env:ExchangeInstallPath\V15\Logging\OABGeneratorLog\*.log"){
        $out = select-string -path "$env:ExchangeInstallPath\V15\Logging\OABGeneratorLog\*.log" -Pattern "Download failed and temporary file"
        if($out){
            $out | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\OABGeneratorLog.txt
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "Suspicious data in OAB Logs"
        }
        else{
            Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Nothing Suspicious in OAB Logs"
            Write-Output "Nothing Suspicious in OAB Logs" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\OABGeneratorLog.txt        
        }
    }
    elseif(test-path "$env:ExchangeInstallPath\Logging\OABGeneratorLog\*.log"){
        $out = select-string -path "$env:ExchangeInstallPath\Logging\OABGeneratorLog\*.log" -Pattern "Download failed and temporary file"
        if($out){
            $out | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\OABGeneratorLog.txt
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "Suspicious data in OAB Logs"
        }
        else{
            Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Nothing Suspicious in OAB Logs"
            Write-Output "Nothing Suspicious in OAB Logs" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\OABGeneratorLog.txt        
        }
    }
    else{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "OAB Logs Don't Exist"
        Write-Output "Log Doesn't Exist" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\OABGeneratorLog.txt    
    }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# CVE-2021-26858
function CVE-2021-26858{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Retrieving data for CVE-2021-26858..."
    try{
        $out = Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error -ErrorAction Stop | Where-Object { $_.Message -like "*System.InvalidCastException*" } 
        $out | export-csv $env:SystemRoot\temp\$env:COMPUTERNAME-exch\UnifiedMessaging.csv
        Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "Suspicious data in MSExchange Unified Messaging Logs"
        }
    catch{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "No Applicable MSExchange Unified Messaging Logs Exist"
        Write-Output "No Applicable Event Logs Exist" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\UnifiedMessaging.txt  
    }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# CVE-2021-27065
function CVE-2021-27065{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Retrieving data for CVE-2021-27065..."
    if(test-path "$env:ExchangeInstallPath\V15\Logging\ECP\Server\*.log"){
        $out = Select-String -Path "$env:ExchangeInstallPath\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory' -ErrorAction SilentlyContinue
        if($out){
            $out | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\ECPLogs.txt 
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "Suspicious Data in ECP Logs"
        }
        else{
            Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Nothing Suspicious in ECP Logs"
            Write-Output "Nothing Suspicious in ECP Logs" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\ECPLogs.txt         
        }
    }
    elseif(test-path "$env:ExchangeInstallPath\Logging\ECP\Server\*.log"){
        $out = Select-String -Path "$env:ExchangeInstallPath\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory' -ErrorAction SilentlyContinue
        if($out){
            $out | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\ECPLogs.txt 
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "Suspicious Data in ECP Logs"
        }
        else{
            Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Nothing Suspicious in ECP Logs"
            Write-Output "Nothing Suspicious in ECP Logs" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\ECPLogs.txt         
        }
    }
    else{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "ECP Logs Don't Exist"
        Write-Output "Log Doesn't Exist" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\ECPLogs.txt 
    }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# Hash validation
function hash{
    Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Checking Webshell Hashes..."
    $paths = "C:\inetpub\wwwroot\aspnet_client\","C:\inetpub\wwwroot\aspnet_client\system_web\","$env:ExchangeInstallPath\V15\FrontEnd\HttpProxy\owa\auth\","$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth\","C:\Exchange\FrontEnd\HttpProxy\owa\auth\", "$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth\"
    $hashes = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0","097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e","2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1","65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5","511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1","4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea", "811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d", "1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944"

    $out = (Get-ChildItem $Paths -Recurse -Filter "*.aspx" -ErrorAction SilentlyContinue).FullName
    foreach($path in $out){
        $sysHashes = get-filehash $path -Algorithm SHA1
        foreach($sysHash in $sysHashes){
            if($hashes -contains $sysHash.hash){
                $sysHash | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\HashMatch.csv -Append 
                $sys = $sysHash.hash 
                write-host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "$sys Matched Known Actor Hashes"
                }
            }
        }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# Compressed Files
function exfilStage{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Checking for potential data staged for exfil..."
    $out = Get-ChildItem $env:systemdrive\ProgramData\*.zip, $env:systemdrive\ProgramData\*.7z, $env:systemdrive\ProgramData\*.rar  -ErrorAction SilentlyContinue
    if($out){
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "Potential Data Exfil Staging in the ProgramData Directory"
            $out | select fullname, CreationTimeUtc, LastWriteTimeUtc, length | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\CompressedFiles.txt 
    }
    else{
            Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "No Compressed Items within the ProgramData Directory"
            Write-Output "No Compressed Items within the ProgramData Directory" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\CompressedFiles.txt 
    }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# Searching for potential LSASS dumps
function lsass{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Checking for potential LSASS dumps..."
    new-item -Path $env:SystemRoot\temp\$env:COMPUTERNAME-exch\dumps -ItemType Directory | out-null

    $files = (Get-ChildItem c:\root, c:\windows\temp -ErrorAction SilentlyContinue -File).FullName
    foreach($file in $files){
    $byte = [Byte[]](Get-Content -Path $file -TotalCount 4 -Encoding Byte -ErrorAction SilentlyContinue) -join('')
        if($byte-eq 77687780){
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "$file is a possible LSASS dump"
            Copy-item $file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\dumps -Force  
            $count++  
        }
    }
    if($count){
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "No Potential LSASS Dumps Found"       
    }
}

# Sysinternals Check
function sysinternals{
    function Get-RegWriteTime {

        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true, ParameterSetName="ByKey", Position=0, ValueFromPipeline=$true)]
            [ValidateScript({ $_ -is [Microsoft.Win32.RegistryKey] })]
            $RegistryKey,
            [Parameter(Mandatory=$true, ParameterSetName="ByPath", Position=0)]
            [string] $Path
        )

        begin {
            $Namespace = "CustomNamespace", "SubNamespace"
            $id = get-random
            Add-Type @"
                using System; 
                using System.Text;
                using System.Runtime.InteropServices; 
                $($Namespace | ForEach-Object {
                    "namespace $_ {"
                })
                    public class advapi32$id {
                        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                        public static extern Int32 RegQueryInfoKey(
                            IntPtr hKey,
                            StringBuilder lpClass,
                            [In, Out] ref UInt32 lpcbClass,
                            UInt32 lpReserved,
                            out UInt32 lpcSubKeys,
                            out UInt32 lpcbMaxSubKeyLen,
                            out UInt32 lpcbMaxClassLen,
                            out UInt32 lpcValues,
                            out UInt32 lpcbMaxValueNameLen,
                            out UInt32 lpcbMaxValueLen,
                            out UInt32 lpcbSecurityDescriptor,
                            out Int64 lpftLastWriteTime
                        );
                        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                        public static extern Int32 RegOpenKeyEx(
                            IntPtr hKey,
                            string lpSubKey,
                            Int32 ulOptions,
                            Int32 samDesired,
                            out IntPtr phkResult
                        );
                        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                        public static extern Int32 RegCloseKey(
                            IntPtr hKey
                        );
                    }
                $($Namespace | ForEach-Object { "}" } )
"@   
            $RegTools = ("{0}.advapi32" -f ($Namespace -join ".")) -as [type]
        }

        process {
            switch ($PSCmdlet.ParameterSetName) {
                "ByKey" {
                }

                "ByPath" {
                    $Item = Get-Item -Path $Path -ErrorAction Stop
                    if ($Item -isnot [Microsoft.Win32.RegistryKey]) {
                        throw "'$Path' is not a path to a registry key!"
                    }
                    $RegistryKey = $Item
                }
            }
            $ClassLength = 255 
            $ClassName = New-Object System.Text.StringBuilder $ClassLength 
            $LastWriteTime = $null
            $KeyHandle = New-Object IntPtr

            if ($RegistryKey.Name -notmatch "^(?<hive>[^\\]+)\\(?<subkey>.+)$") {
                Write-Error ("'{0}' not a valid registry path!")
                return
            }

            $HiveName = $matches.hive -replace "(^HKEY_|_|:$)", ""  # Get hive in a format that [RegistryHive] enum can handle
            $SubKey = $matches.subkey

            try {
                $Hive = [Microsoft.Win32.RegistryHive] $HiveName
            }
            catch {
                Write-Error ("Unknown hive: {0} (Registry path: {1})" -f $HiveName, $RegistryKey.Name)
                return  # Exit function or we'll get an error in RegOpenKeyEx call
            }

            Write-Verbose ("Attempting to get handle to '{0}' using RegOpenKeyEx" -f $RegistryKey.Name)
            switch ($RegTools::RegOpenKeyEx(
                $Hive.value__,
                $SubKey,
                0,  # Reserved; should always be 0
                [System.Security.AccessControl.RegistryRights]::ReadKey,
                [ref] $KeyHandle
            )) {
                0 { # Success
                    # Nothing required for now
                    Write-Verbose "  -> Success!"
                }

                default {
                    # Unknown error!
                    Write-Error ("Error opening handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
                }
            }

            switch ($RegTools::RegQueryInfoKey(
                $KeyHandle,
                $ClassName, 
                [ref] $ClassLength, 
                $null,  # Reserved
                [ref] $null, # SubKeyCount
                [ref] $null, # MaxSubKeyNameLength
                [ref] $null, # MaxClassLength
                [ref] $null, # ValueCount
                [ref] $null, # MaxValueNameLength 
                [ref] $null, # MaxValueValueLength 
                [ref] $null, # SecurityDescriptorSize
                [ref] $LastWriteTime
            )) {

                0 { # Success
                    $LastWriteTime = [datetime]::FromFileTime($LastWriteTime)
                    $RegistryKey | 
                        Add-Member -MemberType NoteProperty -Name LastWriteTime -Value $LastWriteTime -Force -PassThru |
                        Add-Member -MemberType NoteProperty -Name ClassName -Value $ClassName.ToString() -Force -PassThru
                }

                122  { # ERROR_INSUFFICIENT_BUFFER (0x7a)
                    throw "Class name buffer too small"
                    # function could be recalled with a larger buffer, but for
                    # now, just exit
                }

                default {
                    throw "Unknown error encountered (error code $_)"
                }
            }
            Write-Verbose ("Closing handle to '{0}' using RegCloseKey" -f $RegistryKey.Name)
            switch ($RegTools::RegCloseKey($KeyHandle)) {
                0 {
                    Write-Verbose "  -> Success!"
                }
                default {
                    Write-Error ("Error closing handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
                }
            }
        }
    }
    
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Checking for the use of Procdump or PSExec..."
    $out = (Get-childitem HKCU:\Software\sysinternals\p[r-s]* -ErrorAction SilentlyContinue).pschildname
    if(Get-childitem HKCU:\Software\sysinternals\p[r-s]* -ErrorAction SilentlyContinue){
        Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor Green "Procdump or PSExec has been used on the system"
        Get-ChildItem HKCU:\Software\sysinternals | Get-RegWritetime | Select Name, LastWriteTime | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\SysInternals.txt    
    }
    else{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "No Sysinternals tools were used on this system"
        Write-Output "No Sysinternals tools were used on this system" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\Sysinternals.txt   
    }
    Remove-Variable out -ErrorAction SilentlyContinue
}

# Other Event Logs
function eventLogs{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Retrieving PowerShell logs..."
    try{
        $out = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction stop | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\PSLog.csv -Append
        }
    catch{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "No PowerShell Logs Exist"
        Write-Output "No Applicable Event Logs Exist" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\PSLog.txt  
    }
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Retrieving Process Creation logs..."
    try{
        $out = Get-WinEvent -FilterHashtable @{logname='security'; id='4688'} -ErrorAction stop | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\ProcessCreation.csv -Append
        }
    catch{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "No Process Creation Events Exist"
        Write-Output "No Applicable Event Logs Exist" | out-file $env:SystemRoot\temp\$env:COMPUTERNAME-exch\ProcessCreation.txt  
    }
}

# Retrieving SRU DB, if present
function sru{
    write-host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Checking if SRU DB Exists..."
    if(test-path "C:\Windows\system32\sru\srudb.dat"){
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Copying SRU DB (another tool will be needed to read this)"
        copy-item "C:\Windows\system32\sru\srudb.dat" "$env:SystemRoot\temp\$env:COMPUTERNAME-exch\"
    }
    else{
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "SRU DB doesn't exist"
    }
}

# Zips data that was gathered
function zip{
    $src = "$env:SystemRoot\temp\$env:COMPUTERNAME-exch"
    $dst = "$env:SystemRoot\temp\$env:COMPUTERNAME-exch.zip"
    try {
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::CreateFromDirectory($src,$dst)
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Zipping $env:SystemRoot\temp\$env:COMPUTERNAME-exch..."
        Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "$env:SystemRoot\temp\$env:COMPUTERNAME-exch.zip has been created in $env:SystemRoot\temp"
    }
    catch {
        Write-Host -ForegroundColor red "[+] " -NoNewline; Write-host "Could not zip the $env:SystemRoot\temp\$env:COMPUTERNAME-exch, please do it manually." -foregroundcolor red
    }
    Write-Host -ForegroundColor cyan "[+] " -NoNewline; Write-Host -ForegroundColor Green "Done!"
}

write-host -foregroundcolor cyan " _____                _               _   _   ___  ______ _   _ _____ _   ____  ________ _               _    "
write-host -foregroundcolor cyan "|_   _|              | |             | | | | / _ \ |  ___| \ | |_   _| | | |  \/  /  __ \ |             | |   "
write-host -foregroundcolor cyan "  | | _ ____   _____ | | _____ ______| |_| |/ /_\ \| |_  |  \| | | | | | | | .  . | /  \/ |__   ___  ___| | __"
write-host -foregroundcolor cyan "  | || '_ \ \ / / _ \| |/ / _ \______|  _  ||  _  ||  _| | . `  | | | | | | | |\/| | |   | '_ \ / _ \/ __| |/ /"
write-host -foregroundcolor cyan " _| || | | \ V / (_) |   <  __/      | | | || | | || |   | |\  |_| |_| |_| | |  | | \__/\ | | |  __/ (__|   < "
write-host -foregroundcolor cyan " \___/_| |_|\_/ \___/|_|\_\___|      \_| |_/\_| |_/\_|   \_| \_/\___/ \___/\_|  |_/\____/_| |_|\___|\___|_|\_\"
write-host -foregroundcolor yellow "                                                                                                   @WiredPulse"`n

dirCreate
version
CVE-2021-26855
CVE-2021-26857
CVE-2021-26858
CVE-2021-27065
hash
exfilStage
lsass
sysinternals
eventLogs
sru
zip
pause
