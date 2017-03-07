# win-inventory.ps1
# A script for collecting and various properties of a Windows system and comparing them with previous run.
#
# Made by Patrik Nordlén <patriki@gmail.com>

### BEGIN GLOBAL VARIABLE DECLARATIONS ###

# Configuration parameters go below
# This script uses its own directory in AppData for storing historical results.
$OutPath = "C:\temp\malscanner\log"
$OutFile = "$OutPath\results.json"
$OldFile = "$OutPath\oldresults.json"
$DiffFile = "$OutPath\diff.json"

# $LogUrl tells the script where it should post diff data
$LogUrl = "https://somehost.example.com/logendpoint"

# $postParams specifies parameters that should be sent to the HTTP endpoint
# The example endpoint expects a JSON message with log_type and data set
$postParams = @{log_type="blah"; data=@()}

# This array of hashes defines which checks should be run. Each hash needs to contain the following:
# Name - The name of the section in the output file.
# Function - The function that should be called to get data for this check.
# DisplayName - Descriptive text to show while the check is running.
# KeyProperty - Name of the property that should be used for comparing results. Set to $null to skip comparing the check output.
$Checks = @(
            @{Name = "Services"; Function = "Get-Services"; DisplayName="services"; KeyProperty="ServiceName"},
            @{Name = "ScanInfo"; Function = "Get-ScanInfo"; DisplayName="scan info"; KeyProperty=$null},
            @{Name = "RunningProcesses"; Function = "Get-RunningProcesses"; DisplayName="running processes"; KeyProperty="Path"},
            @{Name = "Hosts"; Function = "Get-Hosts"; DisplayName="hostfile contents"; KeyProperty="IP"},
            @{Name = "StartupItems"; Function = "Get-StartupItems"; DisplayName="startup items"; KeyProperty="Command"},
            @{Name = "LocalAdmins"; Function = "Get-LocalAdmins"; DisplayName="local administrators"; KeyProperty="Name"},
            @{Name = "Certificates"; Function = "Get-Certificates"; DisplayName="certificates"; KeyProperty="Thumbprint"},
            @{Name = "InternetExplorerAddons"; Function = "Get-IEAddons"; DisplayName="Internet Explorer addons"; KeyProperty="clsid"},
            @{Name = "InstalledApplications"; Function = "Get-InstalledApplications"; DisplayName="installed applications"; KeyProperty="Name"},
            @{Name = "ScheduledTasks"; Function = "Get-ScheduledTasks"; DisplayName="scheduled tasks"; KeyProperty="Name"},
            @{Name = "ListeningPorts"; Function = "Get-ListeningPorts"; DisplayName="listening ports"; KeyProperty="Port"}
            @{Name = "ChangedDLLs"; Function = "Get-ChangedDLLs"; DisplayName="changed DLL files"; KeyProperty="FullName"},
            @{Name = "PrefetchFiles"; Function = "Get-PrefetchFiles"; DisplayName="prefetch files"; KeyProperty="FullName"}
            )

### END GLOBAL VARIABLE DECLARATIONS ###


### BEGIN HELPER FUNCTIONS ###

# Get-RegistryKey
# This is simply a wrapper for Get-ItemProperty that removes the unnecessary meta fields in output.
function Get-RegistryKey($key) {
    return Get-ItemProperty $key | Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive
}

# Write-Results
# This function writes results to a JSON file specified by $OutFile.
# If a results file already exists in the path, it will be moved to $OldFile.
# It assumes that these items reside in $OutPath, so if this path doesn't exist it will be created.
function Write-Results($results) {
    if(!(Test-Path $OutPath)) {
        mkdir $OutPath | Out-Null
    }

    # TODO: This will be replaced by a rotating function that rotates <x> times instead
    if(Test-Path $OutFile) {
        Move-Item $OutFile $OldFile -force
    }

    ConvertTo-Json $results | Out-File $OutFile
}

# Diff-Results
# This function iterates over all sections found in the $Checks array and compares
# the two supplied results objects in each of these sections.
# It outputs differing sections between the results objects (if any).
function Diff-Results($newresults, $oldresults) {
    $diff = @()

    $Checks | Where-Object { $_.KeyProperty -ne $null } | Foreach-Object {
        $s = $_.Name
        $p = $_.KeyProperty

        $tmpdiff = Diff-Object $newresults.$s $oldresults.$s $p
        if($tmpdiff.count -ne 0) {
            $tmpdiff | Add-Member -MemberType NoteProperty -Name Check -Value $s
            $diff += $tmpdiff
        }
    }

    return $diff
}

# Diff-Object
# This function compares the two supplied objects with regards to the property $keyproperty.
# It currently only checks whether an item with that property only exists in one of the
# supplied objects, and sets the change type to "Added" or "Removed" depending on which object
# the property was found in.
#
# TODO: Make it possible to compare more (but not all) properties in each object and set change type
# to "Changed" if the property exists in both objects but has differing values.
function Diff-Object($refobj, $compobj, $keyproperty) {
    $diffobj = @()

    foreach($item in $refobj) {
        $compitem = $compobj | Where { $_.$keyproperty -eq $item.$keyproperty }
        if(($item.$keyproperty -ne $null) -and !($compitem)) {
            $item | Add-Member -MemberType NoteProperty -Name ChangeType -Value Added
            $diffobj += $item
        }
    }

    foreach($item in $compobj) {
        $compitem = $refobj | Where { $_.$keyproperty -eq $item.$keyproperty }
        if(($item.$keyproperty -ne $null) -and !($compitem)) {
            $item | Add-Member -MemberType NoteProperty -Name ChangeType -Value Removed
            $diffobj += $item
        }
    }

    return $diffobj
}

# Get-ProcessInfo
# This function takes a PID and returns as comprehensive information as possible about the process using that PID.
# The list at the start of the function should be fairly self explanatory.
function Get-ProcessInfo($ProcessID) {
    $proc = "" | select PID, ParentPID, Modules, Name, Path, Command, CertificateStatus, CertificateIssuer, CertificateSubject, MD5Hash, SHA1Hash, SHA256Hash

    $wp = Get-WmiObject -class Win32_Process -Filter "ProcessId = $ProcessID"

    If ($wp.Path -ne $null) {
        $sig = Get-AuthenticodeSignature $wp.Path
        $proc.CertificateStatus = [Enum]::GetName($sig.Status.GetType(), $sig.Status)
        $proc.CertificateIssuer = $sig.SignerCertificate.Issuer
        $proc.CertificateSubject = $sig.SignerCertificate.Subject

        $proc.MD5Hash = (Get-FileHash -Algorithm MD5 $wp.Path).Hash
        $proc.SHA1Hash = (Get-FileHash -Algorithm SHA1 $wp.Path).Hash
        $proc.SHA256Hash = (Get-FileHash -Algorithm SHA256 $wp.Path).Hash
    }
    $proc.Name = $wp.Name
    $proc.Path = $wp.Path
    $proc.PID = $ProcessID

    $proc.Command = $wp.CommandLine
    $proc.ParentPID = $wp.ParentProcessID

    $proc.Modules += (Get-Process -Id $ProcessID).Modules.FileName

    return $proc
}


### END HELPER FUNCTIONS ###


### BEGIN CHECKS ###

# Get-Hosts
# This function reads the contents of the Windows hosts file and returns
# an array of the IP/Hostname pairs it finds.
# TODO: Possibly find related comments (if any) on previous lines or at
# the end of the line and add it as information to the IP/Hostname pair.
function Get-Hosts {
    $hosts = @()

    Switch -file "C:\Windows\system32\drivers\etc\hosts" -regex {
        "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+" {
            $tmp = "" | select IP, Hostname
            $tmp.IP = $_.Split("")[0]
            $tmp.Hostname = $_.Split("")[1]
            $hosts += $tmp
        }
    }

    return $hosts
}

# Get-StartupItems
# This function uses Win32_StartupCommand and registry key checks to find startup items.
# All EXE files have their signature checked.
function Get-StartupItems {
    $items = @()

    # Win32_StartupCommand gives us "all" startup items regardless of where they're located
    # The following (at least) are handled by Win32_StartupCommand:
    #"HKLM\System\Currentcontrolset\Services\%\Imagepath",
    #"hklm:\Software\WOW6432Node\Microsoft\Windows\Currentversion\Run",
    #"hklm:\Software\Microsoft\Windows\Currentversion\Run"
    #"HKLM:\Software\Microsoft\Active Setup\Installed Components"
    #"HKLM:\Software\Microsoft\Windows\Currentversion\Explorer\Browser Helper Objects"
    #"HKLM:\Software\Microsoft\Windows\Currentversion\Runonce"
    #"HKLM:\Software\Microsoft\Windows\Currentversion\Explorer\Shellexecutehooks"
    #"HKLM:\Software\Microsoft\Windows NT\Currentversion\Windows\Appinit_Dlls"
    #"HKLM:\Software\Microsoft\Windows NT\Currentversion\Winlogon\Notify"
    #"HKLM:\Software\Microsoft\Windows\Currentversion\Policies\Explorer\Run"
    #"C:\Documents and Settings\%\Start Menu\Programs\Startup\"
    #"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    $items += Get-WmiObject Win32_StartupCommand | select Command,User,Caption,Location

    # Win32_StartupCommand only finds the registry keys in the 32-bit hive.
    # Items in HKLM\Software\Wow6432Node will not be part of output, so this is handled separately below.
    # 64-bit startup items
    $regkeys = @(
    "hklm:\software\wow6432node\microsoft\windows\currentversion\run",
    "hklm:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "hklm:\software\wow6432node\microsoft\windows\currentversion\runonce",
    "hkcu:\software\wow6432node\microsoft\windows\currentversion\run",
    "hkcu:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "hkcu:\software\wow6432node\microsoft\windows\currentversion\runonce"
    )

    foreach ($key in $regkeys) {
        If(Test-Path $key) {
            $a = Get-RegistryKey $key
            $a.PSObject.Properties | foreach-object {
                $tmp = "" | select Command,Caption,Location
                $tmp.Caption = $_.Name
                $tmp.Command = $_.Value
                $tmp.Location = $key
                $items += $tmp
            }
        }
    }

    $items | Where-Object { $_.Command -imatch "`"*(?<path>.+?\.exe)" } | ForEach-Object {
        $sig = Get-AuthenticodeSignature([System.Environment]::ExpandEnvironmentVariables($matches['path']))
        $_ | Add-Member -MemberType NoteProperty -Name CertificateStatus -Value [Enum]::GetName($sig.Status.GetType(), $sig.Status)
        $_ | Add-Member -MemberType NoteProperty -Name CertificateIssuer -Value $sig.SignerCertificate.Issuer
        $_ | Add-Member -MemberType NoteProperty -Name CertificateSubject -Value $sig.SignerCertificate.Subject
    }

    return $items
}

# Get-LocalAdmins
# This function returns members of the local group "Administrators".
function Get-LocalAdmins {
    $members = @()

    $obj_group = [ADSI]"WinNT://localhost/Administrators,group"
    $obj_group.psbase.Invoke("Members") | foreach {
        $member = "" | Select Name
        $member.Name = ([ADSI]$_).InvokeGet("Name")
        $members += $member
    }
    return $members
}

# Get-Services
# This service gathers all services regardless of state.
function Get-Services {
    $res = @()

    Get-Service | select DisplayName,ServiceName,Status,Name | ForEach-Object {
        $item = $_

        # Because Status is an enum, it needs to be resolved so we're writing the
        # description and not the numeric value to the results file.
        $item.Status = [Enum]::GetName($_.Status.GetType(), $_.Status)

        $item | Add-Member -MemberType NoteProperty -Name Command -Value (Get-WmiObject -class Win32_Service -Filter "Name = '$($item.Name)'").PathName

        $res += $item
    }

    return $res
}

# Get-Certificates
# This function retrieves all certificates installed in the system certificate store.
function Get-Certificates {
    return Get-ChildItem Cert:\ -Recurse | Select FullName, Subject, Issuer, FriendlyName, PSParentPath, Thumbprint
}

# Get-ScanInfo
# This function gathers some metadata about the scan.
function Get-ScanInfo {
    $res = "" | select Hostname, Scantime, SerialNo
    $res.Hostname = $env:COMPUTERNAME
    $res.Scantime = Get-Date
    $res.SerialNo = (Get-WmiObject -class Win32_Bios).SerialNumber

    return $res
}

# Get-InstalledApplications
# This function uses the (somewhat slow) WMI call Win32_Product to return all
# applications that were installed using Windows installer or any variants.
function Get-InstalledApplications {
    Get-WmiObject -class Win32_Product | Select Name, Vendor
}


# Get-RunningProcesses
# This function retrieves information about all running processes, including which DLL files they
# are using and whether they have a valid signature.
function Get-RunningProcesses {
    $processes = @()

    $procnum = @(Get-Process).Count
    $counter = 0

    Get-Process | Where-Object { $_.Name -ne $null } | ForEach-Object {
#        Write-Progress -Activity "Gathering process information" -PercentComplete ([Math]::Floor((100*$counter++/$procnum)))
        $processes += Get-ProcessInfo $_.Id
    }
#    Write-Progress -Activity "Gathering process information" -Completed

    return $processes
}

# GET-IEAddons
# This function checks registry keys related to IE's addons and returns a list of all found
# addons along with the corresponding DLL files.
function Get-IEAddons {
    # For some reason HKCR is not an official drive even though HKLM is. Adding it temporarily here.
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null

    # IE addon info can be stored in a number of different places...
    $ieregkeys = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
                "HKLM:\Software\Microsoft\Internet Explorer\Extensions",
                "HKLM:\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions"
                )

    # ...and their corresponding file paths as well.
    $clsidkeys = @("CLSIDExtension","BandCLSID","PSChildName")

    $res = @()

    # IE addons can be found in any of the locations specified in $ieregkeys above.
    # However the actual corresponding file path is not stored in the same location,
    # rather keys are stored that refer to a CLSID elsewhere in the registry. Path info
    # can then be found under "Inprocserver32" in one of the keys specified in $clsidkeys.
    foreach ($key in $ieregkeys) {
        If(Test-Path $key) {
            Get-ChildItem $key | ForEach-Object {
                foreach($clsidkey in $clsidkeys) {
                    if((Get-ItemProperty $_.PSPath).$clsidkey -ne $null) {
                        $subkey = $clsidkey
                        break
                    }
                }

                $item = "" | select Name, Path, clsid
                $clsid = (Get-ItemProperty $_.PSPath).$subkey
                if (test-path "HKCR:\CLSID\$clsid\InprocServer32") {
                    $regpath = "HKCR:\CLSID\$clsid"
                } elseif (test-path "HKCR:\Wow6432Node\CLSID\$clsid\InprocServer32") {
                    $regpath = "HKCR:\Wow6432Node\CLSID\$clsid"
                }

                $item.Name = (Get-ItemProperty "$regpath").'(default)'
                $item.Path = (Get-ItemProperty "$regpath\InprocServer32").'(default)'
                $item.clsid = $clsid

                $res += $item
            }
        }
    }

    Remove-PSDrive HKCR

    return $res
}

# Get-ScheduledTasks
# This function returns a list of all scheduled tasks on the system.
function Get-ScheduledTasks {
    $tasks = @()

    $schedule = New-Object -com("Schedule.Service")

    $schedule.connect()

    $schedule.GetFolder("\").gettasks(0) | foreach-object {
        $task = "" | select Name, Command, User, Description, LastRunTime, NextRunTime
        $xml = [xml]$_.Xml
        $task.User = $xml.Task.Principals.Principal.UserId
        $task.Description = $xml.Task.RegistrationInfo.Description
        $task.Command = $xml.Task.Actions.Exec.Command,$xml.Task.Actions.Exec.Arguments -join " "
        $task.Name = $_.Name
        $task.LastRunTime = $_.LastRunTime
        $task.NextRunTime = $_.NextRunTime

        $tasks += $task
    }

    return $tasks
}


# Get-ListeningPorts
# Grab information about listening ports on a system. Port 49152 and up are filtered
# due to high risk of noise related to Windows opening up dynamic ports in this range.
# This unfortunately opens up possibilities for an attacker to spawn a listening port in
# this range and go undetected, sadly for now this has to be balanaced against the flood
# of false positives that would be generated if this range were to be included.
# TODO (possibly?): only TCP ports are returned for now, consider adding UDP.
function Get-ListeningPorts {
    $ports = @()

    # Amazingly enough powershell doesn't have any convenient way of getting information about the process
    # that has spawned a listening port. Using the netstat command instead which provides this.
    netstat -nao | where { $_ -match "LISTENING" } | ForEach-Object {
        $port = "" | select Protocol, Port, Address, PID
        $arr = $_ -split '\s+'
        $arr[2] -match '(?<addr>.+?):(?<port>\d+)' | Out-Null
        if($matches['port'] -lt 49152) {
            $port.Protocol = $arr[1]
            $port.Address = $matches['addr']
            $port.Port = $matches['port']
            $port.PID = $arr[5]

            $ports += $port
        }
    }

    return $ports
}

function Get-ChangedDlls {
    return Get-ChildItem -Recurse ("C:\Windows\system32","C:\Windows\SysWOW64") -ErrorAction 0 -Include *.dll | where { $_.LastWriteTime -gt (Get-Date).AddDays(-10) } | select LastWriteTime,FullName
}


function Get-PrefetchFiles {
    return Get-ChildItem "C:\Windows\Prefetch" -Filter *.pf | Sort-Object -Descending { $_.LastWriteTime } | select FullName,LastWriteTime
}

### END CHECKS ###

# Main
# This function loops through all the checks and adds the results from them to
# the $results object, and outputs it as JSON to a file. If there is a previous
# results file it also diffs between these two and writes any differences to stdout.
function Main {
    $results = @{}

    foreach($Check in $Checks) {
        Write-Debug ("Getting " + $Check.DisplayName + "...")
        $results.($Check.Name) = & $Check.Function
    }

    Write-Results $results

    Write-Debug "Comparing results with previous results..."
    if(Test-Path $OldFile) {
        $oldresults = Get-Content $OldFile | ConvertFrom-Json
    } else {
        $oldresults = $null
    }

    # It's a bit backwards to read in the results from the JSON file they were just written to,
    # but this guarantees that both old and new results are represented in the same way.
    $newresults = Get-Content $OutFile | ConvertFrom-Json

    $diff = Diff-Results $newresults $oldresults

    if($diff.count -ne 0) {
        $diff | foreach {
            $post = "" | select ScanInfo, Item
            $post.Item = $_
            $post.ScanInfo = $results.ScanInfo
            $postParams.data = @($post)
            $postBody = ConvertTo-Json -Compress -Depth 5 $postParams
            Invoke-RestMethod -Method Post -Uri $logUrl -ContentType 'application/json' -Body ([System.Text.Encoding]::UTF8.GetBytes($postBody))
            Write-Debug $postBody
        }
	    ConvertTo-Json -Depth 5 $diff | Out-File "$DiffFile"
    }

    Write-Debug "Done! Results have been written to $OutFile"
}

Main
