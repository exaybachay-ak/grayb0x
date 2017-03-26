#STEP 0a: Import modules
Import-Module ServerManager
#Add-WindowsFeature RSAT-AD-PowerShell

#STEP 0b: Configure global variables for use with this program
#  grab info from optional scanTargets file
#  might use this later to put add global variables if necessary
#$inputData = Get-Content .\ScanTargets.txt
$test = Get-Date -format "yyyyMMMd"
$test2 = Get-Date -format "hhmm"
$logtime = "grayb0x_$test" + "_" + "$test2.log"
$outfile = "C:\temp\testoutput.txt"

#STEP 0c: Configure functions for use with this program
#  http://theadminguy.com/2009/04/30/portscan-with-powershell/
function fastping{
  [CmdletBinding()]
  param(
  [String]$computername = $scanIp,
  [int]$delay = 100
  )

  $ping = new-object System.Net.NetworkInformation.Ping
  # see http://msdn.microsoft.com/en-us/library/system.net.networkinformation.ipstatus%28v=vs.110%29.aspx
  try {
    if ($ping.send($computername,$delay).status -ne "Success") {
      return $false;
    }
    else {
      return $true;
    }
  } catch {
    return $false;
  }
}

#STEP 1: Gather and format information
#  get network info to use in determining what to scan
#  use below link to make regex work
#  https://technet.microsoft.com/en-us/library/hh849903.aspx  
#STEP 1a: Grab info on active net adapter from windows command line for parsing
$activeIP = get-wmiobject win32_networkadapterconfiguration | ? {$_.ipenabled}

#STEP 1b: Configure variables for subnet and IP address
write-output "" | Tee-Object -file $outfile -append
write-output "[+] Gathering primary network adapter information" | Tee-Object -file $outfile -append
$ipInfo = $activeIP.ipAddress[0]
$subInfo = $activeIP.ipsubnet[0]

#STEP 1c: Gather info about System
write-output "[+] Time is $test $test2" | Tee-Object -file $outfile -append
write-output "" | Tee-Object -file $outfile -append
write-output "" | Tee-Object -file $outfile -append
write-output "[+] Scanning localhost for system information" | Tee-Object -file $outfile -append
Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice,  BuildNumber, CSName, RegisteredUser | FL | Tee-Object -file $outfile -append
net users | Tee-Object -file $outfile -append
query user /server:localhost | Tee-Object -file $outfile -append
wmic qfe get CSName"," Caption"," Description"," HotFixID"," InstalledOn | Sort-Object InstalledOn | Tee-Object -file $outfile -append
get-process | Sort-Object ID | format-table id,path,processname,starttime,description | Tee-Object -file $outfile -Append
$services = Get-WMIObject Win32_Service | where {
    $_.Caption -notmatch "Windows" -and $_.PathName -notmatch "Windows" -and $_.PathName -notmatch "policyhost.exe" -and $_.Name -ne "LSM" -and $_.PathName -notmatch "OSE.EXE" -and $_.PathName -notmatch "OSPPSVC.EXE" -and $_.PathName -notmatch "Microsoft Security Client"
}
$services | format-table Name,PathName | Tee-Object -file $outfile -append
$services | format-table Name,FullPathName,ProcessID,StartMode,State,Status,ExitCode | Tee-Object -file $outfile -append

#STEP 1d: Gather info about nearby systems
write-output "" | Tee-Object -file $outfile -append
write-output "" | Tee-Object -file $outfile -append
write-output "[+] Scanning for network systems in segment" | Tee-Object -file $outfile -append
net use | Tee-Object -file $outfile -Append
net view | Tee-Object -file $outfile -append
netstat -abno | Tee-Object -file $outfile -append

#STEP 1e: Look around for scripts and misconfigurations
$unattend = get-childitem C:\ -recurse -filter "unattend.*" -ErrorAction SilentlyContinue

#STEP 1f: Look for misconfigurations - unattend.xml
write-output "" | Tee-Object -file $outfile -append
write-output "" | Tee-Object -file $outfile -append
write-output "[+] Scanning for system misconfigurations" | Tee-Object -file $outfile -append
foreach($u in $unattend){
    if($u.directory -notmatch "windows"){
        write-output $u.fullname | Tee-Object -file $outfile -append
    }
    else{
    }
}

#STEP 1g: Look through sysvol for scripts
write-output "" | Tee-Object -file $outfile -append
write-output "" | Tee-Object -file $outfile -append
write-output "[+] Scanning for Active Directory scripts" | Tee-Object -file $outfile -append
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
$sysvoldir = "\\$domain\sysvol\$domain\"
$sysvol = Get-ChildItem $sysvoldir -file -recurse

$ps = @()
$vbs = @()
$bat = @()

foreach($s in $sysvol){
    $testps = $s.FullName -match '\.ps1$'
    $testvbs = $s.FullName -match '\.vbs$'
    $testbat = $s.FullName -match '\.bat$'
    if($testps -eq 'True'){
        $ps += $s.FullName
    }
    elseif($testvbs -eq 'True'){
        $vbs += $s.FullName | Tee-Object -file $outfile -append
    }
    elseif($testbat -eq 'True'){
        $bat += $s.FullName | Tee-Object -file $outfile -append
    }
}
$ps | Tee-Object -file $outfile -append
$vbs | Tee-Object -file $outfile -append
$bat | Tee-Object -file $outfile -append

<#
#STEP 2: Iterate through subnet and scan hosts
#STEP 2a: Figure out if it is a /24 subnet

if ($subInfo -eq "255.255.255.0"){
    $classCPattern = "\b(?:[0-9]{1,3}\.){2}[0-9]{1,3}\."
    $classCIpAddr = ($ipInfo | sls -Pattern $classCPattern).Matches.Value

    #STEP 3.a: Using info above, loop through subnet and see if hosts are responding on 445
	$scanrange = (1..254)

	foreach ($ipaddr in $scanrange){
		#  STEP 2a: Mash up the subnet and IP to get scanrange loop variable
		$scanIp = $classCIpAddr + $ipaddr
        
        #  STEP 2b: Test host with fastest method (ping is all i can think atm) for up/down status
        write-output "" | Tee-Object -file $outfile -append
        write-output "" | Tee-Object -file $outfile -append
        write-output "[-] Beginning network scan actions on" $scanIp | Tee-Object -file $outfile -append

        $pingStatus = fastping
        if ($pingStatus -eq "True"){
    		$tcpClient = New-Object System.Net.Sockets.TCPClient
	    	#  STEP 2b: Check for SMB connectivity to weed out hosts that we aren't interested in
		    $tcpClient.Connect("$scanIp",445)
		    $SMBCheck = $tcpClient.Connected

    		if ($SMBCheck -eq "True"){
	    		write-output "" | Tee-Object -file $outfile -append
                write-output "[+] Starting grayb0x scanning" | Tee-Object -file $outfile -append
                write-output "" | tee-object -file $outfile -append
                
                #STEP 1c: Gather info about System
                write-output "" | Tee-Object -file $outfile -append
                write-output "[+] Scanning remote host for system information" | Tee-Object -file $outfile -append
                #capturing system name for commands that require it
                $hn = [System.Net.Dns]::GetHostByAddress($scanip)
                #try{ 
                #    $sysinfo = Get-CimInstance Win32_OperatingSystem -ComputerName $hn.hostname | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice,  BuildNumber, CSName, RegisteredUser | FL | Tee-Object -file $outfile -append
                #}
                #catch{
                #}
                $sysinfo = Get-CimInstance Win32_OperatingSystem -ComputerName $scanip | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice,  BuildNumber, CSName, RegisteredUser | FL | Tee-Object -file $outfile -append
                $updates = wmic /node:$scanip qfe get CSName"," Caption"," Description"," HotFixID"," InstalledOn | Sort-Object InstalledOn | Tee-Object -file $outfile -append
                $processes = get-process -ComputerName $scanIp | Sort-Object ID | format-table id,path,processname,starttime,description
                $services = Get-WMIObject Win32_Service -ComputerName $scanIp | where {
                    $_.Caption -notmatch "Windows" -and $_.PathName -notmatch "Windows" -and $_.PathName -notmatch "policyhost.exe" -and $_.Name -ne "LSM" -and $_.PathName -notmatch "OSE.EXE" -and $_.PathName -notmatch "OSPPSVC.EXE" -and $_.PathName -notmatch "Microsoft Security Client"
                }
                $services | format-table Name,PathName,ProcessID,StartMode,State,Status,ExitCode | Tee-Object -file $outfile -append

                #STEP 1d: Gather info about nearby systems
                write-output "" | Tee-Object -file $outfile -append
                write-output "[+] Scanning for network connections" | Tee-Object -file $outfile -append
                $netconn = netstat -ano | Tee-Object -file $outfile -append
                #Obviously not done yet.. these are the ideas that I started out with though and will finish in v0.1
                #  specifically, want to add parallelism to the file scanning, so it will run a lot faster
		    	write-output "[-]Beginning WMIC Update scan of:" $scanIp | Tee-Object -file $outfile -append
	    		#  STEP 2b: Use WMIC to check for latest update on host
		    	wmic /node:$scanIp qfe get CSName"," Caption"," Description"," HotFixID"," InstalledOn | Sort-Object InstalledOn | Tee-Object -file $outfile -append
		    	#wmic /node:”$scanIp” /output:.\qfe_remote.html QFE GET CSName"," HotFixID"," Description /format:htable
                #wmic /node:$scanIp qfe get Caption,Description,HotFixID,InstalledOn
                #Get-Hotfix -computername $scanIp | Select Caption, HotfixID, Description, InstalledOn | Sort-Object InstalledOn | Export-Csv .\FoundFiles.csv

                #Step 3: Search files on network shares
                #$computers = Get-ADComputer -filter *  | Select -Exp Name
               
                #foreach ($ip in $scanIp) {
                $filenames = @("sysprep.inf","sysprep.xml", "unattend.xml", "unattended.xml", "desktop.ini", "timonitor.ini, *.bat, *.ps1, *.vbs, *.vba")
                    #for ($i=0; $i -lt $filenames.length; $i++) {
                write-output "[+] Scanning $scanIp for files with potential passwords in them"
                Get-ChildItem -Recurse -Force \\$scanIp\c$ -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) } | Select-Object Name,Directory,Size | Export-Csv .\FoundFiles$scanIp.csv -nti -append
                    #}
                #}

                #look for running processes and services
                get-process | Sort-Object StartTime | format-table id,path,filename,processname,starttime,companyname,description
                get-service | Format-Table DisplayName,Name,ServiceName,Status

                #  STEP 3a: Check for cleartext files with passwords
	    		#    Ideas for these -- sysprep.ini, grep for word password,
		    	#  STEP 3b: Look for encrypted passwords and hashes			
			    #  STEP 3c: Search for unquoted service paths
	    		#  STEP 3d: Scan for folders that contain "Everyone" write, or full control

    			#  STEP 3e: Scan for batch files in domain -- vbs, bat, and ps1
			    #    Will update in future with more interesting extensions
		    }
		    elseif ($SMBCheck -eq "False"){
			    echo "This is not connected, or is probably not Windows" | Tee-Object -file $outfile -append
	    	}
		else {
			echo "This host is down, or not accepting connections"
			echo "   "$scanIp
        }
		}
    $x += 1
}

}

#Step 2a: Figure out if it's a /16 subnet
#  note: haven't started work on this, as almost all internal subnets are /24
elseif ($subInfo -eq "255.255.0.0"){
    
    #STEP 3.a: Using info above, loop through subnet and see if hosts are responding on 445
    $scanrange = (1..65534)
    #not going to add class b in until later, since i haven't seen any of these in my experience.. disabling options
    #foreach ($ipaddr in $scanrange){
		#STEP 2a: Mash up the subnet and IP to get scanrange loop variable
		$scanIp = $classCIpAddr + $ipaddr
		$tcpClient = New-Object System.Net.Sockets.TCPClient
		$tcpClient.Connect($scanIp,445)
		$SMBCheck = $tcpClient.Connected
		echo "The IP is:"$scanIp

		if ($SMBCheck -eq "True"){
			echo "This system is probably Windows"
		}
		elseif ($SMBCheck -eq "False"){
			echo "This is not connected, or is not Windows"
		}
       
		else {
			echo $scanIp
			echo "This host is down"
		}

}

else {
	return
}
#>
