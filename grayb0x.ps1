#STEP 0: Configure global variables for use with this program
#  grab info from optional scanTargets file
#  might use this later to put add global variables if necessary
$inputData = Get-Content .\ScanTargets.txt

#STEP 1: Gather and format information
#  get network info to use in determining what to scan
#  use below link to make regex work
#  https://technet.microsoft.com/en-us/library/hh849903.aspx  
#STEP 1a: Grab info on active net adapter from windows command line for parsing
$activeIP = get-wmiobject win32_networkadapterconfiguration | ? {$_.ipenabled}

#STEP 1b: Configure variables for subnet and IP address
$ipInfo = $activeIP.ipAddress[0]
$subInfo = $activeIP.ipsubnet[0]

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
		$tcpClient = New-Object System.Net.Sockets.TCPClient
		#  STEP 2b: Check for SMB connectivity to weed out hosts that we aren't interested in
		$tcpClient.Connect("$scanIp",445)
		$SMBCheck = $tcpClient.Connected

		if ($SMBCheck -eq "True"){
			#Obviously not done yet.. these are the ideas that I started out with though and will finish in v0.1
			echo "[-]Beginning scan of:"$scanIp
			#  STEP 2b: Use WMIC to check for latest update on host
			Get-Hotfix -computername $scanIp | Select HotfixID, Description, InstalledOn | Sort-Object InstalledOn			
			#  STEP 2c: Check for cleartext files with passwords
			#    Ideas for these -- sysprep.ini, grep for word password,
			#  STEP 2d: Look for encrypted passwords and hashes			
			#  STEP 2e: Search for unquoted service paths
			#  STEP 2f: Scan for folders that contain "Everyone/Domain users" write, or full control
			#  STEP 2g: Scan for batch files in domain -- vbs, bat, and ps1
			#    Will update in future with more interesting extensions
		}
		elseif ($SMBCheck -eq "False"){
			echo "This is not connected, or is probably not Windows"
		}
		else {
			echo "This host is down, or not accepting connections"
			echo "   "$scanIp
		}
	echo $x
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
