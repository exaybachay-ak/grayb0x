mkdir C:\temp -force
mkdir C:\temp\greyb0x -force

$dateYmd = Get-Date -format "yyyyMMMd"
$dateHms = Get-Date -format "hhmmss"

$activeIP = get-wmiobject win32_networkadapterconfiguration | ? {$_.ipenabled}
$ipInfo = $activeIP.ipAddress[0]

$logtime = "grayb0x_$ipInfo" + "_$dateYmd" + "_$dateHms"

Write-Host "[+] Starting grayb0x scanning" | Tee-Object -file C:\temp\greyb0x\$logtime.log
Write-Host "[+] Scanning Windows Updates" | Tee-Object -file C:\temp\greyb0x\$logtime.log
#wmic qfe get CSName"," Caption"," Description"," HotFixID"," InstalledOn | Tee-Object -file C:\temp\greyb0x\FoundUpdates_$logtime.txt
Get-Hotfix -computername $ipInfo | Select Caption, HotfixID, Description, InstalledOn | Sort-Object InstalledOn | Export-Csv C:\temp\greyb0x\FoundUpdates_$logtime.csv
Write-Host "[+] Scanning filesystem" | Tee-Object -file C:\temp\greyb0x\$logtime.log
Get-ChildItem -Recurse -Force c:\ -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) } | Select-Object Name,Directory,Length | Export-Csv C:\temp\greyb0x\FoundFiles_$logtime.csv -nti -append

$source = "C:\temp\greyb0x"
$destination = "C:\temp\greyb0x\$logtime" + "_Backup.zip"
If(Test-path $destination) {Remove-item $destination}
Add-Type -assembly "system.io.compression.filesystem"
[io.compression.zipfile]::CreateFromDirectory($Source, $destination) 