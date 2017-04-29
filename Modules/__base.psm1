<#
.Synopsis
   This function enables PS-Remoting on a computer by using WMI Calls. This allows the usage of PSRemoting & CIM sessions, which are more secure.
.DESCRIPTION
   This function enables PS-Remoting on a computer by using WMI Calls. This allows the usage of PSRemoting & CIM sessions, which are more secure.
.EXAMPLE
   Enable-PSRemoting -Computer MACHINENAME
.EXAMPLE
   Enable-PSRemoting -Computer MACHINENAME -Credential CREDENTIALOBJECT
#>
function Enable-PowerShellRemoting
{
    [CmdletBinding()]
	Param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Remote HostName')] [string]$Computer = '.',
        [Parameter(Position=1, Mandatory=$true, Helpmessage='Credential Object (ie. Get-Credential')][PSCredential]$Credential
	)

    #Enable PSRemoting
    Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList "PowerShell.exe -ExecutionPolicy Bypass Enable-PSRemoting –force" -ComputerName $Computer -Credential $Credential
    
    #Enable WinRM over unencrypted communications 
    Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList "WinRM set winrm/config/client @{AllowUnencrypted=`"true`"}" -ComputerName $Computer -Credential $Credential

	#Creates trust for WinRM between local and remote machine (as Sales & Service machines don't have appropriate trusts from IBMAU to BTFIN + Lack of HTTPS Certificates)
	set-Item WSMan:\localhost\Client\TrustedHosts $Computer -Force -Credential $Credential

    Restart-Service WinRM
}

<#
.DESCRIPTION
   This function enables Diagnostic Logs in the Windows Event Logger for Performance and GPO
.EXAMPLE
   Enable-DiagnosticLogs
#>
function Start-DiagnosticLogs
{
	Start-process -FilePath 'wevtutil.exe' -ArgumentList "set-log Microsoft-Windows-Diagnostics-Performance/Diagnostic`" /q:true /e:true"
	Start-process -FilePath 'wevtutil.exe' -ArgumentList "set-log Microsoft-Windows-GroupPolicy/Operational`" /q:true /e:true"
}

<#
.Synopsis
   Dump Various event logs to a temporary directory on the user's machine. This Command is normally run in a PSRemoting session
.EXAMPLE
   Dump-EventLogs
.EXAMPLE
   Dump-EventLogs -logdir 'C:\Windows\Temp'
#>
function Export-EventLogs
{
    [CmdletBinding()]
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Log directory')] [string]$logdir = 'C:\Windows\Temp\logfiles'
	)

    $MachineName = [System.Environment]::MachineName

    mkdir "$logdir\logfiles"

    #Set Logging Directories
	$SyslogfileName = ("$logdir\System_{0}.evtx" -f $MachineName )
	$ApplogfileName = ("$logdir\Application_{0}.evtx" -f $MachineName )
	$GpoLogFileName = ("$logdir\Gpo_{0}.evtx" -f $MachineName )
	$PerfDiagfileName = ("$logdir\PefDiag_{0}.evtx" -f $MachineName )
	$GpResultFileName = ("$logdir\GpResult_{0}.htm" -f $MachineName )
	$ipConfigFileName = ("$logdir\IpConfig_{0}.txt" -f $MachineName )
	$DfsUtilFileName = ("$logdir\DfsUtil_{0}.txt" -f $MachineName )
	$NlTestFileName = ("$logdir\NlTest_{0}.txt" -f $MachineName )
	$KListFileName = ("$logdir\Klist_{0}.txt" -f $MachineName )
	$NetSHFileName = ("$logdir\NetSH_{0}.txt" -f $MachineName )
	$NetStatFileName = ("$logdir\NetStat_{0}.txt" -f $MachineName )
	$PathPingFileName = ("$logdir\PathPing_{0}.txt" -f $MachineName )
	$RpcPingFileName = ("$logdir\RpcPing_{0}.txt" -f $MachineName )
	$TaskListFileName  = ("$logdir\TaskList_{0}.txt" -f $MachineName )
    $MSDiagFileName = ("$logdir\DiagList_{0}.evtx" -f $MachineName )

	Write-Output "Dumping IP Config to $ipConfigFileName"
	IpConfig /all > $ipConfigFileName

	Write-Output "Dumping Application eventlog to $AppLogFileName"
	Start-process -filepath 'wevtutil.exe' -ArgumentList "epl Application `"$ApplogfileName`" /ow" -Wait -NoNewWindow

	Write-Output "Dumping System eventlog to $SysLogFileName"
	Start-process -FilePath 'wevtutil.exe' -ArgumentList "epl System `"$SysLogFileName`" /ow" -Wait -NoNewWindow

	Write-Output "Dumping Diagnostics-Performance eventlog to $PerfDiagFileName"
	Start-process -FilePath 'wevtutil.exe' -ArgumentList "epl Microsoft-Windows-Diagnostics-Performance/Diagnostic `"$PerfDiagfileName`" /ow" -Wait -NoNewWindow
    Start-process -FilePath 'wevtutil.exe' -ArgumentList "epl Microsoft-Windows-Diagnostics-Performance/Operational `"$MSDiagFileName`" /ow" -Wait -NoNewWindow

	Write-Output "Dumping GPO eventlog to $GPOLogFileName"
	Start-process -FilePath 'wevtutil.exe' -ArgumentList "epl Microsoft-Windows-GroupPolicy/Operational `"$GpoLogFileName`" /ow" -Wait -NoNewWindow

	Write-Output "Dumping GPO results to $GpResultFileName"
	Start-process -FilePath 'GpResult.exe' -ArgumentList "-f -h `"$GpResultFileName`"" -Wait -NoNewWindow

	Write-Output "Dumping Dfs info to $DfsUtilFileName"
	#Start-process -FilePath 'DfsUtil.exe' -ArgumentList "/pktinfo `"$DfsUtilFileName`"" -Wait -NoNewWindow
	DfsUtil.exe /pktinfo > $DfsUtilFileName

	Write-Output "Dumping NlTest info $NlTestFileName"
	NlTest.exe /DsGetSite > $NlTestFileName

	Write-Output "Dumping Kerberos tickets to $KListFileName"
	Klist.exe tickets > $KListFileName

	Write-Output "Dumping NetSH to $NetSHFileName"
	NetSh.exe dump * > $NetSHFileName

	Write-Output "Dumping TaskList to $TaskListFileName"
	TaskList.exe /v > $TaskListFileName
	TaskList.exe /svc >> $TaskListFileName

	Write-Output "Dumping Netstat to $NetStatFileName"
	NetStat.exe -b  > $NetStatFileName
	
	Write-Output "Dumping RpcPing to $RpcPingFileName"
	RpcPing.exe -s outlook.thewestpacgroup.com.au -a connect -u negotiate > $RpcPingFileName

	Write-Output "Dumping PathPing to $PathPingFileName"
	PathPing.exe sites.thewestpacgroup.com.au > $PathPingFileName
}

function Get-AutoRuns
{
	Start-Process -FilePath "C:\Windows\Temp\AutoRuns.exe" -ArgumentList "-a C:\Windows\Temp\AutoRuns.arn" -Wait -NoNewWindow
}

<#
.Synopsis
   Exports a copy of the msinfo32 to a log file
.DESCRIPTION
   Long description
.EXAMPLE
   Get-SystemInfo
.EXAMPLE
   Get-SystemInfo -logfilename "C:\Windows\Temp\" -Computer COMPUTERNAME -Credential CREDENTIALOBJECT
#>
function Get-SystemInfo
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Log file name')] 
        [string]$logfileName = ("C:\Windows\Temp\Tools\{0}.nfo" -f [System.Environment]::MachineName),
        
        [Parameter(Position=1, Mandatory=$false, Helpmessage='Remote HostName')] [string]$Computer = '.',

        [Parameter(Position=2, Mandatory=$false, Helpmessage='Credential Object (ie. Get-Credential')]
        [System.Management.Automation.CredentialAttribute()]$Credential	
    )
	
	$msinfo32 = ("{0}\MsInfo32.exe" -f [System.Environment]::SystemDirectory)
	# https://support.microsoft.com/en-us/kb/300887

	Write-Host "Running MsInfo32, logging to $logfilename"
    $result = Invoke-WMIMethod  -Class Win32_Process `
                                -Name Create `
                                -ArgumentList "$msinfo32 /nfo $logfilename" `
                                -Computer $Computer `
                                -Credential $credential
}

#Returns SMB & DFS driver information and writes to output
function Get-FileVersions
{
	$files = @( 'C:\Windows\System32\Drivers\DfsC.sys', 'C:\Windows\System32\Drivers\Mup.sys', 'C:\Windows\System32\Drivers\Mrxsmb.sys', 'C:\Windows\System32\NtLanman.dll', 'C:\Windows\System32\DfsCli.dll')
	
	foreach( $file in $files )
	{
		$fi = New-Object System.IO.FileInfo( $file )
		Write-Host ("{0}`t{1}`t{2}`t{3}" -f $file, $fi.VersionInfo.FileVersion, $fi.VersionInfo.FileDescription, $fi.LastWriteTime )
	}
}




#Expand-Archive -Path C:\CopyToClient.zip -DestinationPath C:\ -force
