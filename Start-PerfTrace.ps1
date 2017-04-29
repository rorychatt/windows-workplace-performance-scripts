# Enable-PsRemoting
# Get-SystemInfo
# Get-ServiceInfo
# Dump-EventLogs
# Start-PacketTrace
# Get-FileVersions
# Start-DiagnosticLogs #Run before event
# Get-AutoRuns
# Export-EventLogs #Run in PS Remoting Session

# Xperf boot trace
# xbootmgr -trace boot -traceFlags Latency+DISPATCHER -postBootDelay 120 -stackWalk Profile+ProcessCreate+CSwitch+ReadyThread+Mark+SyscallEnter+ThreadCreate
# On x64 first disable the paging executive: Reg.exe add “HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management” -v DisablePagingExecutive -d 0x1 -t REG_DWORD -f

##############################################################
## INITIAL INSTALL & CONFIGURATION
##############################################################

function Copy-Tools
{
    #Define Params
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Source directory')] 
        [String]$source = '.\Tools',
		
        [Parameter(Position=1, Mandatory=$false, Helpmessage='Target directory')] 
        [String]$destination = '',
		
        [Parameter(Position=2, Mandatory=$true,  Helpmessage='Target computer')] 
        [String]$computer = 'LocalHost',
		
        [Parameter(Position=3, Mandatory=$true, Helpmessage='Username')] 
        [PSCredential]$credential
	
    )
    
    # Does Source Directory Exist?
	if (!(Test-Path -Path $source))
	{
		throw New-Object system.Io.DirectoryNotFoundException( $source )
        return $false
	}

    # Is the Machine Online?
	try {
	
    	# Is the target machine on the network?
		Write-Host "Checking if $computer is online"
		if (!(Test-Connection -Computer $computer -Count 1 -Quiet)) {

			Write-Warning "$computer is offline"
			#throw New-Object system.IO.FileNotFoundException( $computer )
			return $false

		} else {

			Write-Host "$computer is online" -ForegroundColor Green

		}

	} catch {
		Write-Warning "$computer is offline"
		return $false

	}
	
    # Create Paths for Remote + Log
	$remoteDir = "\\$computer\c$"
	$logfile = "$env:temp\$($computer)_Robocopy.log"

    # Open a connection using passed credentials (required for Robocopy)
	Write-Host "Connecting to \\$computer\c$"
    Write-Host "Net Use \\$computer\c$ /user:$($credential.UserName) ...password..."

    # Mount the path using the passed credentials
	Net Use \\$computer\c$ /user:$($credential.UserName) $($credential.GetNetworkCredential().password) 

    # Check if the files already exist on the users machine, or the force command is enabled (UPGRADE TO DO A COMPARE LATER)
    if (-Not (test-path \\$computer\c$\Windows\Temp\Tools) -Or $force){

        Write-Host "Copying $source to $remoteDir"
	    Write-Host "RoboCopy.exe `"$source`" `"$remoteDir`" /s /r:2 /w:1 /e /xx /xn /log:$logfile"
	    $process = Start-Process -FilePath 'RoboCopy.exe' -ArgumentList "`"$source`" `"$remoteDir`" /s /r:2 /w:1 /e /xx /xn /log:$logfile" -Wait -PassThru
        
        #Expand the Archive after it has been copied
        Expand-Archive -Path \\$computer\c$\CopyToClient.zip -DestinationPath \\$computer\c$ -force

    }
    
    #Unmount the path
    Net use /delete \\$computer\c$ # Close the share connection

    #Exit code
    Write-Host ("Robocopy returned {0}" -f $process.ExitCode) 
	return ($process.ExitCode -lt 8)

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

function Start-WmiProcess
{
	param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Remote computer name')] [string]$Computer,
		[Parameter(Position=1, Mandatory=$true, Helpmessage='Process filepath')] [string]$filepath = '',
		[Parameter(Position=2, Mandatory=$false, Helpmessage='Arguments')] [string]$Args = '',
		[Parameter(Position=3, Mandatory=$false, Helpmessage='Credential Object (get-credential)')] [string]$credential
	)
	
    $result = Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList "$filepath $args" -Computer $Computer -Credential $credential
	
	return $result.ReturnValue
}

<#
Not Required as we pass the full fiddler install

# Run this on the remote machine
function Install-Fiddler
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Source directory')] [string]$source = 'C:\Windows\Temp\Tools\Fiddler2',
        [Parameter(Position=1, Mandatory=$false, Helpmessage='Computer')] [string]$computer = '.'
	)
	
	if (!(Test-Path -Path $source -PathType Container))
	{
		throw New-Object system.IO.DirectoryNotFoundException( $source )
	}

	Write-Host "Installing $source\fiddler4setup.exe /S"
	# Start-Process -FilePath "$source\fiddler4setup.exe" -ArgumentList '/S' -wait
	Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList "$source\fiddler4setup.exe /S" -Computer $Computer -Credential $credential
}
#>

# Run this on the remote machine
function Install-WPT
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Source directory')] [string]$source = 'C:\Windows\Temp\Tools\WPT',
	    [Parameter(Position=1, Mandatory=$false, Helpmessage='Computer')] [string]$computer = '.',
        [Parameter(Position=2, Mandatory=$false, Helpmessage='Credential')] [PSCredential]$credential = '.'
	)
	
    # Check that tool has successfully been copied over
	if (!(Test-Path -Path $source -PathType Container))
	{
		throw New-Object system.IO.DirectoryNotFoundException( $source )
	}

    # Install WPT based on Architecture
	if ([System.Environment]::Is64BitOperatingSystem)
	{
        #Install 64 Bit WPT
        return (Invoke-WMIMethod -Class Win32_Process `
                                 -Name Create `
                                 -ArgumentList "MsiExec.exe /i `"$source\WPTx64-x64_en-us.msi`" /qn Reboot=ReallySuppress" `
                                 -Computer $Computer `
                                 -Credential $credential
               ).resultvalue
	} else {
        #Install 32 Bit WPT
        return (Invoke-WMIMethod -Class Win32_Process `
                            -Name Create `
                            -ArgumentList "MsiExec.exe /i `"$source\WPTx86-x86_en-us.msi`" /qn Reboot=ReallySuppress" `
                            -Computer $Computer `
                            -Credential $credential
        ).resultvalue
	}
}

# Run this on the remote machine
function Install-Netmon
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Source directory')] [string]$source = 'C:\Windows\Temp\Tools\Netmon',
        [Parameter(Position=1, Mandatory=$false, Helpmessage='Computer')] [string]$computer = '.'
	)
	
	if (!(Test-Path -Path $source -PathType Container))
	{
		throw New-Object system.IO.DirectoryNotFoundException( $source )
	}

	Write-Host ("Hello from {0}" -f [System.Environment]::MachineName )

	if ([System.Environment]::Is64BitOperatingSystem)
	{
		Write-Host "$source\NM34_x64.exe /q"
		# Start-Process -FilePath "$source\NM34_x64.exe" -ArgumentList '/q' -wait
		
		Start-WmiProcess -Computer '.' -filepath "$source\NM34_x64.exe" -Args '/q'
	} else {
		Write-Host "$source\NM34_x86.exe /q"
		#Start-Process -FilePath "$source\NM34_x86.exe" -ArgumentList '/q' -Wait
		#Invoke-Expression "$source\NM34_x86.exe -q"
		#Invoke-command -ScriptBlock {&"$source\NM34_x86.exe" /q}
		
		Start-WmiProcess -Computer '.' -filepath "$source\NM34_x86.exe" -Args '/q'
	}

}

function Test-PsRemoting
{
	param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Remote computer name')] [string]$Computer,
		[Parameter(Position=1, Mandatory=$false, Helpmessage='Credential')] [PSCredential]$credential
	)

	Write-Host "Testing PowerShell remoting to $computer as $($credential.username)"
    Invoke-Command -ComputerName $computer -ScriptBlock {Hostname} -Credential $credential
}

##############################################################
## SCRIPT BLOCKS - Remote codeblocks
##############################################################
function Start-DiagnosticLogs
{
	Start-process -FilePath 'wevtutil.exe' -ArgumentList "set-log Microsoft-Windows-Diagnostics-Performance/Diagnostic`" /q:true /e:true"
	Start-process -FilePath 'wevtutil.exe' -ArgumentList "set-log Microsoft-Windows-GroupPolicy/Operational`" /q:true /e:true"
}

function Get-RemoteWmiRegValue
{
	param(
		[Parameter(Position=0, Mandatory=$True, Helpmessage='Credential')] [System.Management.Automation.CredentialAttribute()] $Credential 
	)

	$reg = Get-WmiObject -List -Namespace root\default -Computer $server -Credential $Credential | Where-Object {$_.Name -eq "StdRegProv"}
	$HKLM = 2147483650
	$value = $reg.GetStringValue($HKLM,"Software\Microsoft\.NetFramework","InstallRoot").sValue

	return $value
}

function Get-ServiceInfo
{

	$services = @(Get-WmiObject Win32_Service | Select-Object -Property Name,DisplayName,Description,PathName,State,StartMode,Status )

	return $services

}

function Get-DriverInfo
{
		
	$drivers = @(Get-WmiObject Win32_PnPSignedDriver) | Select-Object -Property DeviceID,Description,DriverDate,DriverName,StartMode,Status

	return $drivers
}

function Start-DataCollector
{
	param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Data collector ID')] [String]$collectorID
		)

	Start-process -FilePath LogMan.exe -ArgumentList "start `"$collectorID`" -o `"$path`"" -Wait -NoNewWindow

}

function Import-DataCollector
{
	param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Data collector XML file')] [String]$template
		)
	
	if (!(Test-Path -Path $template))
	{
		throw New-Object System.IO.FileNotFoundException( $template )
	}
	
	
	$CollectorID = [System.IO.Path]::GetFileNameWithoutExtension( $template )
	
	Write-Host "Importing data collector $template"
	Start-process -FilePath LogMan.exe -ArgumentList "import $CollectorID -xml `"$template`" -y" -Wait -NoNewWindow
		
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

function Get-AutoRuns
{
	Start-Process -FilePath "C:\Windows\Temp\AutoRuns.exe" -ArgumentList "-a C:\Windows\Temp\AutoRuns.arn" -Wait -NoNewWindow
}

##############################################################
## Traces
##############################################################

# Netmon = WPT Network Packet Capture
function Start-NetmonTrace
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Max log file size (MB)')] [int]$maxLogSize = 100,
		[Parameter(Position=1, Mandatory=$false, Helpmessage='Trace time (mins)')] [int]$tracetime = 10,
		[Parameter(Position=2, Mandatory=$false, Helpmessage='Log path')] [string]$logPath = ("C:\Windows\Temp\Tools\{0}.cap" -f $Env:Computer)
	)

	$netmonDir = 'C:\Program Files\Microsoft Network Monitor 3'
    Clear-Cache
	
	if (Test-Path -Path "$netmonDir\NMCap.exe")
	{
		
		# https://blogs.technet.microsoft.com/rmilne/2014/01/27/how-to-automate-netmon-captures/
		Write-Host "`"$netmonDir\NMCap.exe`" /Network * /Capture (!ARP) /CaptureProcesses /File $logPath`:$maxLogSize"
		Start-Process -FilePath "$netmonDir\NMCap.exe" -ArgumentList ("/Network * /Capture (!ARP) /StopWhen /TimeAfter $tracetime min /CaptureProcesses /File $logPath`:{0}MB" -f $maxLogSize) -Wait -PassThru
    

	} else {

		Write-Warning "Netmon v3.4 was not found on this machine"

	}

}

# Start trace with Fiddler
function Start-FiddlerTrace
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Path to Fidder')] [string]$path = 'C:\Program Files (x86)\Fiddler2\Fiddler.exe'	
	)
	
	if (Test-Path -Path $path -PathType Leaf)
	{
		Start-Process -FilePath $path -ArgumentList ("-quiet -noversioncheck") -Wait -PassThru
	} else {

		Write-Warning "Fiddler was not found on this machine"
	}
}

function Start-NetShTrace
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='ETL log file path')] [string]$tracefile = "C:\Windows\Temp\NetTrace.etl",
		[Parameter(Position=0, Mandatory=$false, Helpmessage='ETL log file size (MB)')] [int]$logSize = 1024
		)
	
    Clear-Cache

	Write-Host 	Netsh.exe trace start scenario=NetConnection capture=yes report=yes persistent=no maxsize=$logSize correlation=yes traceFile=$tracefile

	Netsh.exe trace start scenario=NetConnection capture=yes report=yes persistent=no maxsize=$logSize correlation=yes traceFile=$tracefile

    Write-Host "To stop the trace run: Stop-NetShTrace"
} 

function Stop-NetShTrace
{
	
	# Add a ping marker in the trace
	Ping.exe 127.0.0.1

	Write-Host "Stopping Netsh trace..."
 	NetSh.exe Trace Stop
 
}

function Start-WptTrace
{
    param(
	    [Parameter(Position=0, Mandatory=$false, Helpmessage='Also run NetSH Trace')] [switch]$NetShTrace = $true
	)

    $temp = [System.Environment]::GetEnvironmentVariable( 'temp', [System.EnvironmentVariableTarget]::Machine )


    if ($NetShTrace)
    {
	    Start-NetShTrace
    }

	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='ETL log file path')] [string]	$traceFile = "$temp\WinInetTrace.etl"
	)


	if (Test-Path -Path "C:\Program Files\Windows Kits\10\Windows Performance Toolkit\Wpr.exe" -PathType Leaf)
	{
		$wptPath = "C:\Program Files\Windows Kits\10\Windows Performance Toolkit"
	} 
	elseif (Test-Path -Path "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\Wpr.exe" -PathType Leaf)
	{
		$wptPath = "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit"
	}
	else
	{
		throw New-Object System.IO.FileNotFoundException( "Wpr.exe" )
	}

	# Deprecated - do not use
	#Logman start "wininettrace" -p "microsoft-windows-wininet" –o $traceFile –ets
	#&"$wptPath\xperf.exe" -start wininettrace -on Microsoft-Windows-WinInet -FileMode Circular -MaxFile 50 -f $traceFile

	Write-Host "`"$wptPath\Wpr.exe`" -start CPU -start DiskIO -start FileIO -start Network -Start InternetExplorer -start HTMLResponsiveness -Start HTMLActivity"
	&"$wptPath\Wpr.exe" -start CPU -start DiskIO -start FileIO -start Network -Start InternetExplorer -Start HTMLResponsiveness -Start HTMLActivity -onoffresultspath $temp -recordtempto $temp

    Write-Host "To stop this trace, run .\Stop-WinInetTrace.ps1"
}

function Stop-WptTrace 
{
    $temp = [System.Environment]::GetEnvironmentVariable( 'temp', [System.EnvironmentVariableTarget]::Machine )
    $traceFile = "$temp\WinInetTrace.etl"

    if (Test-Path -Path "C:\Program Files\Windows Kits\10\Windows Performance Toolkit\Wpr.exe" -PathType Leaf)
    {
	    $wptPath = "C:\Program Files\Windows Kits\10\Windows Performance Toolkit"
    } 
    elseif (Test-Path -Path "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\Wpr.exe" -PathType Leaf)
    {
	    $wptPath = "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit"
    }
    else
    {
	    throw New-Object System.IO.FileNotFoundException( "Wpr.exe" )
    }


    Write-Host "`"$wptPath\Wpr.exe`" -stop $traceFile"
    &"$wptPath\Wpr.exe" -stop $traceFile

    Stop-NetShTrace
}

function Start-XPerfWA
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Target drive')] [String]$filepath = '.\Xperf.exe'
	)

	# Start XPerf
	Start-Process -filepath $filepath -ArgumentList "-on DIAGEASY+Latency+DISPATCHER -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile -BufferSize 1024 -MaxBuffers 1024 -MaxFile 1024 -FileMode Circular" -PassThru -Wait

}

function Stop-XperfWA
{

	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='XPerf path')] [String]$filepath = '.\Xperf.exe',
		[Parameter(Position=1, Mandatory=$false, Helpmessage='Log file name')] [String]$tracefile = 'C:\Windows\Temp\WaitAnalyze.etl'
	)


	# Stop XPerf
	Start-Process -filepath $filepath -ArgumentList "–d $tracefile" -PassThru -Wait

}

function Start-PerformanceMetrics
{
    Invoke-Command -ComputerName $computer -ScriptBlock {Start-DiagnosticLogs} -Credential $credential
}

function Export-PerformanceMetrics
{
    param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Remote computer name')] [string]$Computer,
		[Parameter(Position=1, Mandatory=$false, Helpmessage='Username')] [PSCredential]$Credential
	)
    Invoke-Command -ComputerName $computer -ScriptBlock {Export-EventLogs} -Credential $Credential
    Invoke-Command -ComputerName $computer -ScriptBlock {Get-Autoruns} -Credential $Credential
}

function Start-SMBBenchMark
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Target drive')] [String]$netdrive = 'H:'
	)

	try
	{
		
		[Byte[]]$buffer = Get-Content -path 'C:\Windows\System32\kernel32.dll' -Encoding Byte
		
		$NetFile = [System.IO.Path]::Combine( $netdrive, '\SpeedTest.tmp')
		
		$StartTime = [DateTime]::Now
		#[System.IO.File]::Copy( $tempFileName, $NetFile, $rue )
		Set-Content -Path $NetFile -Value $buffer -Encoding Byte -Force

		$copyTime = [DateTime]::Now.Subtract( $StartTime ).TotalMilliseconds
		$throughput = ($buffer.length / $copyTime / 1000 * 8 / 1MB)
		[System.IO.File]::Delete( $NetFile )

	}
	catch
	{
	}

}

##############################################################
## USER WORKFLOW
##############################################################

Import-Module "$PSScriptRoot\Modules\setup-target.psm1" -Force

workflow Install-Tools {
    param(
		[Parameter(Position=1, Mandatory=$true,  Helpmessage='Target computer')] [String[]]$computers,
		[Parameter(Position=2, Mandatory=$true,  Helpmessage='Install source')] [String]$installsource,
		[Parameter(Position=3, Mandatory=$false, Helpmessage='Credential Object (Get-Credential)')] [PsCredential]$credential 
	)

    foreach -parallel ($computer in $computers) {
        Enable-PowerShellRemoting -computer $computer -Credential $credential
        Copy-Tools -computer $computer -source $installsource -credential $credential

        parallel {
            #Install-Fiddler -ComputerName $computer -Credential $credential
            Install-Netmon  -ComputerName $computer -Credential $credential
            Install-WPT     -ComputerName $computer -Credential $credential
        }
    }
}

$installzip = "$PSScriptRoot\Tools"
$source = ""
$computer = "WS508630"
#$credential = Get-Credential

Install-Tools -computers $computer -installsource $installzip -credential $Credential