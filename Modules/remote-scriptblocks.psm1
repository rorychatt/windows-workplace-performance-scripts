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

Stop-WinInetTrace {
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