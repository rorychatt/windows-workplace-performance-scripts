#Start-NetmonTrace
#Enable-PsRemoting
#Install-Tools
#Get-ServiceInfo

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


#Install-Tools -computer 'WS320007' -username 'btfin.com\m031632'



#Get-ServiceInfo

#Test-SSDTrim

# Start-PacketTrace

# Get-SystemInfo

# Dump-EventLogs

# Start-SMBBenchMark

# Xperf boot trace
# xbootmgr -trace boot -traceFlags Latency+DISPATCHER -postBootDelay 120 -stackWalk Profile+ProcessCreate+CSwitch+ReadyThread+Mark+SyscallEnter+ThreadCreate
#On x64 first disable the paging executive: Reg.exe add “HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management” -v DisablePagingExecutive -d 0x1 -t REG_DWORD -f


# C:\Windows\Debug\UserMode\gpsvc.log
# C:\Windows\Debug\Netlogon.log


Get-FileVersions

