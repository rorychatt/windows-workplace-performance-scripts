param(
	[Parameter(Position=0, Mandatory=$false, Helpmessage='Data collector XML file')] [String]$template = 'C:\Windows\Temp\Tools\Data Collector\WBC.xml',
	[Parameter(Position=1, Mandatory=$false, Helpmessage='Data collector ID')] [String]$collectorID = 'WBC'
)


function Start-DataCollector
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Data collector ID')] [String]$collectorID
	)

	Write-Host "LogMan start $collectorID"
	Start-process -FilePath 'LogMan.exe' -ArgumentList "start $collectorID" -Wait -NoNewWindow

}


function Import-DataCollector
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Data collector XML file')] [String]$template = 'C:\Windows\Temp\Tools\Data Collector\WBC.xml',
		[Parameter(Position=1, Mandatory=$false, Helpmessage='Data collector ID')] [String]$collectorID = [System.IO.Path]::GetFileNameWithoutExtension( $template )
	)
	
	
	if (!(Test-Path -Path $template))
	{
		throw New-Object System.IO.FileNotFoundException( $template )
	}
	
	
	# Get the output dir
	$xml = [XML](Get-Content -Path $template)
	$outputDir = $xml.DataCollectorSet.OutputLocation
	
	if (!(Test-Path -Path $outputDir -PathType Container))
	{
		Write-Host "Creating $outputDir"
		[System.IO.Directory]::CreateDirectory( $outputDir )
	}
	
		
	Write-Host "Importing data collector $template [$CollectorID]"
	
	Write-Host "LogMan.exe import -n $CollectorID -xml `"$template`" -y"
	
	#$proc = Start-process -FilePath 'Logman.exe' -ArgumentList "import -n $CollectorID -xml `"$template`" -y" -Wait -PassThru
	Logman.exe import -n $CollectorID -xml `"$template`" -y
	
	Write-Host $lastExitCode
	
	if ($proc.ExitCode -eq -2147024891)
	{
		throw New-Object System.AccessViolationException("Access denied")
	} else {
		Write-Host $proc.ExitCode
	}
		
}


Import-DataCollector -template $template

[System.Threading.Thread]::Sleep( 1000 )

Start-DataCollector -collectorID $collectorID

