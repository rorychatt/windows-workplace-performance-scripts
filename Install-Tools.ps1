Import-Module "$PSScriptRoot\Modules\WorkplacePerfAnalysis.psm1" -Force
$installzip = "$PSScriptRoot\Tools"
$source = ""
$computer = "AUUR03VP1999" # Leigh AU6159LP0034 # Matt AU2104LP6155
#$cred = Get-Credential

function Install-Tools
{
	param(
		[Parameter(Position=0, Mandatory=$false, Helpmessage='Target computer')] [String]$source,
		[Parameter(Position=1, Mandatory=$true,  Helpmessage='Target computer')] [String]$computer,
		[Parameter(Position=2, Mandatory=$true,  Helpmessage='Install source')] [String]$installsource,
		[Parameter(Position=3, Mandatory=$false, Helpmessage='Credential Object (Get-Credential)')] [PsCredential]$credential 
	)

	if (Copy-Tools -computer $computer -source $installsource -credential $credential)
	{
		Enable-PowerShellRemoting -Computer $Computer -credential $credential

		Install-Fiddler -ComputerName $computer -Credential $credential
		[System.Threading.Thread]::Sleep( 5000 )
		Install-Netmon  -ComputerName $computer -Credential $credential
        [System.Threading.Thread]::Sleep( 5000 )
        Install-WPT     -ComputerName $computer -Credential $credential

        return $true
    }

	else 
	{
        Write-Warning "Tools Cannot be installed on end user computer"
		return $false
	}
}


function Test-PsRemoting
{
	param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Remote computer name')] [string]$Computer,
		[Parameter(Position=1, Mandatory=$false, Helpmessage='Username')] [PSCredential]$credential
	)

	Write-Host "Testing PowerShell remoting to $computer as $($credential.username)"
    Invoke-Command -ComputerName $computer -ScriptBlock {Hostname} -Credential $credential
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











if (Install-Tools -computer $computer -source $source -installsource $installzip -credential $cred)
{

	Test-PsRemoting -computer $computer -credential $cred

    #Enables Diagnostic Logs on the machine
    Invoke-Command -ComputerName $computer -ScriptBlock {Start-DiagnosticLogs} -Credential $credential

	#Invoke-Command -ComputerName $computer -FilePath "$source\Enable-DiagnosticLogs.ps1" -Credential $credential
	#Invoke-Command -ComputerName $computer -FilePath "$source\Start-DataCollector.ps1" -Credential $credential
    #Export-PerformanceMetrics -Computer $computer -Credential $credential

    #Invoke-Command -ComputerName $computer -ScriptBlock {
}
