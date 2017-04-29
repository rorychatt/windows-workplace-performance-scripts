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


function Start-WmiProcess
{
	param(
		[Parameter(Position=0, Mandatory=$true, Helpmessage='Remote computer name')] [string]$Computer,
		[Parameter(Position=1, Mandatory=$true, Helpmessage='Process filepath')] [string]$filepath = '',
		[Parameter(Position=2, Mandatory=$false, Helpmessage='Arguments')] [string]$Args = '',
		[Parameter(Position=3, Mandatory=$false, Helpmessage='Credential Object (get-credential)')] [string]
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
	    [Parameter(Position=1, Mandatory=$false, Helpmessage='Computer')] [string]$computer = '.'
        [Parameter(Position=2, Mandatory=$false, Helpmessage='Computer')] [string]$computer = '.'
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


Install-Netmon