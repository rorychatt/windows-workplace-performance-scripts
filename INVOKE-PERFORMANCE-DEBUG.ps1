Import-Module \WorkplacePerfAnalysis.psm1 -Force



Enable-PSRemoting -Computer MACHINENAME -Credential CREDENTIALOBJECT




Start-DiagnosticLogs #Run before event


Export-EventLogs #Run in PS Remoting Session
Get-AutoRuns

#
#Expand-Archive -Path C:\CopyToClient.zip -DestinationPath C:\ -force
