# Attacking LSASS
## Dumping LSASS Process Memory

## Task Manager Method
Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file
A file called lsass.DMP is created and saved in: 
`C:\Users\loggedonusersdirectory\AppData\Local\Temp`

## Rundll32.exe & Comsvcs.dll Method
### Finding LSASS PID in cmd
```
> tasklist /svc 
```
and find lsass.exe and its process ID in the PID field.

### Finding LSASS PID in PowerShell
```
PS > Get-Process lsass 
```
and see the process ID in the Id field.

### Creating lsass.dmp using PowerShell
```
PS > rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

If we manage to run this command and generate the lsass.dmp file, we can proceed to transfer the file onto our attack box to attempt to extract any credentials that may have been stored in LSASS process memory.

## Using Pypykatz to Extract Credentials
Recall that LSASS stores credentials that have active logon sessions on Windows systems. When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present. 

```
$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```

### MSV
MSV is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. Pypykatz extracted the SID, Username, Domain, and even the NT & SHA1 password hashes associated with the bob user account's logon session stored in LSASS process memory. This will prove helpful in the final stage of our attack covered at the end of this section.

### WDIGEST
WDIGEST is an older authentication protocol enabled by default in Windows XP - Windows 8 and Windows Server 2003 - Windows Server 2012. LSASS caches credentials used by WDIGEST in clear-text. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text. Modern Windows operating systems have WDIGEST disabled by default. Additionally, it is essential to note that Microsoft released a security update for systems affected by this issue with WDIGEST. We can study the details of that security update here.

### Kerberos
Kerberos is a network authentication protocol used by Active Directory in Windows Domain environments. Domain user accounts are granted tickets upon authentication with Active Directory. This ticket is used to allow the user to access shared resources on the network that they have been granted access to without needing to type their credentials each time. LSASS caches passwords, ekeys, tickets, and pins associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

### DPAPI
The Data Protection Application Programming Interface or DPAPI is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications. Here are just a few examples of applications that use DPAPI and what they use it for:

| Applications            | Use of DPAPI                                                                 |
|-------------------------|------------------------------------------------------------------------------|
| Internet Explorer       | Password form auto-completion data (username and password for saved sites).   |
| Google Chrome           | Password form auto-completion data (username and password for saved sites).   |
| Outlook                 | Passwords for email accounts.                                                |
| Remote Desktop Connection | Saved credentials for connections to remote machines.                        |
| Credential Manager      | Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more. |


Mimikatz and Pypykatz can extract the DPAPI masterkey for the logged-on user whose data is present in LSASS process memory. This masterkey can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts. DPAPI attack techniques are covered in greater detail in the Windows Privilege Escalation module.

### Cracking the NT Hash with Hashcat
Now we can use Hashcat to crack the NT Hash. In this example, we only found one NT hash associated with the Bob user, which means we won't need to create a list of hashes as we did in the Attacking SAM section of this module. After setting the mode in the command, we can paste the hash, specify a wordlist, and then crack the hash.

```
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```