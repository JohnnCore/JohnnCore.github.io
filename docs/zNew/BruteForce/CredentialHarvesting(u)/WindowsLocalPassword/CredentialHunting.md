# Credential Hunting in Windows
## Key Terms to Search

Passwords 	Passphrases 	Keys
Username 	User account 	Creds
Users 	Passkeys 	Passphrases
configuration 	dbcredential 	dbpassword
pwd 	Login 	Credentials

## Search Tools
With access to the GUI, it is worth attempting to use Windows Search to find files on the target using some of the keywords mentioned above.

By default, it will search various OS settings and the file system for files & applications containing the key term entered in the search bar.


**Running Lazagne All**
We can also take advantage of third-party tools like Lazagne to quickly discover credentials that web browsers or other installed applications may insecurely store. It would be beneficial to keep a standalone copy of Lazagne on our attack host so we can quickly transfer it over to the target. Lazagne.exe will do just fine for us in this scenario. We can use our RDP client to copy the file over to the target from our attack host. If we are using xfreerdp all we must do is copy and paste into the RDP session we have established.

```
> start lazagne.exe all
```

**Using findstr**
We can also use findstr to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

```
> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
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

