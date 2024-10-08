# Pass the Ticket (PtT) from Linux
## Kerberos on Linux
### Identifying Linux and Active Directory Integration
#### realm - Check If Linux Machine is Domain Joined
```
$ realm list
```
#### PS - Check if Linux Machine is Domain Joined
```
$ ps -ef | grep -i "winbind\|sssd"`
```

### Finding Kerberos Tickets in Linux
As an attacker, we are always looking for credentials. On Linux domain joined machines, we want to find Kerberos tickets to gain more access. Kerberos tickets can be found in different places depending on the Linux implementation or the administrator changing default settings. Let's explore some common ways to find Kerberos tickets.

#### Finding Keytab Files
A straightforward approach is to use find to search for files whose name contains the word keytab. When an administrator commonly creates a Kerberos ticket to be used with a script, it sets the extension to .keytab. Although not mandatory, it is a way in which administrators commonly refer to a keytab file.

#### Using Find to Search for Files with Keytab in the Name
```
$ find / -name *keytab* -ls 2>/dev/null
```

`Note: To use a keytab file, we must have read and write (rw) privileges on the file.`

#### Identifying Keytab Files in Cronjobs
```
$ crontab -l
```

### Finding ccache Files
A credential cache or ccache file holds Kerberos credentials while they remain valid and, generally, while the user's session lasts. Once a user authenticates to the domain, a ccache file is created that stores the ticket information. The path to this file is placed in the KRB5CCNAME environment variable. This variable is used by tools that support Kerberos authentication to find the Kerberos data. Let's look for the environment variables and identify the location of our Kerberos credentials cache:

#### Reviewing Environment Variables for ccache Files.
```
$ env | grep -i krb5
```

As mentioned previously, ccache files are located, by default, at /tmp. We can search for users who are logged on to the computer, and if we gain access as root or a privileged user, we would be able to impersonate a user using their ccache file while it is still valid.

#### Searching for ccache Files in /tmp
```
$ ls -la /tmp
```

### Abusing KeyTab Files
As attackers, we may have several uses for a keytab file. The first thing we can do is impersonate a user using kinit. To use a keytab file, we need to know which user it was created for. klist is another application used to interact with Kerberos on Linux. This application reads information from a keytab file. Let's see that with the following command:

#### Listing keytab File Information
```
$ klist -k -t 
```

The ticket corresponds to the user Carlos. We can now impersonate the user with kinit. Let's confirm which ticket we are using with klist and then import Carlos's ticket into our session with kinit.

`Note: kinit is case-sensitive, so be sure to use the name of the principal as shown in klist. In this case, the username is lowercase, and the domain name is uppercase.`

#### Impersonating a User with a keytab
```
$ klist
$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
$ klist
```
We can attempt to access the shared folder \\dc01\carlos to confirm our access.

#### Connecting to SMB Share as Carlos
```
$ smbclient //dc01/carlos -k -c ls
```

`Note: To keep the ticket from the current session, before importing the keytab, save a copy of the ccache file present in the enviroment variable KRB5CCNAME.`

