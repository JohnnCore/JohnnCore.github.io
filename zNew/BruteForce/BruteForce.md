---
layout: default
---

# Passwords Attack
## Hash Identifier
```bash
$ hash-identifier
```

## Crack Password
### John The Ripper
```bash
$ john pass.txt --wordlist=/usr/share/wordlists/rockyou.txt`
```

### Hashcat
```bash
$ hashcat -m 3200 -a 0 -o found.txt passwd.txt /usr/share/wordlists/rockyou.txt

# 1000 NTLM hashes
# 5600 NTLMv2 hashes
# 13100 Kerberos TGS
```

## Password Mutations
`/usr/share/hashcat/rules/`
```bash
$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

* * *

# Custom Wordlists
## CeWL
We can now use another tool called CeWL to scan potential words from the company's website and save them in a separate list. We can then combine this list with the desired rules and create a customized password list that has a higher probability of guessing a correct password. We specify some parameters, like the depth to spider (-d), the minimum length of the word (-m), the storage of the found words in lowercase (--lowercase), as well as the file where we want to store the results (-w).


```bash
$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```
   - `-d minimum word length`
   - `-m maximum word length`
   - `--lowercase all words are lowercase`
   - `-w output file`

## CUPP
```bash
$ cupp -i

sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```

## Custom list of Usernames
```bash
$ ./username-anarchy -i /home/ltnbob/names.txt 
$ ./username-anarchy Bill Gates > bill.txt
```

## Default Passwords
**Credential Stuffing - Hydra**
There are various databases that keep a running list of known default credentials. One of them is the (DefaultCreds-Cheat-Sheet)[https://github.com/ihebski/DefaultCreds-cheat-sheet]. Here is a small excerpt from the entire table of this cheat sheet:

This is a simplified variant of brute-forcing because only composite usernames and the associated passwords are used.
```bash
$ hydra -C <user_pass.list> <protocol>://<IP>
```

* * *

# Services
`Note: Although we may find services vulnerable to brute force, most applications today prevent these types of attacks. A more effective method is Password Spraying.`

## Hydra 
```bash
$ hydra -L user.list -P password.list <protocol>://<IP> -t 48 -p <port>

- L user list 
- l single username 
- P pass list
- p single password
- t <num> threads
- p <port>
```

## FTP
```bash
$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 

$ hydra -L user.list -P password.list ftp://<IP> -s 21
```

## SSH
```bash
$ hydra -L user.list -P password.list ssh://<IP>
```

## SMB
```bash
$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

$ hydra -L user.list -P password.list smb://10.129.42.197

$ msf6 > use auxiliary/scanner/smb/smb_login
```

## WinRM
```bash
$ crackmapexec winrm <IP> -u user.list -p password.list
```

## RDP
```bash
$ crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
$ hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
$ hydra -L user.list -P password.list rdp://10.129.42.197`
```

* * *

# Login Attacks
## Default Passwords
`/usr/share/wordlists/seclists/Passwords/Default-Credentials`

```bash
$ hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <IP> -s <PORT> http-get /
```

## Username/Password Attack
```bash
$ hydra -L /usr/share/wordlists/secLists/Usernames/Names/names.txt -P /usr/share/wordlists/rockyou.txt -u -f <IP> -s <PORT> http-get /
```

## Username Brute Force
```bash
$ hydra -L /usr/share/wordlists/secLists/Usernames/Names/names.txt -p <PASSWORD> -u -f <IP> -s <PORT> http-get /
```

## Brute Forcing Forms
two types of http modules interesting for us:

- http[s]-{head|get|post}
- http[s]-post-form
The 1st module serves for basic HTTP authentication, while the 2nd module is used for login forms, like .php or .aspx and others.

To decide which module we need, we have to determine whether the web application uses GET or a POST form. We can test it by trying to log in and pay attention to the URL. If we recognize that any of our input was pasted into the URL, the web application uses a GET form. Otherwise, it uses a POST form.


```bash
$ hydra -l <admin> -P /usr/share/wordlists/rockyou.txt -f <IP> -s <PORT> http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

- login.php: url
- username=^USER^&password=^PASS^: parameters to POST (Capture on Burp Suite)
- Third: form name (Check source code)


# Protected Files
## Cracking with John
```bash
$ locate *2john*
```

```bash
$ ssh2john.py SSH.private > ssh.hash
```

## Cracking OpenSSL Encrypted Archives
```bash 
$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```

### Using a for-loop to Display Extracted Contents
```bash
$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```
