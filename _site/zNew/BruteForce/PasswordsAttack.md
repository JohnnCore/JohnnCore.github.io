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
```

## Password Mutations
```bash
$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

```bash
$ ls /usr/share/hashcat/rules/
```

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
```

## Custom list of Usernames
```bash
$ ./username-anarchy -i /home/ltnbob/names.txt 
$ ./username-anarchy Bill Gates > bill.txt
```

# Default Passwords
**Credential Stuffing - Hydra**
There are various databases that keep a running list of known default credentials. One of them is the (DefaultCreds-Cheat-Sheet)[https://github.com/ihebski/DefaultCreds-cheat-sheet]. Here is a small excerpt from the entire table of this cheat sheet:

This is a simplified variant of brute-forcing because only composite usernames and the associated passwords are used.
```bash
$ hydra -C <user_pass.list> <protocol>://<IP>
```



