# Protected Files
## Hunting for Encoded Files
```
cry0l1t3@unixclient:~$ for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

## Hunting for SSH Keys
```
$ grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

## Cracking with John
```bash
$ locate *2john*
```

```bash
$ ssh2john.py SSH.private > ssh.hash
```

## Cracking OpenSSL Encrypted Archives
```
$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```