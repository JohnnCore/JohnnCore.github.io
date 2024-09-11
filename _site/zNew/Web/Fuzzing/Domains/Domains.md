# Domain

Add to /etc/hosts

```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.academy.htb/
```

# Vhosts

```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

# Filtering Results
```bash
$ ffuf -h
```