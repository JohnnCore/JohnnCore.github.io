# Directories

```
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://SERVER_IP:PORT/FUZZ
```

# Extension Fuzzing
```
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt -u http://SERVER_IP:PORT/indexFUZZ
```

# Page Fuzzing
```
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://SERVER_IP:PORT/FUZZ.php
```

# Recursive Scanning
```
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```