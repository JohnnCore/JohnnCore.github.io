---
layout: default
---

# Footprinting
## Nmap
```bash
$ nmap -p53 -Pn -sV -sC 10.10.110.213
```


## Dig
| DNS Record | Description |
|------------|-------------|
| A          | Returns an IPv4 address of the requested domain as a result. |
| AAAA       | Returns an IPv6 address of the requested domain. |
| MX         | Returns the responsible mail servers as a result. |
| NS         | Returns the DNS servers (nameservers) of the domain. |
| TXT        | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| CNAME      | This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu. |
| PTR        | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names. |
| SOA        | Provides information about the corresponding DNS zone and email address of the administrative contact. |

```bash
# DIG - NS Query
$ dig ns inlanefreight.htb @<IP>

# DIG - Version Query
$ dig CH TXT version.bind 10.129.120.85

# DIG - ANY Query
$ dig any inlanefreight.htb @<IP>

# DIG - AXFR Zone Transfer
$ dig axfr inlanefreight.htb @<IP>
```

We dig axfr and see what returns. 
If nothing returns, brute force.

## Subdomain Brute Forcing
```bash
$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @<IP> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

```bash
$ dnsenum --dnsserver <IP> --enum -p 0 -s 0 -o subdomains.txt -f usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt/fierce.txt inlanefreight.htb
```

## Attacking DNS
### DIG - AXFR Zone Transfer

COR33@htb[/htb]# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

### Domain Takeovers & Subdomain Enumeration
COR33@htb[/htb]# ./subfinder -d inlanefreight.com -v       

COR33@htb[/htb]$ cd subbrute
COR33@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
COR33@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt 