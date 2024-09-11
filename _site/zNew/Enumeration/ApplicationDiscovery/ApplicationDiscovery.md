# EyeWitness
```bash
$ sudo apt install eyewitness
```

Let's run the default --web option to take screenshots using the Nmap XML output from the discovery scan as input.

```bash
$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

# Aquatone
```bash
$ wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```

```bash
$ cat web_discovery.xml | ./aquatone -nmap
```

