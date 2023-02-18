# CHOMTE.SH
CHOMTE.SH is a shell script that automates reconnaissance during penetration testing by utilizing Go-based tools. It can be useful for bug bounty and penetration testing (internal/external) to identify the attack surface. The script has a simple and modular code base, making it easy to contribute, and fast with fully configurable flags to probe multiple elements.

## Features
CHOMTE.SH has the following features:

Gather Subdomains using subfinder: This feature allows you to gather subdomains using the subfinder tool.
DNS Subdomain Bruteforcing using dmut: This feature enables DNS subdomain bruteforcing using the dmut tool.
Quick Port Scan using Naabu: This feature allows for quick port scanning using the Naabu tool.
Service Enumeration using Nmap: This feature enables service enumeration using Nmap by scanning ports that are only open on the host.
Nmap Report Format: This feature allows you to generate reports in XML, NMAP, CSV, and HTML (raw and styled) formats.
HTTP Probing using projectdiscovery HTTPX: This feature allows for HTTP probing using the projectdiscovery HTTPX tool to generate a CSV file.
Installation
To install CHOMTE.SH, follow these steps:

1. Install Golang by following the instructions on this link.
Clone the repository: git clone https://github.com/mr-rizwan-syed/chomtesh
Change the directory: cd chomtesh
Make the script executable: chmod +x *.sh
Run the installation script: ./install.sh
You can also use the following command to install CHOMTE.SH:

curl -L https://raw.githubusercontent.com/mr-rizwan-syed/chomtesh/main/install.sh | bash

Usage
To use CHOMTE.SH, run the script with the following flags:
```
└─# ./chomte.sh


 ██████╗██╗  ██╗ ██████╗ ███╗   ███╗████████╗███████╗   ███████╗██╗  ██╗
██╔════╝██║  ██║██╔═══██╗████╗ ████║╚══██╔══╝██╔════╝   ██╔════╝██║  ██║
██║     ███████║██║   ██║██╔████╔██║   ██║   █████╗     ███████╗███████║
██║     ██╔══██║██║   ██║██║╚██╔╝██║   ██║   ██╔══╝     ╚════██║██╔══██║
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║   ███████╗██╗███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝


~~~~~~~~~~~
 U S A G E
~~~~~~~~~~~
Usage: ./chomte.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> -brt -n
Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]
Usage: ./chomte.sh -p projectname -d example.com -brt
Usage: ./chomte.sh -p projectname -d Domains-list.txt
Usage: ./chomte.sh -p projectname -i 127.0.0.1
Usage: ./chomte.sh -p projectname -i IPs-list.txt -n

  Mandatory Flags:
    -p  | --project         : Specify Project Name here
    -d  | --domain          : Specify Root Domain here / Domain List here
    -i  | --ip              : Specify IP / CIDR/ IPlist here
 Optional Flags
    -n  | --nmap            : Nmap Scan against open ports
    -brt | --dnsbrute       : DNS Recon Bruteforce
    -h | --help             : Show this help
```

```
./chomte.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> -brt -n
./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]
```
### Mandatory Flags
-p or --project: Specify the project name here.
-d or --domain: Specify the root domain here or a domain list.
-i or --ip: Specify the IP/CIDR/IP list here.

### Optional Flags
-n or --nmap: Nmap scan against open ports.
-brt or --dnsbrute: DNS Recon Bruteforce.
-h or --help: Show help.

## Example
Here are some example commands:

./chomte.sh -p projectname -d example.com -brt
./chomte.sh -p projectname -d Domains-list.txt
./chomte.sh -p projectname -i 127.0.0.1
./chomte.sh -p projectname -i IPs-list.txt -n

Customization
CHOMTE.SH allows you to customize the tool flags by editing the flags.conf file.

## Acknowledgement
The CHOMTE.SH project was made possible by community contributions. We acknowledge and thank all the contributors who have made this project what it is.
