# CHOMTE.SH
<div>
  <p align="center">
    <img src="https://i.imgur.com/Z9kuemb.png" width="200"> 
  </p>
</div>
<h4 align="center">Be sure to :star: my configuration repo so you can keep up to date on any daily progress!</h4>
<div align="center">
  
[![Twitter Follow](https://img.shields.io/twitter/follow/ccostan?color=blue&amp;label=tweet&amp;logo=twitter&amp;style=for-the-badge)](https://twitter.com/_r12w4n)
[![YouTube Subscribe](https://img.shields.io/youtube/channel/subscribers/UC301G8JJFzY0BZ_0lshpKpQ?label=YouTube&logo=Youtube&logoColor=%23DF5D44&style=for-the-badge)](https://www.youtube.com/@r12w4n7?sub_confirmation=1)
[![GitHub Follow](https://img.shields.io/github/stars/mr-rizwan-syed/chomtesh?label=sTARS&amp;logo=Github&amp;style=for-the-badge)](https://github.com/chomtesh)

</div>

CHOMTE.SH is a shell script that automates reconnaissance during penetration testing by utilizing Go-based tools. It can be useful for bug bounty and penetration testing (internal/external) to identify the attack surface. The script has a simple and modular code base, making it easy to contribute, and fast with fully configurable flags to probe multiple elements.

<br>

![alt text](https://i.imgur.com/CGIuS5z.png)

## Features
CHOMTE.SH has the following features:

1. Gather Subdomains using subfinder: This feature allows you to gather subdomains using the subfinder tool.
2. DNS Subdomain Bruteforcing using dmut: This feature enables DNS subdomain bruteforcing using the dmut tool.
3. Quick Port Scan using Naabu: This feature allows for quick port scanning using the Naabu tool.
4. Service Enumeration using Nmap: This feature enables service enumeration using Nmap by scanning ports that are only open on the host.
5. Nmap Report Format: This feature allows you to generate reports in XML, NMAP, CSV, and HTML (raw and styled) formats.
6. HTTP Probing using projectdiscovery HTTPX: This feature allows for HTTP probing using the projectdiscovery HTTPX tool to generate a CSV file.

## Installation
To install CHOMTE.SH, follow these steps:

1. Install Golang by following the instructions on this [Go Setup](https://tzusec.com/how-to-install-golang-in-kali-linux/).
2. Clone the repository: `git clone https://github.com/mr-rizwan-syed/chomtesh`
3. Change the directory: `cd chomtesh`
4. Make the script executable: `chmod +x *.sh`
5. Run the installation script: `./install.sh`
6. Run Chomte.sh: `./chomte.sh`

## Usage
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
    -p   | --project         : Specify Project Name here
    -d   | --domain          : Specify Root Domain here / Domain List here
    -i   | --ip              : Specify IP / CIDR/ IPlist here
 Optional Flags
    -n   | --nmap            : Nmap Scan against open ports
    -brt | --dnsbrute        : DNS Recon Bruteforce
    -hpl | --hostportlist    : HTTP Probing on Host:Port List
    -e   | --enum            : Active Recon
    -jsd | --jsubfinder      : Get Subdomains from WebPage and JS file by crawling
    -h   | --help            : Show this help
```

```
./chomte.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> -brt -n
./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]
```
### Mandatory Flags
- -p or --project: Specify the project name here.
- -d or --domain: Specify the root domain here or a domain list.
- -i or --ip: Specify the IP/CIDR/IP list here.

### Optional Flags
-n or --nmap                  : Nmap scan against open ports.
-brt or --dnsbrute            : DNS Recon Bruteforce.
-hpl or --hostportlist <path> : HTTP Probing on Host:Port List
-cd or --content <path>       : Content Discovery - Path is optional
-e or --enum                  : Active Enum based on technologies
-h or --help                  : Show help.

### Example
Here are some example commands:
```
./chomte.sh -p projectname -d example.com
./chomte.sh -p projectname -d example.com -brt
./chomte.sh -p projectname -d example.com -n -cd -e
./chomte.sh -p projectname -d Domains-list.txt
./chomte.sh -p projectname -i 127.0.0.1
./chomte.sh -p projectname -i 192.168.10.0/24
./chomte.sh -p projectname -i IPs-list.txt -n
```

## Customization
- CHOMTE.SH allows you to customize the tool flags by editing the flags.conf file.
- Add API keys to subfinder ~/.config/subfinder/provider-config.yaml [Subfinder API Keys](https://github.com/projectdiscovery/subfinder#post-installation-instructions).

## Contributions
Contributions and pull requests are highly encouraged for this project.


## Acknowledgement
The CHOMTESH project was made possible by community contributions. We acknowledge and thank all the contributors who have made this project what it is.
