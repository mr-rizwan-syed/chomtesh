# CHOMTE.SH
<div>
  <p align="center">
    <img src="https://i.imgur.com/Z9kuemb.png" width="200"> 
  </p>
</div>
<h4 align="center">Be sure to :star: this repo so you can keep up to date on any daily progress!</h4>
<div align="center">
  
[![Twitter Follow](https://img.shields.io/twitter/follow/ccostan?color=blue&amp;label=tweet&amp;logo=twitter&amp;style=for-the-badge)](https://twitter.com/_r12w4n)
[![YouTube Subscribe](https://img.shields.io/youtube/channel/subscribers/UC301G8JJFzY0BZ_0lshpKpQ?label=YouTube&logo=Youtube&logoColor=%23DF5D44&style=for-the-badge)](https://www.youtube.com/@r12w4n7?sub_confirmation=1)
[![GitHub Follow](https://img.shields.io/github/stars/mr-rizwan-syed/chomtesh?label=sTARS&amp;logo=Github&amp;style=for-the-badge)](https://github.com/chomtesh)

</div>

CHOMTE.SH is a shell script that automates reconnaissance during penetration testing by utilizing Go-based tools. It can be useful for bug bounty and penetration testing (internal/external) to identify the attack surface. The script has a simple and modular code base, making it easy to contribute, and fast with fully configurable flags to probe multiple elements.

<br>

![chomtesh_usage](https://i.imgur.com/ezSLYjN.png)

## Features
CHOMTE.SH has the following features:

1. Gather Subdomains using subfinder: This feature allows you to gather subdomains using the subfinder tool.
2. DNS Subdomain Bruteforcing using dmut: This feature enables DNS subdomain bruteforcing using the dmut tool.
3. Quick Port Scan using Naabu: This feature allows for quick port scanning using the Naabu tool.
4. Service Enumeration using Nmap: This feature enables service enumeration using Nmap by scanning ports that are only open on the host.
5. Nmap Report Format: This feature allows you to generate reports in XML, NMAP, CSV, and HTML (raw and styled) formats.
6. HTTP Probing using projectdiscovery HTTPX: This feature allows for HTTP probing using the projectdiscovery HTTPX tool to generate a CSV file.

![chomtesh_MindMap](https://i.imgur.com/xVr74XT.png)

## Installation
To install CHOMTE.SH, follow these steps:

1. Clone the repository: `git clone https://github.com/mr-rizwan-syed/chomtesh`
2. Change the directory: `cd chomtesh`
3. Switch to root user `sudo su`
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
Usage: ./chomte.sh -p <ProjectName> -d <domain.com> [option]
Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]
Usage: ./chomte.sh -p projectname -d example.com -brt -ax -pp -sto -n -cd -e -ex
Usage: ./chomte.sh -p projectname -d Domains-list.txt
Usage: ./chomte.sh -p projectname -i 127.0.0.1
Usage: ./chomte.sh -p projectname -i IPs-list.txt -n -cd -e -ru -nf -cd -ex

  Mandatory Flags:
    -p   | --project <string>       : Specify Project Name here
    -d   | --domain <string>        : Specify Root Domain here / Domain List here
      OR
    -i   | --ip <string>            : Specify IP / CIDR/ IPlist here
      OR
    -hpl | --hostportlist <filename>: HTTP Probing on Host:Port List

Optional Flags - Only applicable with domain -d flag

    -sd | --singledomain            : Single Domain for In-Scope Engagement
    -pp   | --portprobe             : Probe HTTP web services in ports other than 80 & 443
         -n   | --nmap                      : Nmap Scan against open ports
    -a   | --all                    : Run all required scans
    -rr   | --rerun                 : ReRun the scan again
    -brt | --dnsbrute               : DNS Recon Bruteforce
        -ax | --alterx              : Subdomain Bruteforcing using DNSx on Alterx Generated Domains
    -sto | --takeover               : Subdomain Takeover Scan

Global Flags - Applicable with both -d / -i
    -e   | --enum                      : Active Recon
       -cd  | --content                : Content Discovery Scan
       -cd  | --content subdomains.txt : Content Discovery Scan
       -ru  | --reconurl               : URL Recon; applicable with enum -e flag
       -ex  | --enumxnl                : XNL JS Recon; applicable with enum -e flag
       -nf  | --nucleifuzz             : Nuclei Fuzz; applicable with enum -e flag
    -h   | --help                      : Show this help
```
### Mandatory Flags
- -p or --project: Specify the project name here.
- -d or --domain: Specify the root domain here or a domain list.
- -i or --ip: Specify the IP/CIDR/IP list here.

### Optional Flags
-n or --nmap                  : Nmap scan against open ports.\
-brt or --dnsbrute            : DNS Recon Bruteforce.\
-hpl or --hostportlist <path> : HTTP Probing on Host:Port List\
-cd or --content <path>       : Content Discovery - Path is optional\
-e or --enum                  : Active Enum based on technologies\
-h or --help                  : Show help.

### Example
Here are some example commands:
| Mode  |  Commands |
|-------|-------|
| Gather Subdomains and perform HTTP Probing | ./chomte.sh -p projectname -d example.com |
| Bruteforcing Subdomains with dmut | ./chomte.sh -p projectname -d example.com -brt |
| Perform AlterX Bruteforcing using DNSx | ./chomte.sh -p projectname -d example.com -brt -ax |
| Subdomain Takeover Scan using Subjack and Nuclei | ./chomte.sh -p projectname -d example.com -brt -ax -sto |
| Port Scanning and then HTTP probing on open ports | ./chomte.sh -p projectname -d example.com -pp |
| Nmap Scan on open ports + CSV,HTML Reporting | ./chomte.sh -p projectname -d example.com -pp -n |
| EnumScan: Content Discovery scan on Potential URLs | ./chomte.sh -p projectname -d example.com -e -cd |
| EnumScan: URL Recon Function  | ./chomte.sh -p projectname -d example.com -e -ru |
| EnumScan: Nuclei Fuzzer Template Scan on Potential Parameter URLs | ./chomte.sh -p projectname -d example.com -e -ru -nf |
| EnumScan: Run all Enum modules | ./chomte.sh -p projectname -d example.com -e -cd -ru -nf |
| EnumScan: XNL JS Recon and do Trufflehog Secret Scan | ./chomte.sh -p projectname -d example.com -e -ex |
| Perform all applicable Scans | ./chomte.sh -p projectname -d example.com -all |
| Input List of domains in scope | ./chomte.sh -p projectname -d Domains-list.txt |
| Single Domain for in scope engagements | ./chomte.sh -p projectname -d target.com -sd |
| Single IP Scan | ./chomte.sh -p projectname -i 127.0.0.1 |
| CIDR / Subnet Scan | ./chomte.sh -p projectname -i 192.168.10.0/24 |
| Perform Nmap scan on open ports | ./chomte.sh -p projectname -i IPs-list.txt -n |
| Perform host:port http probing & enum | ./chomte.sh -p projectname -hpl hostportlist.txt -e -cd |

### Horizontal Recon - To gather Root / TLD using crt.sh
Here are some example commands:
```
./crt.sh teslaoutput tesla.com
./crt.sh teslaoutput "TESLA, INC."
```
![chomtesh_crtsh](https://i.imgur.com/lVpNY6L.png)
![chomtesh_org](https://i.imgur.com/E5CO0Y4.png)
![chomtesh_org](https://i.imgur.com/qJKZMOg.png)

## Customization
- CHOMTE.SH allows you to customize the tool flags by editing the `flags.conf` file.
- Add API keys to subfinder ~/.config/subfinder/provider-config.yaml [Subfinder API Keys](https://github.com/projectdiscovery/subfinder#post-installation-instructions).

## Contributions
Contributions and pull requests are highly encouraged for this project.
Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are greatly appreciated.


## Acknowledgement
The CHOMTESH project was made possible by community contributions. We acknowledge and thank all the contributors who have made this project what it is.
