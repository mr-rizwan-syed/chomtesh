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
CHOMTE.SH is a versatile framework designed for automating reconnaissance tasks in penetration testing. It's useful for bug bounty hunters and penetration testers in both internal and external network engagements. Its key features include subdomain gathering, DNS subdomain brute-forcing, quick port scanning, HTTP probing, service enumeration, and generating reports in various formats. Additionally, it performs content discovery, identifies common misconfigurations and vulnerabilities, conducts deep internet reconnaissance, provides command transparency, and specializes in JavaScript reconnaissance. Users can customize tool arguments by modifying the flags.conf file.
<br>
<br>

![chomtesh_usage](https://i.imgur.com/ajBUjdx.png)

## Major Features
Here are some of the key features that make **CHOMTE.SH** a must-have for security professionals:

1. **Subdomain Discovery**: Easily gather subdomains with the help of the robust subfinder tool.
2. **DNS Subdomain Bruteforcing**: Strengthen your DNS security by performing subdomain bruteforcing with the dmut tool.
3. **Quick Port Scanning**: Quickly identify potential vulnerabilities by performing port scans using Naabu.
4. **HTTP Probing**: Generate detailed reports, including techdetect and webanalyze, using projectdiscovery HTTPX.
5. **Service Enumeration**: Discover open ports and services using Nmap, focusing only on what matters.
6. **Reporting**: Create comprehensive reports in XML, NMAP, CSV, and HTML formats, allowing you to present your findings effectively.
7. **Content Discovery**: Identify sensitive files exposed in web applications and rectify potential security flaws.
8. **Vulnerability Scanning**: Uncover common misconfigurations and vulnerabilities in your infrastructure and web applications.
9. **Deep Reconnaissance**: Leverage Shodan and Certificate Transparency for thorough internet-wide reconnaissance.
10. **Command Transparency**: Gain full visibility into executed commands, their locations, and file outputs.
11. **URL Extraction and Validation**: Collect all URLs, extract JavaScript files, and validate them, including those with unique parameters.
12. **Nuclei-based Scanning**: Run Nuclei scans based on technologies found in subdomains and perform parameter fuzzing on URLs.
13. **JavaScript Recon**: Uncover hardcoded credentials, sensitive keys, and passwords in your applications.
14. **Customization**: Tailor the tool's behavior to your needs by modifying the flags.conf file.

**CHOMTE.SH** is a game-changer for cybersecurity professionals, offering a comprehensive toolkit to secure your digital assets and strengthen your web application defenses. Stay ahead of threats, protect your online presence, and make **CHOMTE.SH** a part of your security arsenal.

![chomtesh_MindMap](https://i.imgur.com/HXDYfGA.png)

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

 U S A G E
Usage: ./chomte.sh -p <ProjectName> -d <domain.com> [option]
Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]
Usage: ./chomte.sh -p projectname -d example.com -brt -jsd -sto -n -cd -e -js -ex
Usage: ./chomte.sh -p projectname -d Domains-list.txt
Usage: ./chomte.sh -p projectname -i 127.0.0.1
Usage: ./chomte.sh -p projectname -i IPs-list.txt -n -cd -e -js -ex

Mandatory Flags:
    -p   | --project <string>       : Specify Project Name here
    -d   | --domain <string>        : Specify Root Domain here / Domain List here
      OR
    -i   | --ip <string>            : Specify IP / IPlist here - Starts with Naabu
    -c   | --cidr | --asn <string>  : CIDR / ASN - Starts with Nmap Host Discovery
      OR
    -hpl | --hostportlist <filename>: HTTP Probing on Host:Port List

╔════════════════════════════════════════════════════════════════════════════════╗
        Optional Flags - Only applicable with domain -d flag
╚════════════════════════════════════════════════════════════════════════════════╝


    -sd | --singledomain            : Single Domain for In-Scope Engagement
    -pp   | --portprobe             : Probe HTTP web services in ports other than 80 & 443
    -a   | --all                    : Run all required scans
    -rr   | --rerun                 : ReRun the scan again
    -brt | --dnsbrute               : DNS Recon Bruteforce
        -ax | --alterx              : Subdomain Bruteforcing using DNSx on Alterx Generated Domains
    -sto | --takeover               : Subdomain Takeover Scan


╔════════════════════════════════════════════════════════════════════════════════╗
        Global Flags - Applicable with both -d / -i
╚════════════════════════════════════════════════════════════════════════════════╝
    -s   | --shodan                    : Shodan Deep Recon - API Key Required
    -n   | --nmap                      : Nmap Scan against open ports
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
| EnumScan: Run all Enum modules | ./chomte.sh -p projectname -d example.com -e -cd -ru -v -nf |
| EnumScan: XNL JS Recon and do Trufflehog Secret Scan | ./chomte.sh -p projectname -d example.com -e -ex |
| Perform all applicable Scans | ./chomte.sh -p projectname -d example.com -all |
| Shodan Scan [API Key Required]| ./chomte.sh -p projectname -d example.com -s |
| Input List of domains in scope | ./chomte.sh -p projectname -d Domains-list.txt |
| Single Domain for in scope engagements | ./chomte.sh -p projectname -d target.com -sd |
| Single IP Scan | ./chomte.sh -p projectname -i 127.0.0.1 |
| CIDR / Subnet Scan | ./chomte.sh -p projectname --cidr 192.168.10.0/24 |
| ASN Scan | ./chomte.sh -p projectname --asn AS394363 |
| Perform Nmap scan on open ports | ./chomte.sh -p projectname -i IPs-list.txt -n |
| Perform host:port http probing & enum | ./chomte.sh -p projectname -hpl hostportlist.txt -e -cd |

### Setup after Installation
1. Setup Subfinder API Keys `~/.config/subfinder/provider-config.yaml` [Subfinder API Keys](https://github.com/projectdiscovery/subfinder#post-installation-instructions).
2. Setup API Keys in Chomtesh Config file `chomtesh/config.yml`
3. Customization `flags.conf`, CHOMTE.SH allows you to customize the tool flags by editing the `flags.conf` file.


### Pulling the Docker Image

To pull the `chomtesh` image from Docker Hub, use the following command:

```bash
docker pull r12w4n/chomtesh
```

## Usage


### Running a Temporary Container (Container will be automatically deleted once the command finishes)

To run `chomtesh` in a container that removes itself after completion:

```bash
docker run --rm -it r12w4n/chomtesh ./chomte.sh -p vulnweb -d vulnweb.com -a
```

### Mapping Results to Local Machine

To execute `chomtesh` and map the `Results` directory from the container to your local machine:

```bash
docker run --rm -it -v "$(pwd)/Results:/app/chomtesh/Results" r12w4n/chomtesh ./chomte.sh -p vulnweb -d vulnweb.com -brt -ax
```

This command will create a `Results` folder in your current working directory and populate it with the results from the container.

### Using Configuration Files from the Host

If you have configuration files on your host machine that you need to use within the container:

1. **Host File Paths:**
   - `~/.config/subfinder/provider-config.yaml`
   - `$(pwd)/config.yml`

2. **Container Mapping Paths:**
   - `~/.config/subfinder/provider-config.yaml`
   - `/app/chomtesh/config.yml`

Use the following command to map these files into the container:

```bash
docker run --rm -it \
    -v ~/.config/subfinder/provider-config.yaml:~/.config/subfinder/provider-config.yaml \
    -v $(pwd)/config.yml:/app/chomtesh/config.yml \
    r12w4n/chomtesh ./chomte.sh -p vulnweb -d vulnweb.com -a
```
 

## Horizontal Recon - To gather Root / TLD using cert-knock.sh
Here are some example commands:
```
cp core/cert-knock.sh . && chmod +x cert-knock.sh
./cert-knock.sh teslaoutput tesla.com
./cert-knock.sh teslaoutput "TESLA, INC."
```
![chomtesh_crtsh](https://i.imgur.com/lVpNY6L.png)
![chomtesh_org](https://i.imgur.com/E5CO0Y4.png)
![chomtesh_org](https://i.imgur.com/qJKZMOg.png)

Read More here: [External Reconnaissance Unveiled: A Deep Dive into Domain Analysis](https://breachforce.net/external-recon-1)


## Contributions
Contributions and pull requests are highly encouraged for this project.
Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are greatly appreciated.


## Acknowledgement
The CHOMTESH project was made possible by community contributions. We acknowledge and thank all the contributors who have made this project what it is.
1. Rizwan Syed
2. Rushikesh Patil
3. Ashutosh Barot
4. Kaustubh Rai
