#!/bin/bash
#title:         Chomtesh-Dependency-Installer


apt install python3 -y
apt install python3-pip -y
apt install git -y
apt install nmap -y
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/ameenmaali/qsinject@latest
go install github.com/tomnomnom/qsreplace@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/haccer/subjack@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/rverton/webanalyze/cmd/webanalyze@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/bp0lr/dmut@latest
go install github.com/ThreatUnkown/jsubfinder@latest
wget https://raw.githubusercontent.com/ThreatUnkown/jsubfinder/master/.jsf_signatures.yaml && mv .jsf_signatures.yaml ~/.jsf_signatures.yaml

# If Naabu is not getting installed by below command, download the compiled binary from official naabu github release page. 
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest


apt install dnsrecon -y
apt install dirsearch -y
apt install nmap -y
apt install xsltproc -y
apt install csvkit -y
pip install xmlmerge


nuclei -update
nuclei -ut 

git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

git clone https://github.com/r00tkie/grep-pattern.git /tmp/grep-pattern
mv /tmp/grep-pattern/* ~/.gf/

pip install csvkit
