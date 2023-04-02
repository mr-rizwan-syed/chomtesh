#!/bin/bash
#title:         Chomtesh-Dependency-Installer

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
NC=`tput sgr0`
wul=`tput smul`

command_exists() {
    command -v "$1" >/dev/null 2>&1
}


dependency_installer(){
    if ! command_exists pv; then
            apt-get install -y pv &>/dev/null
    fi

        if ! command_exists python3; then
            echo "${YELLOW}[*] Installing python3 ${NC}"
            apt install python3 -y  > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: python3"
        fi

    if ! command_exists python3-pip; then
        echo "${YELLOW}[*] Installing python3-pip ${NC}"
        apt install python3-pip -y  > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: python3-pip"
    fi

    if ! command_exists git; then
        echo "${YELLOW}[*] Installing git ${NC}"
        apt install git -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: git"
    fi

    if ! command_exists nmap; then
        echo "${YELLOW}[*] Installing nmap ${NC}"
        apt install nmap -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: nmap"
    fi

    if ! command_exists xsltproc; then
        echo "${YELLOW}[*] Installing xsltproc ${NC}"
        apt install xsltproc -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: xsltproc"
    fi

    if ! command_exists dirsearch; then
        echo "${YELLOW}[*] Installing dirsearch ${NC}"
        apt install dirsearch -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: dirsearch"
    fi

    if ! command_exists ffuf; then
        echo "${YELLOW}[*] Installing FFUF ${NC}"
        go install github.com/ffuf/ffuf/v2@latest
    fi

    if ! command_exists csvcut; then
        echo "${YELLOW}[*] Installing csvkit ${NC}"
        apt install csvkit -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: csvkit"
    fi

    if ! command_exists subfinder; then
        echo "${YELLOW}[*] Installing Subfinder ${NC}"
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: subfinder"
    fi

    if ! command_exists gau; then
        echo "${YELLOW}[*] Installing gau${NC}"
        go install github.com/lc/gau/v2/cmd/gau@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: gau"
    fi

    if ! command_exists waybackurls; then
        echo "${YELLOW}[*] Installing waybackurls ${NC}"
        go install github.com/tomnomnom/waybackurls@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: waybackurls"
    fi

    if ! command_exists httpx; then
        echo "${YELLOW}[*] Installing httpx ${NC}"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.2.6 > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: httpx"
    fi

    if ! command_exists anew; then
        echo "${YELLOW}[*] Installing anew ${NC}"
        go install github.com/tomnomnom/anew@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: anew"
    fi

    if ! command_exists gf; then
        echo "${YELLOW}[*] Installing gf ${NC}"
        go install github.com/tomnomnom/gf@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: gf"
        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf > /dev/null 2>&1
    fi

    if ! command_exists jsubfinder; then
        echo "${YELLOW}[*] Installing jsubfinder ${NC}"
        go install github.com/ThreatUnkown/jsubfinder@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: jsubfinder"
    fi

    if ! command_exists qsinject; then
        echo "${YELLOW}[*] Installing qsinject ${NC}"
        go install github.com/ameenmaali/qsinject@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: qsinject"
    fi

    if ! command_exists qsreplace; then
        echo "${YELLOW}[*] Installing qsreplace ${NC}"
        go install github.com/tomnomnom/qsreplace@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: qsreplace"
    fi
        
    if ! command_exists subjack; then
        echo "${YELLOW}[*] Installing subjack ${NC}"
        go install github.com/haccer/subjack@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: subjack"
    fi

    if ! command_exists webanalyze; then
        echo "${YELLOW}[*] Installing webanalyze ${NC}"
        go install github.com/rverton/webanalyze/cmd/webanalyze@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: webanalyze"
    fi    

    if ! command_exists nuclei; then
        echo "${YELLOW}[*] Installing nuclei ${NC}"
        go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: nuclei"
        nuclei -update
    fi

    if ! command_exists dmut; then
        echo "${YELLOW}[*] Installing dmut ${NC}"
        go install github.com/bp0lr/dmut@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: dmut"
    fi

    if ! command_exists nuclei; then
        echo "${YELLOW}[*] Installing nuclei ${NC}"
        go install github.com/bp0lr/dmut@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: nuclei" 
        nuclei -update &>/dev/null
        nuclei -ut &>/dev/null
    fi

    if ! command_exists naabu; then
        echo "${YELLOW}[*] Installing naabu ${NC}"
        # If Naabu is not getting installed by below command, download the compiled binary from official naabu github release page. 
        # go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: naabu"
        wget https://github.com/projectdiscovery/naabu/releases/download/v2.1.0/naabu_2.1.0_linux_amd64.zip -P ./MISC/naabu &>/dev/null
        if ! command_exists unzip; then 
            apt install unzip -y &>/dev/null
        fi
        unzip ./MISC/naabu/naabu_2.1.0_linux_amd64.zip -d ./MISC/naabu/ &>/dev/null
        mv ./MISC/naabu/naabu /usr/local/bin &>/dev/null
    fi

    if ! command_exists interlace; then
        echo "${YELLOW}[*] Installing Interlace ${NC}"
        git clone https://github.com/codingo/Interlace.git ./MISC/Interlace/ &>/dev/null
        pip3 install -r ./MISC/Interlace/requirements.txt > /dev/null 2>&1
        apt install python3-netaddr > /dev/null 2>&1
        apt install python3-tqdm > /dev/null 2>&1
        cd ./MISC/Interlace/ && python3 setup.py install && cd - > /dev/null 2>&1
    fi  

    if ! command_exists ansi2html; then
        echo "${YELLOW}[*] Installing ansi2html ${NC}"
        pip3 install ansi2html &>/dev/null
    fi

    if ! command_exists subjs; then
        echo "${YELLOW}[*] Installing Subjs ${NC}"
        go install -v github.com/lc/subjs@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: subjs" 
    fi

    if ! command_exists katana; then
        echo "${YELLOW}[*] Installing Katana ${NC}"
        go install github.com/projectdiscovery/katana/cmd/katana@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: katana" 
    fi
    
    if [ ! -d ./MISC/LinkFinder ]; then
        git clone https://github.com/GerbenJavado/LinkFinder.git ./MISC/LinkFinder &>/dev/null
        pip3 install -r ./MISC/LinkFinder/requirements.txt &>/dev/null
        python3 ./MISC/LinkFinder/setup.py install &>/dev/null
    fi

    if [ ! -d ./MISC/SecretFinder ]; then
        echo "${YELLOW}[*] Installing SecretFinder ${NC}"
        git clone https://github.com/m4ll0k/SecretFinder.git ./MISC/SecretFinder &>/dev/null
        pip3 install -r ./MISC/SecretFinder/requirements.txt &>/dev/null
    fi

    if [ ! -d ./MISC/waymore ]; then
        echo "${YELLOW}[*] Installing WayMore ${NC}"
        git clone https://github.com/xnl-h4ck3r/waymore.git ./MISC/waymore &>/dev/null
        python3 ./MISC/waymore/setup.py install &>/dev/null
    fi

    if ! command_exists trufflehog; then
        echo "${YELLOW}[*] Installing Trufflehog ${NC}"
        wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.31.2/trufflehog_3.31.2_linux_amd64.tar.gz -P /tmp/ &>/dev/null
        tar -xvf /tmp/trufflehog* -C /usr/local/bin/ &>/dev/null
        chmod +x /usr/local/bin/trufflehog
    fi

    if [ ! -d ./MISC/ ]; then
        echo "${YELLOW}[*] Installing xnLinkFinder ${NC}"
        git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git ./MISC/xnLinkFinder &>/dev/null
        python3 ./MISC/xnLinkFinder/setup.py install &>/dev/null
    fi

    if ! command_exists ccze; then
        echo "${YELLOW}[*] Installing CCZE ${NC}"
        apt install ccze > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: ccze" 
    fi

    [ ! -e ./MISC/dicc.txt ] && wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -P ./MISC/ > /dev/null 2>&1
    [ ! -e ./MISC/fingerprints.json ] && wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -P ./MISC/ > /dev/null 2>&1
    [ ! -e ~/.gf/excludeExt.json ] && cp ./MISC/excludeExt.json ~/.gf/ && exec $SHELL

}

required_tools=("go" "python3" "ccze" "git" "pip" "subfinder" "naabu" "httpx" "csvcut" "dmut" "dirsearch" "ffuf" "nuclei" "nmap" "ansi2html" "xsltproc" "trufflehog" "anew" "interlace" "subjs" "katana")
missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null 2>&1; then
        missing_tools+=("$tool")
        echo "Dependency ${RED}$tool${NC} not found..."
    else
        echo "Installed ${GREEN}$tool${NC}"
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e ""
    echo -e "${RED}[-]The following tools are not installed:${NC} ${missing_tools[*]}"
    dependency_installer
    exit 1
else
    echo -e ""
    echo -e "${GREEN}All Good - JOD ${NC}"
    echo -e "${CYAN}Run Chomte.sh Now :)${NC}"
fi



   

    









