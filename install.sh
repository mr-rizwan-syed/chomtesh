#!/bin/bash

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

    if ! command_exists gobuster; then
        echo "${YELLOW}[*] Installing gobuster ${NC}"
        apt-get install -y gobuster &>/dev/null
    fi

    if ! command_exists pv; then
        apt-get install -y pv &>/dev/null
    fi

    if ! command_exists go; then
        echo "${YELLOW}[*] Installing go ${NC}"
        ./goinstaller.sh
        echo "${GREEN}[*] Rerun install.sh${NC}"
    fi

    if ! command_exists pup; then
         echo "${YELLOW}[*] Installing pup ${NC}"
         apt install pup -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: pup" >/dev/null
    fi

    if ! command_exists knockknock; then
         echo "${YELLOW}[*] Installing knockknock ${NC}"
         go install github.com/harleo/knockknock@latest > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: knockknock" >/dev/null
    fi

    if ! command_exists python3; then
         echo "${YELLOW}[*] Installing python3 ${NC}"
         apt install python3 -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3" >/dev/null
    fi

    if ! command_exists pip; then
        echo "${YELLOW}[*] Installing python3-pip ${NC}"
        apt install python3-pip -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3-pip" >/dev/null
    fi

    if ! command_exists git; then
        echo "${YELLOW}[*] Installing git ${NC}"
        apt install git -y 2>/dev/null | pv -p -t -e -N "Installing Tool: git" >/dev/null
    fi

    if ! command_exists nmap; then
        echo "${YELLOW}[*] Installing nmap ${NC}"
        apt install nmap -y 2>/dev/null | pv -p -t -e -N "Installing Tool: nmap" >/dev/null
    fi

    if ! command_exists xsltproc; then
        echo "${YELLOW}[*] Installing xsltproc ${NC}"
        apt install xsltproc -y 2>/dev/null | pv -p -t -e -N "Installing Tool: xsltproc" >/dev/null
    fi

    if ! command_exists dirsearch; then
        echo "${YELLOW}[*] Installing dirsearch ${NC}"
        apt install dirsearch -y 2>/dev/null | pv -p -t -e -N "Installing Tool: dirsearch" >/dev/null
    fi

    if ! command_exists ffuf; then
        echo "${YELLOW}[*] Installing FFUF ${NC}"
        go install github.com/ffuf/ffuf/v2@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: FFUF" >/dev/null
    fi

    if ! command_exists csvcut; then
        echo "${YELLOW}[*] Installing csvkit ${NC}"
        apt install csvkit -y 2>/dev/null | pv -p -t -e -N "Installing Tool: csvkit" >/dev/null
    fi

    if ! command_exists subfinder; then
        echo "${YELLOW}[*] Installing Subfinder ${NC}"
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: subfinder" >/dev/null
    fi

    if ! command_exists gau; then
        echo "${YELLOW}[*] Installing gau${NC}"
        go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: gau" >/dev/null
    fi

    if ! command_exists waybackurls; then
        echo "${YELLOW}[*] Installing waybackurls ${NC}"
        go install github.com/tomnomnom/waybackurls@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: waybackurls" >/dev/null
    fi

    if ! command_exists httpx; then
        echo "${YELLOW}[*] Installing httpx ${NC}"
        rm "$(which httpx)"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: httpx" >/dev/null
    fi

    if ! command_exists dnsx; then
        echo "${YELLOW}[*] Installing DNSx ${NC}"
        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: httpx"
    fi

    if ! command_exists anew; then
        echo "${YELLOW}[*] Installing anew ${NC}"
        go install github.com/tomnomnom/anew@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: anew" >/dev/null
    fi

    if ! command_exists gf; then
        echo "${YELLOW}[*] Installing gf ${NC}"
        go install github.com/tomnomnom/gf@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: gf" >/dev/null
        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf > /dev/null 2>&1
    fi

    if ! command_exists jsubfinder; then
        echo "${YELLOW}[*] Installing jsubfinder ${NC}"
        go install github.com/ThreatUnkown/jsubfinder@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: jsubfinder" >/dev/null
    fi

    if ! command_exists qsinject; then
        echo "${YELLOW}[*] Installing qsinject ${NC}"
        go install github.com/ameenmaali/qsinject@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: qsinject" >/dev/null
    fi

    if ! command_exists qsreplace; then
        echo "${YELLOW}[*] Installing qsreplace ${NC}"
        go install github.com/tomnomnom/qsreplace@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: qsreplace" >/dev/null
    fi

    if ! command_exists subjack; then
        echo "${YELLOW}[*] Installing subjack ${NC}"
        go install github.com/haccer/subjack@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: subjack" >/dev/null
    fi

    if ! command_exists webanalyze; then
        echo "${YELLOW}[*] Installing webanalyze ${NC}"
        go install github.com/rverton/webanalyze/cmd/webanalyze@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: webanalyze" >/dev/null
    fi

    if ! command_exists nuclei; then
        echo "${YELLOW}[*] Installing nuclei ${NC}"
        go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: nuclei" >/dev/null
        nuclei -update
    fi

    if ! command_exists dmut; then
        echo "${YELLOW}[*] Installing dmut ${NC}"
        go install github.com/bp0lr/dmut@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: dmut" >/dev/null
    fi

    if ! command_exists nuclei; then
        echo "${YELLOW}[*] Installing nuclei ${NC}"
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: nuclei"
        nuclei -update &>/dev/null
        nuclei -ut &>/dev/null
    fi

    if ! command_exists naabu; then
        echo "${YELLOW}[*] Installing naabu ${NC}"
        # go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Naabu" &>/dev/null
        # If Naabu is not getting installed by below command, download the compiled binary from official naabu github release page.
        # go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: naabu"
        wget https://github.com/projectdiscovery/naabu/releases/download/v2.1.0/naabu_2.1.0_linux_amd64.zip -P ./MISC/naabu &>/dev/null
        if ! command_exists unzip; then
            apt install unzip -y &>/dev/null
        fi
        unzip ./MISC/naabu/naabu_2.1.0_linux_amd64.zip -d ./MISC/naabu/ &>/dev/null
        mv ./MISC/naabu/naabu /usr/local/bin &>/dev/null
        sudo apt install libpcap0.8-dev libuv1-dev -y &>/dev/null
    fi

    if ! command_exists interlace; then
        echo "${YELLOW}[*] Installing Interlace ${NC}"
        [ ! -e ./MISC/Interlace/ ] && git clone https://github.com/codingo/Interlace.git ./MISC/Interlace/ 2>/dev/null | pv -p -t -e -N "Installing Tool: Interlace" &>/dev/null
        [ ! -e ./MISC/Interlace/ ] && pip3 install -r ./MISC/Interlace/requirements.txt > /dev/null 2>&1
        apt install python3-netaddr python3-tqdm -y > /dev/null 2>&1
        cd ./MISC/Interlace/ && python3 setup.py install > /dev/null 2>&1
        cd -
    fi

    if ! command_exists ansi2html; then
        echo "${YELLOW}[*] Installing ansi2html ${NC}"
        pip3 install ansi2html &>/dev/null
        sudo apt install colorized-logs &>/dev/null
    fi

    if ! command_exists subjs; then
        echo "${YELLOW}[*] Installing Subjs ${NC}"
        go install -v github.com/lc/subjs@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: subjs" &>/dev/null
    fi

    if ! command_exists katana; then
        echo "${YELLOW}[*] Installing Katana ${NC}"
        go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: katana" &>/dev/null
    fi
}

dependency_installer2(){
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
        [ ! -e /usr/local/bin/trufflehog ] && tar -xvf /tmp/trufflehog* -C /usr/local/bin/ &>/dev/null
        [ ! -e /usr/local/bin/trufflehog ] && chmod +x /usr/local/bin/trufflehog*
    fi

    if [ ! -d ./MISC/xnLinkFinder ]; then
        echo "${YELLOW}[*] Installing xnLinkFinder ${NC}"
        git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git ./MISC/xnLinkFinder &>/dev/null
        python3 ./MISC/xnLinkFinder/setup.py install &>/dev/null
    fi

    if ! command_exists ccze; then
        echo "${YELLOW}[*] Installing CCZE ${NC}"
        apt install ccze -y 2>/dev/null  | pv -p -t -e -N "Installing Tool: ccze" &>/dev/null
    fi

    [ ! -e /usr/share/dirb/wordlists/dicc.txt ] && wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -P /usr/share/dirb/wordlists/ > /dev/null 2>&1
    [ ! -e ./MISC/fingerprints.json ] && wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -P ./MISC/ > /dev/null 2>&1
    [ ! -e ~/.gf/excludeExt.json ] && cp ./MISC/excludeExt.json ~/.gf/ && exec $SHELL

}

required_tools=("gobuster" "pv" "go" "python3" "ccze" "git" "pip" "pup" "knockknock" "subfinder" "naabu" "dnsx" "httpx" "csvcut" "dmut" "dirsearch" "ffuf" "nuclei" "nmap" "ansi2html" "xsltproc" "trufflehog" "anew" "interlace" "subjs" "katana")
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
    dependency_installer2
    exit 1
else
    echo -e ""
    echo -e "${GREEN}All Good - JOD ${NC}"
fi
