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
    if ! command_exists python3; then
        echo "Installing python3"
        apt install python3 -y  > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: python3"
    fi

    if ! command_exists python3-pip; then
        echo "Installing python3-pip"
        apt install python3-pip -y  > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: python3-pip"
    fi

    if ! command_exists git; then
        echo "Installing git"
        apt install git -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: git"
    fi

    if ! command_exists nmap; then
        echo "Installing nmap"
        apt install nmap -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: nmap"
    fi

    if ! command_exists xsltproc; then
        echo "Installing xsltproc"
        apt install xsltproc -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: xsltproc"
    fi

    if ! command_exists dirsearch; then
        echo "Installing dirsearch"
        apt install dirsearch -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: dirsearch"
    fi

    if ! command_exists ffuf; then
        echo "Installing FFUF"
        go install github.com/ffuf/ffuf/v2@latest
    fi

    if ! command_exists csvcut; then
        echo "Installing csvkit"
        apt install csvkit -y > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: csvkit"
    fi

    if ! command_exists subfinder; then
        echo "Installing Subfinder"
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: subfinder"
    fi

    if ! command_exists gau; then
        echo "Installing gau"
        go install github.com/lc/gau/v2/cmd/gau@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: gau"
    fi

    if ! command_exists waybackurls; then
        echo "Installing waybackurls"
        go install github.com/tomnomnom/waybackurls@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: waybackurls"
    fi

    if ! command_exists httpx; then
        echo "Installing httpx"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.2.6 > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: httpx"
    fi

    if ! command_exists anew; then
        echo "Installing anew"
        go install github.com/tomnomnom/anew@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: anew"
    fi

    if ! command_exists gf; then
        echo "Installing gf"
        go install github.com/tomnomnom/gf@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: gf"
        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
        cp ./MISC/excludeExt ~/.gf/
        exec $SHELL
    fi

    if ! command_exists anew; then
        echo "Installing anew"
        go install github.com/tomnomnom/anew@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: anew"
    fi

    if ! command_exists qsinject; then
        echo "Installing qsinject"
        go install github.com/ameenmaali/qsinject@latestt > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: qsinject"
    fi

    if ! command_exists qsreplace; then
        echo "Installing qsreplace"
        go install github.com/tomnomnom/qsreplace@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: qsreplace"
    fi
        
    if ! command_exists subjack; then
        echo "Installing subjack"
        go install github.com/haccer/subjack@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: subjack"
    fi

    if ! command_exists webanalyze; then
        echo "Installing webanalyze"
        go install github.com/rverton/webanalyze/cmd/webanalyze@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: webanalyze"
    fi    

    if ! command_exists nuclei; then
        echo "Installing nuclei"
        go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: nuclei"
        nuclei -update
    fi

    if ! command_exists dmut; then
        echo "Installing dmut"
        go install github.com/bp0lr/dmut@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: dmut"
    fi

    if ! command_exists nuclei; then
        echo "Installing nuclei"
        go install github.com/bp0lr/dmut@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: nuclei" 
        nuclei -update &>/dev/null
        nuclei -ut &>/dev/null
    fi

    if ! command_exists naabu; then
        echo "Installing naabu"
        # If Naabu is not getting installed by below command, download the compiled binary from official naabu github release page. 
        # go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: naabu"
        wget https://github.com/projectdiscovery/naabu/releases/download/v2.1.0/naabu_2.1.0_linux_amd64.zip -P /opt/tools/naabu &>/dev/null
        unzip /opt/tools/naabu/naabu_2.1.2_linux_amd64.zip -d /opt/tools/naabu &>/dev/null
        mv /opt/tools/naabu/naabu /usr/local/bin &>/dev/null
    fi

    if ! command_exists interlace; then
        echo "Installing Interlace"
        git clone https://github.com/codingo/Interlace.git ./MISC/Interlace/ &>/dev/null
        pip3 install -r ./MISC/Interlace/requirements.txt &>/dev/null
        apt install python3-netaddr &>/dev/null
        apt install python3-tqdm &>/dev/null
        python3 ./MISC/Interlace/setup.py install &>/dev/null
    fi  

    if ! command_exists ansi2html; then
        pip3 install ansi2html &>/dev/null
    fi

    if ! command_exists subjs; then
        go install -v github.com/lc/subjs@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: subjs" 
    fi

    if ! command_exists katana; then
        go install github.com/projectdiscovery/katana/cmd/katana@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: katana" 
    fi
    
    if [ ! -d ./MISC/LinkFinder ]; then
        git clone https://github.com/GerbenJavado/LinkFinder.git ./MISC/LinkFinder &>/dev/null
        pip3 install -r ./MISC/LinkFinder/requirements.txt &>/dev/null
        python3 ./MISC/LinkFinder/setup.py install &>/dev/null
    fi

    if [ ! -d ./MISC/SecretFinder ]; then
        git clone https://github.com/m4ll0k/SecretFinder.git ./MISC/SecretFinder &>/dev/null
        pip3 install -r ./MISC/SecretFinder/requirements.txt &>/dev/null
    fi

    if [ ! -d ./MISC/waymore ]; then
        git clone https://github.com/xnl-h4ck3r/waymore.git ./MISC/waymore
        python3 ./MISC/waymore/setup.py install
    fi

    if [ ! -d ./MISC/xnLinkFinder ]; then
        git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git ./MISC/xnLinkFinder
        python3 ./MISC/xnLinkFinder/setup.py install
    fi


}

required_tools=("go" "python3" "git" "pip" "subfinder" "naabu" "httpx" "csvcut" "dmut" "dirsearch" "ffuf" "nuclei" "nmap" "ansi2html" "xsltproc" "anew" "interlace" "subjs" "katana")
missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null 2>&1; then
        missing_tools+=("$tool")
        echo "Dependency '$tool' not found, installing..."
        if ! command_exists pv; then
            apt-get install -y pv &>/dev/null
        fi
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e ""
    echo -e "${RED}[-]The following tools are not installed:${NC} ${missing_tools[*]}"
    dependency_installer
    wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -P ./MISC/ > /dev/null 2>&1
    exit 1
else
    echo -e ""
    echo -e "${GREEN}All Good - JOD ${NC}"
    echo -e "${CYAN}Run Chomte.sh Now :)"
fi



   

    









