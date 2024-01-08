#!/bin/bash
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
NC=`tput sgr0`
wul=`tput smul`

check_exist() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    elif [ -d "$1" ] || [ -e "$1" ]; then
        return 0
    else
        return 1
    fi
}

dependency_installer(){
    if ! check_exist pv; then
        apt-get install -y pv &>/dev/null
    fi
    if ! check_exist ipcalc; then
        apt-get install -y ipcalc &>/dev/null
    fi
    if ! check_exist go; then
        echo "${YELLOW}[*] Installing go ${NC}"
        ./goinstaller.sh
        echo "${GREEN}[*] Rerun install.sh${NC}"
    fi
    if ! check_exist knockknock; then
        echo "${YELLOW}[*] Installing knockknock ${NC}"
        go install github.com/harleo/knockknock@latest > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: knockknock" >/dev/null
    fi
    if ! check_exist python3; then
        echo "${YELLOW}[*] Installing python3 ${NC}"
        apt install python3 -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3" >/dev/null
    fi
    if ! check_exist pip; then
        echo "${YELLOW}[*] Installing python3-pip ${NC}"
        apt install python3-pip -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3-pip" >/dev/null
    fi
    if ! check_exist whois; then
        echo "${YELLOW}[*] Installing whois ${NC}"
        apt install whois -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: Whois" >/dev/null
    fi
    if ! check_exist git; then
        echo "${YELLOW}[*] Installing git ${NC}"
        apt install git -y 2>/dev/null | pv -p -t -e -N "Installing Tool: git" >/dev/null
    fi
    if ! check_exist jq; then
        echo "${YELLOW}[*] Installing jq ${NC}"
        apt install jq -y 2>/dev/null | pv -p -t -e -N "Installing Tool: jq" >/dev/null
    fi
    if ! check_exist dalfox; then
        echo "${YELLOW}[*] Installing dalfox ${NC}"
        go install github.com/hahwul/dalfox/v2@latest > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: dalfox" >/dev/null
    fi
    if ! check_exist lolcat; then
        echo "${YELLOW}[*] Installing lolcat ${NC}"
        apt install lolcat -y 2>/dev/null | pv -p -t -e -N "Installing Tool: lolcat" >/dev/null
        [ -e /usr/games/lolcat ] && mv /usr/games/lolcat /usr/local/bin/
    fi
    if ! check_exist nmap; then
        echo "${YELLOW}[*] Installing nmap ${NC}"
        apt install nmap -y 2>/dev/null | pv -p -t -e -N "Installing Tool: nmap" >/dev/null
    fi
    if ! check_exist asnmap; then
        echo "${YELLOW}[*] Installing ASNmap ${NC}"
        go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: ASNmap" >/dev/null
    fi
    if ! check_exist mapcidr; then
        echo "${YELLOW}[*] Installing mapCIDR ${NC}"
        go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: mapCIDR" >/dev/null
    fi
    if ! check_exist xsltproc; then
        echo "${YELLOW}[*] Installing xsltproc ${NC}"
        apt install xsltproc -y 2>/dev/null | pv -p -t -e -N "Installing Tool: xsltproc" >/dev/null
    fi
    if ! check_exist dirsearch; then
        echo "${YELLOW}[*] Installing dirsearch ${NC}"
        apt install dirsearch -y 2>/dev/null | pv -p -t -e -N "Installing Tool: dirsearch" >/dev/null
    fi
    if ! check_exist ffuf; then
        echo "${YELLOW}[*] Installing FFUF ${NC}"
        go install github.com/ffuf/ffuf/v2@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: FFUF" >/dev/null
    fi
    if ! check_exist csvcut; then
        echo "${YELLOW}[*] Installing csvkit ${NC}"
        apt install csvkit -y 2>/dev/null | pv -p -t -e -N "Installing Tool: csvkit" >/dev/null
    fi
    if ! check_exist subfinder; then
        echo "${YELLOW}[*] Installing Subfinder ${NC}"
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: subfinder" >/dev/null
    fi
    if ! check_exist gau; then
        echo "${YELLOW}[*] Installing gau${NC}"
        go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: gau" >/dev/null
    fi
    if ! check_exist waybackurls; then
        echo "${YELLOW}[*] Installing waybackurls ${NC}"
        go install github.com/tomnomnom/waybackurls@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: waybackurls" >/dev/null
    fi
    if ! check_exist httpx; then
        echo "${YELLOW}[*] Installing httpx ${NC}"
        rm "$(which httpx)" 2>/dev/null
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: httpx" >/dev/null
    fi
    if ! check_exist tlsx; then
        echo "${YELLOW}[*] Installing TLSx ${NC}"
        go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: TLSx" >/dev/null
    fi
    if ! check_exist alterx; then
        echo "${YELLOW}[*] Installing AlterX ${NC}"
        go install github.com/projectdiscovery/alterx/cmd/alterx@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: AlterX"
    fi
    
    if ! check_exist dnsx; then
        echo "${YELLOW}[*] Installing DNSx ${NC}"
        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest > /dev/null 2>&1 | pv -p -t -e -N "Installing Tool: DNSx"
    fi
    if ! check_exist anew; then
        echo "${YELLOW}[*] Installing anew ${NC}"
        go install github.com/tomnomnom/anew@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: anew" >/dev/null
    fi
    if ! check_exist gf; then
        echo "${YELLOW}[*] Installing gf ${NC}"
        go install github.com/tomnomnom/gf@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: gf" >/dev/null
        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf > /dev/null 2>&1
    fi
    if ! check_exist qsinject; then
        echo "${YELLOW}[*] Installing qsinject ${NC}"
        go install github.com/ameenmaali/qsinject@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: qsinject" >/dev/null
    fi
    if ! check_exist qsreplace; then
        echo "${YELLOW}[*] Installing qsreplace ${NC}"
        go install github.com/tomnomnom/qsreplace@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: qsreplace" >/dev/null
    fi
    if ! check_exist subjack; then
        echo "${YELLOW}[*] Installing subjack ${NC}"
        go install github.com/haccer/subjack@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: subjack" >/dev/null
    fi
    if ! check_exist webanalyze; then
        echo "${YELLOW}[*] Installing webanalyze ${NC}"
        go install github.com/rverton/webanalyze/cmd/webanalyze@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: webanalyze" >/dev/null
    fi
    if ! check_exist nuclei; then
        echo "${YELLOW}[*] Installing nuclei ${NC}"
        go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: nuclei" >/dev/null
        nuclei -update
    fi
    if ! check_exist dmut; then
        echo "${YELLOW}[*] Installing dmut ${NC}"
        go install github.com/bp0lr/dmut@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: dmut" >/dev/null
        dmut --update-files &>/dev/null
    fi
    if ! check_exist nuclei; then
        echo "${YELLOW}[*] Installing nuclei ${NC}"
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: nuclei"
        nuclei -update &>/dev/null
        nuclei -ut &>/dev/null
    fi
    if ! check_exist naabu; then
        echo "${YELLOW}[*] Installing naabu ${NC}"
        # go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Naabu" &>/dev/null
        # If Naabu is not getting installed by below command, download the compiled binary from official naabu github release page.
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: naabu" >/dev/null
        #rm "$(which naabu)" 2>/dev/null
        #wget https://github.com/projectdiscovery/naabu/releases/download/v2.1.0/naabu_2.1.0_linux_amd64.zip -P ./MISC/naabu &>/dev/null
        if ! check_exist unzip; then
            apt install unzip -y &>/dev/null
        fi
        #unzip ./MISC/naabu/naabu_2.1.0_linux_amd64.zip -d ./MISC/naabu/ &>/dev/null
        #mv ./MISC/naabu/naabu /usr/local/bin &>/dev/null
        sudo apt install libpcap0.8-dev libuv1-dev -y &>/dev/null
    fi
    if ! check_exist interlace; then
        echo "${YELLOW}[*] Installing Interlace ${NC}"
        [ ! -e ./MISC/Interlace/ ] && git clone https://github.com/codingo/Interlace.git ./MISC/Interlace/ 2>/dev/null | pv -p -t -e -N "Installing Tool: Interlace" &>/dev/null
        [ ! -e ./MISC/Interlace/ ] && pip3 install -r ./MISC/Interlace/requirements.txt > /dev/null 2>&1
        apt install python3-netaddr python3-tqdm -y > /dev/null 2>&1
        cd ./MISC/Interlace/ && python3 setup.py install > /dev/null 2>&1
        cd -
    fi
    if ! check_exist ansi2html; then
        echo "${YELLOW}[*] Installing ansi2html ${NC}"
        pip3 install ansi2html &>/dev/null
        sudo apt install colorized-logs &>/dev/null
    fi
    if ! check_exist shodan; then
        echo "${YELLOW}[*] Installing Shodan ${NC}"
        apt install python3-shodan -y &>/dev/null
    fi
    if ! check_exist subjs; then
        echo "${YELLOW}[*] Installing Subjs ${NC}"
        go install -v github.com/lc/subjs@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: subjs" &>/dev/null
    fi
    if ! check_exist katana; then
        echo "${YELLOW}[*] Installing Katana ${NC}"
        go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: katana" &>/dev/null
    fi
    if ! check_exist ccze; then
        echo "${YELLOW}[*] Installing CCZE ${NC}"
        #apt install ccze -y 2>/dev/null  | pv -p -t -e -N "Installing Tool: ccze" &>/dev/null
        cp ./MISC/ccze /usr/local/bin/ && chmod +x /usr/local/bin/ccze
    fi
    if ! check_exist ./MISC/LinkFinder; then
        git clone https://github.com/GerbenJavado/LinkFinder.git ./MISC/LinkFinder &>/dev/null
        pip3 install -r ./MISC/LinkFinder/requirements.txt &>/dev/null
        python3 ./MISC/LinkFinder/setup.py install &>/dev/null
    fi
    if ! check_exist ./MISC/SecretFinder; then
        echo "${YELLOW}[*] Installing SecretFinder ${NC}"
        git clone https://github.com/m4ll0k/SecretFinder.git ./MISC/SecretFinder &>/dev/null
        pip3 install -r ./MISC/SecretFinder/requirements.txt &>/dev/null
    fi
    if ! check_exist ./MISC/waymore; then
        echo "${YELLOW}[*] Installing WayMore ${NC}"
        pip install pyyaml &>/dev/null
        git clone https://github.com/xnl-h4ck3r/waymore.git ./MISC/waymore &>/dev/null
        python3 ./MISC/waymore/setup.py install &>/dev/null
        apt install python3-termcolor -y &>/dev/null
    fi
    if ! check_exist trufflehog; then
        echo "${YELLOW}[*] Installing Trufflehog ${NC}"
        wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.31.2/trufflehog_3.31.2_linux_amd64.tar.gz -P /tmp/ &>/dev/null
        [ ! -e /usr/local/bin/trufflehog ] && tar -xvf /tmp/trufflehog* -C /usr/local/bin/ &>/dev/null
        [ ! -e /usr/local/bin/trufflehog ] && chmod +x /usr/local/bin/trufflehog*
    fi
    if ! check_exist ./MISC/xnLinkFinder; then
        echo "${YELLOW}[*] Installing xnLinkFinder ${NC}"
        git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git ./MISC/xnLinkFinder &>/dev/null
        python3 ./MISC/xnLinkFinder/setup.py install &>/dev/null
    fi
    if ! check_exist ./MISC/fuzzing-templates; then
        echo "${YELLOW}[*] Installing xnLinkFinder ${NC}"
        git clone https://github.com/projectdiscovery/fuzzing-templates.git ./MISC/fuzzing-templates &>/dev/null
    fi
    check_exist "/usr/share/dirb/wordlists/dicc.txt" || wget -q https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -P /usr/share/dirb/wordlists/
    check_exist "./MISC/fingerprints.json" || wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -P ./MISC/
    check_exist "./MISC/technologies.json" || wget -q https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json -P ./MISC/
    check_exist "$HOME/.gf/excludeExt.json" || cp ./MISC/excludeExt.json "$HOME/.gf/"
}
required_tools=("pv" "go" "python3" "ccze" "git" "pip" "knockknock" "subfinder" "ipcalc" "asnmap" "naabu" "dnsx" "httpx" "csvcut" "dmut" "dirsearch" "ffuf" "shodan" "nuclei" "nmap" "ansi2html" "xsltproc" "trufflehog" "anew" "interlace" "subjs" "katana" "alterx" "dalfox")
required_directories=(
    "./MISC/LinkFinder"
    "./MISC/SecretFinder"
    "./MISC/waymore"
    "./MISC/xnLinkFinder"
    "./MISC/fuzzing-templates"
    "./MISC/fingerprints.json"
    "./MISC/technologies.json"
    "$HOME/.gf/excludeExt.json"
    "/usr/share/dirb/wordlists/dicc.txt"
)
missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! check_exist "$tool"; then
        missing_tools+=("$tool")
        echo "Dependency ${RED}$tool${NC} not found..."
    else
        echo "Installed ${GREEN}$tool${NC}"
    fi
done
for directory in "${required_directories[@]}"; do
    if ! check_exist "$directory"; then
        echo "${YELLOW}[*] Required Directory ${NC}$directory${YELLOW} does not exist.${NC}"
        missing_tools+=("$directory")
        echo "Dependency ${RED}$directory${NC} not found..."
    else
        echo "Installed ${GREEN}$directory${NC}"
    fi
done
if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e ""
    echo -e "${RED}[-]The following tools are not installed:${NC} ${missing_tools[*]}"
    dependency_installer
    echo -e "${MAGENTA}\n[-]Re-Run the Installation script to check what else pending...$0 \n${NC}"
    exit 1
else
    echo -e "${CYAN}${wul}\nAll Good - JOD\n${NC}"
    exec "$SHELL" && exit
fi
