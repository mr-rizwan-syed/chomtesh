#!/bin/bash
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
NC=$(tput sgr0)
wul=$(tput smul)

FAILED_INSTALLS=()
UPDATE_MODE=false

# Flag Parsing
while [[ $# -gt 0 ]]; do
  case $1 in
    -u|--update)
      UPDATE_MODE=true
      shift
      ;;
    *)
      shift
      ;;
  esac
done

check_exist() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    elif [ -d "$1" ] || [ -e "$1" ]; then
        return 0
    else
        return 1
    fi
}

install_apt() {
    local pkg="$1" label="${2:-$1}"
    echo -e "${YELLOW}[*] Installing $label ${NC}"
    if ! apt-get install -y "$pkg" >/dev/null 2>&1; then
        echo -e "${RED}[✘] Failed to install $label via apt${NC}"
        FAILED_INSTALLS+=("$label")
        return 1
    fi
    echo -e "${GREEN}[✔] $label installed${NC}"
}

install_go() {
    local pkg="$1" label="$2"
    echo -e "${YELLOW}[*] Installing $label ${NC}"
    if ! go install "$pkg" >/dev/null 2>&1; then
        echo -e "${RED}[✘] Failed to install $label via go install${NC}"
        FAILED_INSTALLS+=("$label")
        return 1
    fi
    echo -e "${GREEN}[✔] $label installed${NC}"
}

install_pip() {
    local pkg="$1" label="${2:-$1}"
    echo -e "${YELLOW}[*] Installing $label ${NC}"
    if ! pip3 install "$pkg" --break-system-packages >/dev/null 2>&1; then
        echo -e "${RED}[✘] Failed to install $label via pip${NC}"
        FAILED_INSTALLS+=("$label")
        return 1
    fi
    echo -e "${GREEN}[✔] $label installed${NC}"
}

install_pipx() {
    local pkg="$1" label="$2"
    echo -e "${YELLOW}[*] Installing $label via pipx ${NC}"
    
    local cmd="install"
    if [ "$UPDATE_MODE" = true ] && check_exist "$label"; then
        cmd="upgrade"
        echo -e "${YELLOW}[*] Updating $label...${NC}"
    fi

    # Handle git URLs vs package names
    # If pkg contains 'git+', use it directly for install/upgrade? pipx upgrade works on package name mostly.
    # For git+ installs, we might need 'pipx install --force ...' or 'pipx upgrade spec'.
    
    if [[ "$pkg" == "git+"* ]]; then
         # For git urls, we force install or reinstall if updating
         if [ "$UPDATE_MODE" = true ]; then
            pipx install --force "$pkg" >/dev/null 2>&1
         else
            pipx install "$pkg" >/dev/null 2>&1
         fi
    else
        # Standard package
        if pipx list | grep -q "$label"; then
             [ "$UPDATE_MODE" = true ] && pipx upgrade "$label" >/dev/null 2>&1
        else
             pipx install "$pkg" >/dev/null 2>&1
        fi
    fi

    # Verify
    if ! pipx list | grep -q "$label" && ! command -v "$label" >/dev/null 2>&1; then
         echo -e "${RED}[✘] Failed to install $label via pipx${NC}"
         FAILED_INSTALLS+=("$label")
         return 1
    fi
    echo -e "${GREEN}[✔] $label installed/updated${NC}"
}

dependency_installer(){
    # --- System packages ---
    check_exist pv      || install_apt pv
    check_exist ipcalc  || install_apt ipcalc
    check_exist python3 || install_apt python3
    check_exist pip     || install_apt python3-pip "python3-pip"
    check_exist whois   || install_apt whois
    check_exist git     || install_apt git
    check_exist jq      || install_apt jq
    check_exist tmux    || install_apt tmux
    check_exist nmap    || install_apt nmap
    check_exist xsltproc || install_apt xsltproc
    check_exist csvcut  || install_apt csvkit "csvkit"
    check_exist unzip   || install_apt unzip
    check_exist pipx    || { install_apt pipx || install_pip pipx; pipx ensurepath; }

    if ! check_exist batcat; then
        install_apt bat "BatCat"
    fi

    if ! check_exist lolcat; then
        install_apt lolcat
        [ -e /usr/games/lolcat ] && mv /usr/games/lolcat /usr/local/bin/
    fi

    if ! check_exist dirsearch; then
        install_apt dirsearch
    fi

    # --- Go (prerequisite for all go tools) ---
    if ! check_exist go; then
        echo -e "${YELLOW}[*] Installing Go ${NC}"
        if [ -f ./goinstaller.sh ]; then
            ./goinstaller.sh
            echo -e "${RED}[!] Go was just installed. Please restart your shell and rerun install.sh${NC}"
            exit 1
        else
            echo -e "${RED}[✘] goinstaller.sh not found. Install Go manually.${NC}"
            FAILED_INSTALLS+=("go")
            return 1
        fi
    fi

    # --- Go tools ---
    check_exist knockknock || install_go "github.com/harleo/knockknock@latest" "knockknock"
    check_exist dalfox     || install_go "github.com/hahwul/dalfox/v2@latest" "dalfox"
    check_exist asnmap     || install_go "github.com/projectdiscovery/asnmap/cmd/asnmap@latest" "asnmap"
    check_exist mapcidr    || install_go "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest" "mapcidr"
    check_exist ffuf       || install_go "github.com/ffuf/ffuf/v2@latest" "ffuf"
    check_exist subfinder  || install_go "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
    check_exist gau        || install_go "github.com/lc/gau/v2/cmd/gau@latest" "gau"
    check_exist waybackurls || install_go "github.com/tomnomnom/waybackurls@latest" "waybackurls"
    check_exist anew       || install_go "github.com/tomnomnom/anew@latest" "anew"
    check_exist qsinject   || install_go "github.com/ameenmaali/qsinject@latest" "qsinject"
    check_exist qsreplace  || install_go "github.com/tomnomnom/qsreplace@latest" "qsreplace"
    check_exist subjack    || install_go "github.com/haccer/subjack@latest" "subjack"
    check_exist webanalyze || install_go "github.com/rverton/webanalyze/cmd/webanalyze@latest" "webanalyze"
    check_exist subjs      || install_go "github.com/lc/subjs@latest" "subjs"
    check_exist katana     || install_go "github.com/projectdiscovery/katana/cmd/katana@latest" "katana"
    check_exist uncover    || install_go "github.com/projectdiscovery/uncover/cmd/uncover@latest" "uncover"
    check_exist alterx     || install_go "github.com/projectdiscovery/alterx/cmd/alterx@latest" "alterx"
    check_exist dnsx       || install_go "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" "dnsx"
    check_exist dmut       || { install_go "github.com/bp0lr/dmut@latest" "dmut" && dmut --update-files &>/dev/null; }
    check_exist jsleak     || install_go "github.com/0xTeles/jsleak/v2/jsleak@latest" "jsleak"
    check_exist wappscan   || install_go "github.com/mr-rizwan-syed/wappscan@latest" "wappscan"

    if ! check_exist httpx; then
        rm "$(which httpx)" 2>/dev/null
        install_go "github.com/projectdiscovery/httpx/cmd/httpx@latest" "httpx"
    fi
    if ! check_exist tlsx; then
        install_go "github.com/projectdiscovery/tlsx/cmd/tlsx@latest" "tlsx"
    fi

    if ! check_exist nuclei; then
        install_go "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" "nuclei"
        nuclei -update &>/dev/null
        nuclei -ut &>/dev/null
    fi

    if ! check_exist naabu; then
        sudo apt-get install -y libpcap0.8-dev libuv1-dev >/dev/null 2>&1
        install_go "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "naabu"
    fi

    if ! check_exist gf; then
        install_go "github.com/tomnomnom/gf@latest" "gf"
        [ ! -d ~/.gf ] && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf >/dev/null 2>&1
    fi

    # --- massdns + puredns ---
    if ! check_exist massdns; then
        echo -e "${YELLOW}[*] Installing massdns ${NC}"
        local massdns_tmp="/tmp/massdns_build_$$"
        if git clone https://github.com/blechschmidt/massdns.git "$massdns_tmp" >/dev/null 2>&1 \
           && make -C "$massdns_tmp" >/dev/null 2>&1 \
           && sudo make -C "$massdns_tmp" install >/dev/null 2>&1; then
            echo -e "${GREEN}[✔] massdns installed${NC}"
        else
            echo -e "${RED}[✘] Failed to install massdns${NC}"
            FAILED_INSTALLS+=("massdns")
        fi
        rm -rf "$massdns_tmp"
    fi

    if ! check_exist puredns; then
        install_go "github.com/d3mondev/puredns/v2@latest" "puredns"
    fi

    # --- Python tools ---
    check_exist shodan   || install_pip shodan "Shodan CLI"
    check_exist ansi2html || {
        install_pip ansi2html
        sudo apt-get install -y colorized-logs >/dev/null 2>&1
    }

    # --- Interlace (requires git clone + setup.py) ---
    if ! check_exist interlace; then
        echo -e "${YELLOW}[*] Installing Interlace ${NC}"
        if [ ! -d ./MISC/Interlace ]; then
            git clone https://github.com/codingo/Interlace.git ./MISC/Interlace >/dev/null 2>&1
        fi
        if [ -d ./MISC/Interlace ]; then
            pip3 install -r ./MISC/Interlace/requirements.txt --break-system-packages >/dev/null 2>&1
            apt-get install -y python3-netaddr python3-tqdm >/dev/null 2>&1
            (cd ./MISC/Interlace && python3 setup.py install >/dev/null 2>&1)
            if check_exist interlace; then
                echo -e "${GREEN}[✔] Interlace installed${NC}"
            else
                echo -e "${RED}[✘] Failed to install Interlace${NC}"
                FAILED_INSTALLS+=("interlace")
            fi
        fi
    fi

    # --- ccze ---
    if ! check_exist ccze; then
        echo -e "${YELLOW}[*] Installing ccze ${NC}"
        if [ -f ./MISC/ccze ]; then
            cp ./MISC/ccze /usr/local/bin/ && chmod +x /usr/local/bin/ccze
            echo -e "${GREEN}[✔] ccze installed${NC}"
        else
            echo -e "${RED}[✘] ./MISC/ccze not found${NC}"
            FAILED_INSTALLS+=("ccze")
        fi
    fi

    # --- trufflehog ---
    if ! check_exist trufflehog; then
        echo -e "${YELLOW}[*] Installing Trufflehog ${NC}"
        if wget -q https://github.com/trufflesecurity/trufflehog/releases/download/v3.31.2/trufflehog_3.31.2_linux_amd64.tar.gz -P /tmp/; then
            tar -xf /tmp/trufflehog_3.31.2_linux_amd64.tar.gz -C /usr/local/bin/ >/dev/null 2>&1
            chmod +x /usr/local/bin/trufflehog 2>/dev/null
            echo -e "${GREEN}[✔] Trufflehog installed${NC}"
        else
            echo -e "${RED}[✘] Failed to download Trufflehog${NC}"
            FAILED_INSTALLS+=("trufflehog")
        fi
    fi

    # --- Git-cloned Python tools ---
    if ! check_exist ./MISC/LinkFinder; then
        echo -e "${YELLOW}[*] Installing LinkFinder ${NC}"
        if git clone https://github.com/GerbenJavado/LinkFinder.git ./MISC/LinkFinder >/dev/null 2>&1; then
            pip3 install -r ./MISC/LinkFinder/requirements.txt --break-system-packages >/dev/null 2>&1
            python3 ./MISC/LinkFinder/setup.py install >/dev/null 2>&1
            echo -e "${GREEN}[✔] LinkFinder installed${NC}"
        else
            echo -e "${RED}[✘] Failed to clone LinkFinder${NC}"
            FAILED_INSTALLS+=("LinkFinder")
        fi
    fi

    if ! check_exist ./MISC/SecretFinder; then
        echo -e "${YELLOW}[*] Installing SecretFinder ${NC}"
        if git clone https://github.com/m4ll0k/SecretFinder.git ./MISC/SecretFinder >/dev/null 2>&1; then
            pip3 install -r ./MISC/SecretFinder/requirements.txt --break-system-packages >/dev/null 2>&1
            echo -e "${GREEN}[✔] SecretFinder installed${NC}"
        else
            echo -e "${RED}[✘] Failed to clone SecretFinder${NC}"
            FAILED_INSTALLS+=("SecretFinder")
        fi
    fi

    # --- Pipx Tools (Waymore, xnLinkFinder) ---
    install_pipx "git+https://github.com/xnl-h4ck3r/waymore.git" "waymore"
    install_pipx "xnLinkFinder" "xnLinkFinder"

    if ! check_exist ./MISC/fuzzing-templates; then
        echo -e "${YELLOW}[*] Installing fuzzing-templates ${NC}"
        if git clone https://github.com/projectdiscovery/fuzzing-templates.git ./MISC/fuzzing-templates >/dev/null 2>&1; then
            echo -e "${GREEN}[✔] fuzzing-templates installed${NC}"
        else
            echo -e "${RED}[✘] Failed to clone fuzzing-templates${NC}"
            FAILED_INSTALLS+=("fuzzing-templates")
        fi
    fi

    # --- Static file downloads ---
    check_exist "/usr/share/dirb/wordlists/dicc.txt" || wget -q https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -P /usr/share/dirb/wordlists/
    check_exist "./MISC/fingerprints.json" || wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -P ./MISC/
    check_exist "./MISC/technologies.json" || wget -q https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json -P ./MISC/
    check_exist "$HOME/.gf/excludeExt.json" || cp ./MISC/excludeExt.json "$HOME/.gf/"
}

# ========================= MAIN =========================

required_tools=("pv" "go" "python3" "ccze" "uncover" "tmux" "git" "pip" "knockknock" "subfinder" "ipcalc" "asnmap" "naabu" "dnsx" "httpx" "csvcut" "dmut" "dirsearch" "ffuf" "shodan" "nuclei" "nmap" "ansi2html" "xsltproc" "trufflehog" "anew" "interlace" "subjs" "katana" "alterx" "dalfox" "massdns" "puredns" "pipx" "waymore" "xnLinkFinder" "jsleak" "wappscan")
required_directories=(
    "./MISC/LinkFinder"
    "./MISC/SecretFinder"
    "./MISC/fuzzing-templates"
    "./MISC/fingerprints.json"
    "./MISC/technologies.json"
    "$HOME/.gf/excludeExt.json"
    "/usr/share/dirb/wordlists/dicc.txt"
)

# Start Install / Check 
# If -u provided, we run dependency_installer anyway to trigger updates
if [ "$UPDATE_MODE" = true ]; then
    echo -e "${BLUE}[*] Update Mode Enabled (-u). Forcing checks and updates...${NC}"
    dependency_installer
fi

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
    echo -e "${RED}[-] The following tools are not installed:${NC} ${missing_tools[*]}"
    
    # Only run if we haven't already run it via -u
    if [ "$UPDATE_MODE" = false ]; then
         dependency_installer
    fi

    # Report any failures
    if [ ${#FAILED_INSTALLS[@]} -ne 0 ]; then
        echo -e ""
        echo -e "${RED}[✘] The following tools failed to install:${NC}"
        for fail in "${FAILED_INSTALLS[@]}"; do
            echo -e "  ${RED}• $fail${NC}"
        done
    fi
    echo -e "${MAGENTA}\n[-] Re-run the installation script to check what else is pending: $0 \n${NC}"
    exit 1
else
    echo -e "${CYAN}${wul}\nAll Good - JOD\n${NC}"
    # Reminder for pipx path
    echo -e "${YELLOW}[!] If you just installed pipx tools, you may need to run: source ~/.bashrc${NC}"
    exec "$SHELL" && exit
fi
