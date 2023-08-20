#!/bin/bash
#title: certpolice.sh
#description:   Certificate Transparency Monitoring
#author:        mr-rizwan-syed | @_r12w4n
#version:       1.0.0
#==============================================================================

RED=`tput setaf 1`
GREEN=`tput setaf 2`
MAGENTA=`tput setaf 5`
BLUE=`tput setaf 4`
NC=`tput sgr0`

function cleanup() {
  echo "Cleaning up before exit"
  exit 0
}

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
    if ! check_exist anew; then
        echo "${YELLOW}[*] Installing anew ${NC}"
        go install github.com/tomnomnom/anew@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: anew" >/dev/null
    fi
    if ! check_exist python3; then
        echo "${YELLOW}[*] Installing python3 ${NC}"
        apt install python3 -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3" >/dev/null
    fi
    if ! check_exist pip; then
        echo "${YELLOW}[*] Installing python3-pip ${NC}"
        apt install python3-pip -y > /dev/null 2>/dev/null | pv -p -t -e -N "Installing Tool: python3-pip" >/dev/null
    fi
    if ! check_exist jq; then
        echo "${YELLOW}[*] Installing jq ${NC}"
        apt install jq -y 2>/dev/null | pv -p -t -e -N "Installing Tool: jq" >/dev/null
    fi
    if ! check_exist certspotter; then
        echo "${YELLOW}[*] Installing certspotter ${NC}"
	pip install certspotter 2>/dev/null | pv -p -t -e -N "Installing Tool: certspotter" >/dev/null
    fi
    if ! check_exist notify; then
        echo "${YELLOW}[*] Installing jq ${NC}"
        go install -v github.com/projectdiscovery/notify/cmd/notify@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: Notify" >/dev/null
    fi
    if ! check_exist tlsx; then
        echo "${YELLOW}[*] Installing jq ${NC}"
        go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest 2>/dev/null | pv -p -t -e -N "Installing Tool: TLSx" >/dev/null
    fi

}

required_tools=("pv" "anew" "python3" "pip" "jq" "certspotter" "notify" "tlsx")

missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! check_exist "$tool"; then
        missing_tools+=("$tool")
        echo "Dependency ${RED}$tool${NC} not found..."
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e ""
    echo -e "${RED}[-]The following tools are not installed:${NC} ${missing_tools[*]}"
    dependency_installer
    exit 1
fi

banner(){
echo -e '
 ██████╗███████╗██████╗ ████████╗   ██████╗  ██████╗ ██╗     ██╗ ██████╗███████╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝   ██╔══██╗██╔═══██╗██║     ██║██╔════╝██╔════╝
██║     █████╗  ██████╔╝   ██║█████╗██████╔╝██║   ██║██║     ██║██║     █████╗  
██║     ██╔══╝  ██╔══██╗   ██║╚════╝██╔═══╝ ██║   ██║██║     ██║██║     ██╔══╝  
╚██████╗███████╗██║  ██║   ██║      ██║     ╚██████╔╝███████╗██║╚██████╗███████╗
 ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝╚══════╝'
echo -e "Certificate Transparency Monitoring @_r12w4n"
echo -e
}

trap cleanup SIGINT

# Initialize variables
silent=false
notify=false

# Python function to extract and parse subdomains
parse_results() {
    all_domains_found=("$@")
    seen_domains=()

    for subdomain in "${all_domains_found[@]}"; do
        for domain in "${domains[@]}"; do
            if [[ $subdomain == *$domain* ]]; then
                # removing wildcards
                if [[ $subdomain == "*"* ]]; then
                    seen_domains+=("${subdomain:2}")
                else
                    seen_domains+=("$subdomain")
                fi
                break
            fi
        done
    done

    # we have a list of found domains now (which might be containing some duplicate entries)
    # Lets get rid of duplicate entries
    unique_subdomains=($(echo "${seen_domains[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

    # checking if domain already exists in already seen file
    for host in "${unique_subdomains[@]}"; do
    	[[ ${silent} == true ]] && echo -e "$host" || echo -e "${GREEN}[MATCH]${NC} : tlsx -u $host -silent -cn)
    	echo -e "$(date +'%Y-%m-%d') $host" | anew -q "$output_file"
    	[[ ${notify} == true ]] && echo -e "$host" | notify -silent >/dev/null 2>&1
    done

}

# Start CertStream monitor and process JSON output with callback
print_callback() {
    while IFS= read -r line; do
        if [[ $line == *"message_type"*"\"heartbeat\""* ]]; then
            continue
        fi

        if [[ $line == *"message_type"*"\"certificate_update\""* ]]; then
            all_domains=($(echo "$line" | jq -r '.data.leaf_cert.all_domains[]'))
            if [[ ${#all_domains[@]} -eq 0 ]]; then
                continue
            else
                parse_results "${all_domains[@]}"
            fi
        fi
    done
}

# Start CertStream monitor and process JSON output with callback

function initiate(){
	# Output file for saving subdomains
	output_file="found_subdomains.txt"
	[[ ${silent} == false ]] && banner
	# Read target domains from the file
	[[ -f "$target" && -s "$target" ]] && declare -a domains=($(cat "$target")) || { echo -e ${MAGENTA}"Target file issue: File does not exist or is empty.${NC}"; exit 1; }
	[[ ${silent} == false ]] && echo -e "${BLUE}[INFO]${NC} No. of domains/Keywords to monitor ${#domains[@]}"
	[[ ${silent} == false && "$notify" == true ]] && echo -e "${BLUE}[INFO]${NC} Notify is enabled"
	# Start CertStream monitor and process JSON output with callback
	certstream --url "wss://certstream.calidog.io/" --full --json 2>/dev/null| print_callback
}

print_usage() {
	banner
	echo $0 --silent --notify --target targets.txt
	echo $0 -s -n -t targets.txt
	echo $0 --add "STRING" --target  targets.txt
	echo $0 -a "STRING" -t targets.txt
}


while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      print_usage
      exit
      ;;
    -s|--silent)
      silent=true
      shift
      ;;
    -n|--notify)
      notify=true
      shift
      ;;
    -t|--target)
      target="$2"
      initiate
      shift 2
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      break # Exit the option processing loop
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [[ ! -n $1 ]]; then
    print_usage
fi
