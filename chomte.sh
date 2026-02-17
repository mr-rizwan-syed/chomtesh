#!/bin/bash
#title: CHOMTE.SH
#description:   Automated and Modular Framework to Gather Attack Surface & Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed | rushikeshhh-patil
#version:       5.2.0
#==============================================================================

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
NC=`tput sgr0`
BOLD='\033[1m'
wul=`tput smul`
black='\e[38;5;016m'
bluebg='\e[1;44m'
greenbg='\e[1;32m'
yellowbg='\e[1;33m'
redbg='\e[1;31m'
right=$(printf '\u2714')
cross=$(printf '\u2718')
upper="${lightblue}╔$(printf '%.0s═' $(seq "80"))╗${end}"
lower="${lightblue}╚$(printf '%.0s═' $(seq "80"))╝${end}"

export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CORE_DIR="$SCRIPT_DIR/core"
export MISC_DIR="$SCRIPT_DIR/MISC"
core="$CORE_DIR"
ORIGINAL_ARGS=("$@")

# for script_file in "$core"/*.sh; do
#     source "$script_file"
# done

source $core/gatherSubdomains.sh
source $core/bruteSubdomains.sh
source $core/subdomainTKO.sh
source $core/resolveDNS.sh
source $core/portScanner.sh
source $core/nmapScanner.sh
source $core/probeHttp.sh
source $core/contentDiscovery.sh
source $core/techDetection.sh
source $core/activeRecon.sh
source $core/urlRecon.sh
source $core/hostdiscovery.sh
source $core/enumVuln.sh
source $core/shodaner.sh
source $core/ui_helpers.sh
source $core/report.sh

# --- Helper Functions ---
should_run() { [[ ! -e "$1" || "$rerun" == true ]]; }

log_debug() {
  local logfile="$results/debug.log"
  echo "[$(date '+%H:%M:%S')] $*" >> "$logfile"
}

# Redirect stderr based on verbosity
if [[ "$verbose" == true ]]; then
    export ERR_LOG="/dev/stderr"
    ui_print_info "Verbose mode enabled. Tool errors will be shown."
else
    export ERR_LOG="/dev/null"
fi

# --- Flag Parsing & Tool Resources ---
RES_DIR="/root/.dmut" # Directory for tool resources (resolvers, wordlists)
FLAGS_CONF="$SCRIPT_DIR/flags.conf"
parse_flag() { grep "^$1=" "$FLAGS_CONF" | cut -d= -f2-; }

subfinder_flags=$(parse_flag subfinder_flags)
dmut_flags=$(parse_flag dmut_flags | sed "s|MISC/|$MISC_DIR/|g; s|/root/.dmut|$RES_DIR|g")
naabu_flags=$(parse_flag naabu_flags | sed "s|/root/.dmut|$RES_DIR|g")
httpx_flags=$(parse_flag httpx_flags | sed "s|/root/.dmut|$RES_DIR|g")
wappscan_flags=$(parse_flag wappscan_flags)
nmap_flags=$(parse_flag nmap_flags)
dirsearch_flags=$(parse_flag dirsearch_flags)
dnsx_flags=$(parse_flag dnsx_flags | sed "s|/root/.dmut|$RES_DIR|g")
nuclei_flags=$(parse_flag nuclei_flags)
katana_flags=$(parse_flag katana_flags)

ip_flags(){
  naabu_flags=$(parse_flag ip_naabu_flags)
  httpx_flags=$(parse_flag ip_httpx_flags)
}

banner(){
  ui_print_banner
}

function cleanup() {
  ui_print_info "Cleaning up before exit"
  exit 0
}

trap cleanup SIGINT

function declared_paths(){
  subdomains="$results/subdomains.txt"
  naabuout="$results/naabuout"
  nmapscans="$results/nmapscans"
  aliveip="$results/aliveip.txt"
  httpxout="$results/httpxout"
  webtech="$results/webtech.json"
  hostport="$results/hostport.txt"
  ipport="$results/ipport.txt"
  urlprobed="$results/urlprobed.txt"
  potentialsdurls="$results/potentialsdurls.txt"
  urlprobedsd="$results/urlprobedsd.txt"
  enumscan="$PWD/$results/enumscan"
}

print_usage() {
  banner
  echo -e "${bluebg} U S A G E${NC}"
  echo "Usage: ./chomte.sh -p <ProjectName> -d <domain.com> [option]"
  echo "Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]"
  echo "Usage: ./chomte.sh -p projectname -d example.com -brt -jsd -sto -n -cd -e -js -ex "
  echo "Usage: ./chomte.sh -p projectname -d Domains-list.txt"
  echo "Usage: ./chomte.sh -p projectname -i 127.0.0.1"
  echo "Usage: ./chomte.sh -p projectname -i IPs-list.txt -n -cd -e -js -ex"
  echo "${NC}"
  echo -e "${bluebg}Mandatory Flags:${NC}"
  echo "    -p   | --project <string>       : Specify Project Name here"
  echo "    -d   | --domain <string>        : Specify Root Domain here / Domain List here"
  echo "      OR          "
  echo "    -i   | --ip <string>            : Specify IP / IPlist here - Starts with Naabu"
  echo "    -c   | --cidr | --asn <string>  : CIDR / ASN - Starts with Nmap Host Discovery"
  echo "      OR          "
  echo "    -hpl | --hostportlist <filename>: HTTP Probing on Host:Port List"
  printf "\n${upper}\n\tOptional Flags - ${wul}Only applicable with domain -d flag${NC}\n${lower}\n"
  echo ""
  echo -e ""
  echo "    -sd | --singledomain            : Single Domain for In-Scope Engagement"
  echo "    -pp   | --portprobe             : Probe HTTP web services in ports other than 80 & 443"
  echo "    -a   | --all                    : Run all required scans"
  echo "    -rr   | --rerun                 : ReRun the scan again"
  echo "    -brt | --dnsbrute               : DNS Recon Bruteforce"
  echo "        -ax | --alterx              : Subdomain Bruteforcing using DNSx on Alterx Generated Domains"
  echo "    -sto | --takeover               : Subdomain Takeover Scan"
    echo "    -r   | --report                 : Show Summary Report"
  
  echo -e ""
  printf "\n${upper}\n\tGlobal Flags - ${wul}Applicable with both -d / -i ${NC}\n${lower}\n"
  echo "    -s   | --shodan                    : Shodan Deep Recon - API Key Required"
  echo "    -n   | --nmap                      : Nmap Scan against open ports"
  echo "    -e   | --enum                      : Active Recon"
  echo "       -cd  | --content                : Content Discovery Scan"
  echo "       -cd  | --content subdomains.txt : Content Discovery Scan"
  echo "       -ru  | --reconurl               : URL Recon; applicable with enum -e flag"
  echo "       -ex  | --enumxnl                : XNL JS Recon; applicable with enum -e flag"  
  echo "       -nf  | --nucleifuzz             : Nuclei Fuzz; applicable with enum -e flag" 
  echo "    -v   | --verbose                   : Enable verbose logging"
  echo "    -h   | --help                      : Show this help"
  echo "${NC}"
  exit
}

function domaindirectorycheck(){
    results=Results/$project
    if [ -d $results ]
    then
        # echo -e "${yellowbg}[I] $results Directory already exists: $results\n${NC}"
        :
    else
        mkdir -p $results
        ui_print_success "$results Directory Created: $results" 
    fi
}

required_tools=("pv" "go" "python3" "ccze" "git" "pip" "knockknock" "subfinder" "naabu" "dnsx" "httpx" "csvcut" "csvstack" "dmut" "dirsearch" "ffuf" "nuclei" "nmap" "ansi2html" "xsltproc" "trufflehog" "anew" "interlace" "subjs" "katana" "gau" "gf" "qsinject" "jsleak" "waymore" "xnLinkFinder" "tlsx" "dalfox" "jq" "asnmap" "whois" "lolcat" "host")
missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done
if [ ${#missing_tools[@]} -ne 0 ]; then
    ui_print_error "The following tools are not installed: ${missing_tools[*]}"
    exit 1
fi

function var_checker(){
	if [[ -z ${project} ]]; then
		ui_print_error "Project Name is not set (Missing -p)"
    exit 1
  else
    domaindirectorycheck
  fi

  if [[ ${ipscan} == true ]] || [[ ${domainscan} == true || ${hostportscan} == true || ${casnscan} == true ]];then
    [[ ${domainscan} == true ]] && rundomainscan
    [[ ${ipscan} == true ]] && ip_flags && runipscan
    [[ ${casnscan} == true ]] && ip_flags && runcidrscan
    [[ ${hostportscan} == true ]] && ip_flags && runhostportscan
  else
    ui_print_error "IP or domain is not set (Missing -i or -d)"
  fi
}


#######################################################
function display_execution_context() {
    echo -e ""
    ui_print_info "Command: $0 ${ORIGINAL_ARGS[*]}"
    
    local active_modules=()
    [[ "$domainscan" == true ]] && active_modules+=("Domain Scan")
    [[ "$singledomain" == true ]] && active_modules+=("Single Domain")
    [[ "$ipscan" == true ]] && active_modules+=("IP Scan")
    [[ "$hostportscan" == true ]] && active_modules+=("Host:Port Scan")
    [[ "$casnscan" == true ]] && active_modules+=("CIDR/ASN Scan")
    
    # Optional Modules
    [[ "$dnsbrute" == true ]] && active_modules+=("DNS Brute")
    [[ "$alterx" == true ]] && active_modules+=("Alterx")
    [[ "$portprobe" == true ]] && active_modules+=("Port Probe")
    [[ "$shodan" == true ]] && active_modules+=("Shodan")
    [[ "$nmap" == true ]] && active_modules+=("Nmap")
    [[ "$enum" == true ]] && active_modules+=("Active Recon")
    [[ "$vuln" == true ]] && active_modules+=("Vuln Scan")
    [[ "$all" == true ]] && active_modules+=("All Modules")
    [[ "$enumxnl" == true ]] && active_modules+=("XNL Linkfinding")
    [[ "$contentscan" == true ]] && active_modules+=("Content Discovery")
    
    if [ ${#active_modules[@]} -gt 0 ]; then
        local modules_list=$(IFS=', '; echo "${active_modules[*]}")
        ui_print_info "Active Modules: ${modules_list}"
    fi
     echo -e ""
}

function setup_dirs(){
  display_execution_context
  ui_print_info "Results Dir: $results" && mkdir -p $results
  ui_print_info "Enum Dir: ${enumscan#*/chomtesh/}" && mkdir -p $enumscan
}

function phase_subdomain_enum() {
    local target="$1"
    # Logic common to single domain and domain list
    # $target is either a single domain or a file path
    [[ "$nosubdomainscan" != true ]] && getsubdomains "$target" "$results/subdomains.txt"
    [[ "$nosubdomainscan" == true && -f "$target" ]] && cat "$target" | anew -q "$results/subdomains.txt"
    
    # DNS Brute and Takeover
    [[ "$dnsbrute" == true || "$alterx" == true || "$all" == true ]] && dnsreconbrute "$target" "$results/dnsbruteout.txt"
    [[ ("$shodan" == true || "$all" == true) && ! -f "$target" ]] && shodun "$target" &
    
    # Subdomain Takeover (Explicit Request)
    [[ "$enum" == true || "$vuln" == true || "$all" == true ]] && subdomaintakeover &
    
    # Wait for parallel jobs if any launched? 
    # Current implementation waits after probing, which is fine.
}

function phase_probing() {
    # Consolidated probing logic
    # Expects $subdomains to be set or $domain in single mode
    
    if [[ "$singledomain" == true ]]; then
         portscanner "$domain" $naabuout
         httpprobing "$hostport" "$httpxout"
    else
         # Probe the consolidated subdomains list once (includes brute results)
         httpprobing "$subdomains" "$httpxout"
         # On --rerun, also probe only the newly discovered delta
         [[ -e "$results/newsubdomains.tmp" ]] && httpprobing "$results/newsubdomains.tmp" "$httpxout-new"
    fi
     
    # Wait for background jobs (shodan/takeover) launched in enum phase
    wait 
    
    # Merge all httpx outputs
    # Merge all httpx outputs
    if [[ "$singledomain" != true ]]; then
        local csv_files=()
        [[ -s "$httpxout.csv" ]] && csv_files+=("$httpxout.csv")
        [[ -s "$httpxout-new.csv" ]] && csv_files+=("$httpxout-new.csv")
        
        if [ ${#csv_files[@]} -gt 0 ]; then
             csvstack "${csv_files[@]}" > "$results/httpxmerge.csv" 2>/dev/null
        fi

        # Concatenate JSONs to NDJSON (standard for tools) or Array if needed.
        # Assuming NDJSON is better for streaming/concat. 
        # But if jq -s add was used, maybe they wanted a single object? Unlikely.
        # Let's produce a JSON Array which is safer for "merge.json" naming.
        # Check if files exist to avoid jq errors.
        if ls "$results"/httpx*.json 1> /dev/null 2>&1; then
             cat "$results"/httpx*.json | jq -s '.' > "$results/httpxmerge.json" 2>$ERR_LOG
        fi
    fi
    
    # Host Port / Naabu / Nmap logic
    if [[ "$all" == true || "$pp" == true ]]; then
       if [[ "$singledomain" == true ]]; then
            # Single Domain specific additional scanning logic if needed?
            # Original code just ran nmap
             [[ "$nmap" == "true" ]] && nmapscanner "$ipport" "$nmapscans"
       else
          [[ ! -e "$naabuout.json" || "$rerun" == true ]] && echo -e "${YELLOW}[*] Probing HTTP web services excluding ports 80 & 443${NC}"
          
          # Logic differs slightly between List and Domain modes in original code for DNS resolution
          # Unified approach: Always resolve from subdomains list
          dnsresolve "$results/subdomains.txt" "$results/dnsreconout.txt" "$results/dnsxresolved.txt"
          
          # Use subdomains list as primary input for port scanning
          local target_list="$results/subdomains.txt"
          # [[ -s "$results/dnsxresolved.txt" ]] && target_list="$results/dnsxresolved.txt"
          
          portscanner "$target_list" "$naabuout"
          
          # Port mapper if needed? Original code had it only in List mode block
          [[ -e "$dnsxresolved" && -e "$naabuout.csv" ]] && portmapper
          
          [[ -e "$hostport" ]] && cat "$hostport" | grep -vE ':80$|:443$' | anew -q "$hostport-services"
          [[ ! -e "$httpxout-portprobe.json" ]] && echo -e "${YELLOW}[*] Rerunning HTTP Probing excluding port 80 & 443${NC}"
          [[ -s "$hostport-services" ]] && httpprobing "$hostport-services" "$httpxout-portprobe"
          
          # Re-merge with portprobe data
          local csv_files_merge=()
          [[ -s "$httpxout.csv" ]] && csv_files_merge+=("$httpxout.csv")
          [[ -s "$httpxout-portprobe.csv" ]] && csv_files_merge+=("$httpxout-portprobe.csv")
          [[ -s "$httpxout-new.csv" ]] && csv_files_merge+=("$httpxout-new.csv")
          
          if [ ${#csv_files_merge[@]} -gt 0 ]; then
               csvstack "${csv_files_merge[@]}" > "$results/httpxmerge.csv" 2>/dev/null
          fi
          
          if ls "$results"/httpx*.json 1> /dev/null 2>&1; then
               cat "$results"/httpx*.json | jq -s '.' > "$results/httpxmerge.json" 2>$ERR_LOG
          fi
          
          [[ "$nmap" == "true" ]] && nmapscanner "$ipport" "$nmapscans"
       fi
    fi
    
    # Run Tech Detection and Summary (No Nuclei yet)
    if [[ -e "$httpxout" ]]; then
        identify_technologies
        show_tech_summary
    fi
}

function phase_vulnerability_scan() {
    # Consolidated Vulnerability Scanning Phase
    ui_print_info "Starting Vulnerability Scanning Phase..."
    
    [[ "$reconurl" == true || "$all" == true ]] && recon_url
    [[ "$enumxnl" == true && ! -f "$domain" || "$all" == true ]] && xnl
    
    # Active Recon (Nuclei Technology Scan)
    [[ "$enum" == true || "$vuln" == true || "$all" == true ]] && active_recon
    
    # Integrated Vulnerability Checks
    [[ "$vuln" == true || "$all" == true ]] && enumVuln
    
    # Content Discovery
    [[ "$contentscan" == true || "$all" == true ]] && {
        if [[ -n "$cdlist" ]]; then
            content_discovery "$cdlist"
        else
            content_discovery "$potentialsdurls"
        fi
    }
}

function rundomainscan(){
    # 1. Setup Environment
    if [[ -n "$domain" && ! -f "$domain" && "$singledomain" != true ]]; then
        # Standard Domain Mode
        ui_print_header "DOMAIN MODULE" "$domain"
        results="Results/$project/$domain"
        declared_paths
        setup_dirs
        
        phase_subdomain_enum "$domain"
        phase_probing
        [[ $enum == true || "$all" == true || $vuln == true ]] && phase_vulnerability_scan

    elif [[ -n "$domain" && -f "$domain" ]]; then
        # Domain List Mode
        ui_print_header "DOMAIN MODULE" "List: $domain"
        domainlist=true
        local list_name=$(basename "$domain" | cut -d . -f 1)
        results="Results/$project/$list_name"
        declared_paths
        setup_dirs
        
        # Prime targets
        cat "$domain" | anew -q "$results/targets.txt"
        
        phase_subdomain_enum "$results/targets.txt"
        phase_probing
        [[ "$enum" == true || "$all" == true || "$vuln" == true ]] && phase_vulnerability_scan

    elif [[ "$singledomain" == true && -n "$domain" ]]; then
        # Single Domain Mode
        ui_print_header "SINGLE DOMAIN MODULE" "$domain"
        results="Results/$project/$domain"
        declared_paths
        setup_dirs
        
        # Skip subdomain enum
        phase_probing
        [[ "$enum" == true || "$all" == true || "$vuln" == true ]] && phase_vulnerability_scan
    fi
}

function runipscan(){
  ip_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  if [[ $ip =~ $ip_pattern ]] && [[ $ip != *"\/"* ]] && [[ $ip != *"AS"* ]] || [[ -f $ip ]]; then
    # Valid IP or File
    if [[ -f $ip ]]; then
        ipdir=$(basename "$ip" | tr . _)
        ui_print_header "IP MODULE" "File: $ip"
    else
        ipdir=$(echo "$ip" | tr . _)
        ui_print_header "IP MODULE" "$ip"
    fi

    results="Results/$project/$ipdir"
    declared_paths
    setup_dirs
    
    portscanner "$ip" "$naabuout"
    httpprobing "$ipport" "$httpxout"
    [[ "$nmap" == "true" ]] && nmapscanner "$ipport" "$nmapscans"
    
    # Run Tech Detect and Summary
    if [[ -e "$httpxout" ]]; then
       identify_technologies
       show_tech_summary
    fi
     
    # Run active_recon if requested
    [[ "$enum" == true || "$vuln" == true || "$all" == true ]] && active_recon
    
    [[ $vuln == true || "$all" == true ]] && phase_vulnerability_scan

  else
    ui_print_error "IP Input is Wrong; Try Correct Flag --asn / --cidr $ip"
  fi
}

function runcidrscan(){
  ui_print_header "CIDR/ASN MODULE" "$casn"
  
  casndir=$(echo "$casn" | tr / _)
  results="Results/$project/$casndir"
  declared_paths
  setup_dirs
  
  nmapdiscovery "$casn"
  portscanner "$aliveip" "$naabuout"
  httpprobing "$ipport" "$httpxout"
  [[ "$nmap" == "true" ]] && nmapscanner "$ipport" "$nmapscans"
  
  # Run Tech Detect and Summary
  if [[ -e "$httpxout" ]]; then
      identify_technologies
      show_tech_summary
  fi
  
  # Run active_recon if requested
  [[ "$enum" == true || "$vuln" == true || "$all" == true ]] && active_recon

  
  [[ $vuln == true || "$all" == true ]] && phase_vulnerability_scan
}

function runhostportscan(){
  ui_print_header "HOSTPORT SCAN MODULE" "$hostportlist"
  if [ -n "${hostportlist}" ]; then
    declared_paths
    setup_dirs
    
    httpprobing "$hostportlist" "$httpxout"
    [[ "$nmap" == "true" ]] && nmapscanner "$hostportlist" "$nmapscans" 
    
    # Run Tech Detect and Summary
    if [[ -e "$httpxout" ]]; then
        identify_technologies
        show_tech_summary
    fi

    # Run active_recon
    [[ "$enum" == true || "$vuln" == true || "$all" == true ]] && active_recon
    
    [[ $vuln == true || "$all" == true ]] && phase_vulnerability_scan
  fi
}

#######################################################

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      print_usage
      shift
      ;;
    -u|--update)
      update=true
      shift
      ;;
    -p|--project)
      project="$2"
      banner
      shift
      ;;
    -d|--domain)
      domain="$2"
      domainscan=true
      shift 
      ;;
    -sd|--singledomain)
      singledomain=true
      shift
      ;;
    -nss|--nosubdomainscan)
      nosubdomainscan=true
      shift
      ;;

    -r|--report)
      report=true
      shift
      ;;
    -v|--vuln)
      vuln=true
      shift
      ;;
    -i|--ip)
      ip="$2"
      ipscan=true
      shift
      ;;
    -c|--cidr|--asn)
      casn="$2"
      casnscan=true
      shift
      ;;
    -a|--all)
      all=true
      shift
      ;;
    -s|--shodan)
      shodan=true
      shift
      ;;
    -pp|--portprobe)
      pp=true
      shift
      ;;
    -rr|--rerun)
      rerun=true
      shift
      ;;
    -hpl|--hostportlist)
      hostportlist="$2"
      hostportscan=true
      shift
      ;;
    -cd|--content)
      cdlist="$2"
      contentscan=true
      shift
      ;;
    -e|--enum)
      enum=true
      shift
      ;;
    -ru|--reconurl)
      reconurl=true
      shift
      ;;
    -nf|--nucleifuzz)
      nucleifuzz=true
      shift
      ;;
    -ex|--enumxnl)
      enumxnl=true
      shift
      ;;
    -brt|--dnsbrute)
      dnsbrute=true
      shift
      ;;
    -ax|--alterx)
      alterx=true
      shift
      ;;
    -n|--nmap)
      nmap=true
      shift 
      ;;
    -td|--techdetect)
      tech="$2"
      techdetect=true
      shift
      ;;
    -v|--verbose)
      verbose=true
      shift
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1 
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift 
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [[ $update == true ]];then
	git pull origin main 2>$ERR_LOG
  echo -e ${GREEN}Update Completed${NC} && exit 0
elif [[ -z $1 ]]; then
    print_usage
fi

var_checker

if [[ "$report" == true ]]; then
    generate_report "$project" "$domain"
fi
