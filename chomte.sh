#!/bin/bash
#title: CHOMTE.SH
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed | rushikeshhh-patil
#version:       5.0.0
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

core="$PWD/core"

for script_file in "$core"/*.sh; do
    source "$script_file"
done

# sed -i 's/\s\+/ /g' flags.conf

subfinder_flags=$(grep '^subfinder_flags=' flags.conf | awk -F= '{print $2}' | xargs)
dmut_flags=$(grep '^dmut_flags=' flags.conf | awk -F= '{print $2}' | xargs)
naabu_flags=$(grep '^naabu_flags=' flags.conf | awk -F= '{print $2}' | xargs)
httpx_flags=$(grep '^httpx_flags=' flags.conf | awk -F= '{print $2}' | xargs)
webanalyze_flags=$(grep '^webanalyze_flags=' flags.conf | awk -F= '{print $2}' | xargs)
nmap_flags=$(grep '^nmap_flags=' flags.conf | awk -F= '{print $2}' | xargs)
dirsearch_flags=$(grep '^dirsearch_flags=' flags.conf | awk -F= '{print $2}' | xargs)
dnsx_flags=$(grep '^dnsx_flags=' flags.conf | awk -F= '{print $2}' | xargs)
nuclei_flags=$(grep '^nuclei_flags=' flags.conf | awk -F= '{print $2}' | xargs)

banner(){
echo ${GREEN} '

 ██████╗██╗  ██╗ ██████╗ ███╗   ███╗████████╗███████╗   ███████╗██╗  ██╗
██╔════╝██║  ██║██╔═══██╗████╗ ████║╚══██╔══╝██╔════╝   ██╔════╝██║  ██║
██║     ███████║██║   ██║██╔████╔██║   ██║   █████╗     ███████╗███████║
██║     ██╔══██║██║   ██║██║╚██╔╝██║   ██║   ██╔══╝     ╚════██║██╔══██║
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║   ███████╗██╗███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
      '  ${NC}                                                      
}

function cleanup() {
  echo "Cleaning up before exit"
  exit 0
}

trap cleanup SIGINT

function declared_paths(){
  subdomains="$results/subdomains.txt"
  naabuout="$results/naabu.csv"
  nmapscans="$results/nmapscans"
  aliveip="$results/aliveip.txt"
  httpxout="$results/httpxout.csv"
  webtech="$results/webtech.csv"
  hostport="$results/hostport.txt"
  ipport="$results/ipport.txt"
  urlprobed="$results/urlprobed.txt"
  potentialsdurls="$results/potentialsdurls.txt"
  urlprobedsd="$results/urlprobedsd.txt"
  enumscan="$PWD/$results/enumscan"
}

print_usage() {
  banner
  echo "${MAGENTA}"
  echo "~~~~~~~~~~~"
  echo " U S A G E"
  echo "~~~~~~~~~~~"
  echo "Usage: ./chomte.sh -p <ProjectName> -d <domain.com> [option]"
  echo "Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]"
  echo "Usage: ./chomte.sh -p projectname -d example.com -brt -jsd -sto -n -cd -e -js -ex "
  echo "Usage: ./chomte.sh -p projectname -d Domains-list.txt"
  echo "Usage: ./chomte.sh -p projectname -i 127.0.0.1"
  echo "Usage: ./chomte.sh -p projectname -i IPs-list.txt -n -cd -e -js -ex"
  echo "${NC}"
  echo "  Mandatory Flags:"
  echo "    -p   | --project <string>       : Specify Project Name here"
  echo "    -d   | --domain <string>        : Specify Root Domain here / Domain List here"
  echo "      OR          "
  echo "    -i   | --ip <string>            : Specify IP / CIDR/ IPlist here"
  echo "      OR          "
  echo "    -hpl | --hostportlist <filename>: HTTP Probing on Host:Port List"
  echo ""  
  echo "Optional Flags - ${wul}Only applicable with domain -d flag${NC}"
  echo ""
  echo "    -sd | --singledomain            : Single Domain for In-Scope Engagement"
  echo "    -pp   | --portprobe             : Probe HTTP web services in ports other than 80 & 443"
  echo "    -a   | --all                    : Run all required scans"
  echo "    -rr   | --rerun                 : ReRun the scan again"
  echo "    -brt | --dnsbrute               : DNS Recon Bruteforce"
  echo "        -ax | --alterx              : Subdomain Bruteforcing using DNSx on Alterx Generated Domains"
  echo "    -jsd | --jsubfinder             : Get Subdomains from WebPage and JS file by crawling"
  echo "    -sto | --takeover               : Subdomain Takeover Scan"
  echo ""
  echo "Global Flags - ${wul}Applicable with both -d / -i ${NC}"
 
  echo "    -n   | --nmap                      : Nmap Scan against open ports"
  echo "    -e   | --enum                      : Active Recon"
  echo "       -cd  | --content                : Content Discovery Scan"
  echo "       -cd  | --content subdomains.txt : Content Discovery Scan"
  echo "       -js  | --jsrecon                : JS Recon; applicable with enum -e flag"
  echo "       -ex  | --enumxnl                : XNL JS Recon; applicable with enum -e flag"  
  echo "    -h   | --help                      : Show this help"
  echo ""
  echo "${NC}"
  exit
}

function domaindirectorycheck(){
    results=Results/$project
    if [ -d $results ]
    then
        echo -e
        echo -e "${BLUE}[I] $results Directory already exists: $results\n${NC}"
    else
        mkdir -p $results
        echo -e "${BLUE}[I] $results Directory Created: $results\n${NC}" 
    fi
}

required_tools=("pv" "go" "python3" "ccze" "git" "pip" "pup" "knockknock" "subfinder" "naabu" "dnsx" "httpx" "csvcut" "dmut" "dirsearch" "ffuf" "nuclei" "nmap" "ansi2html" "xsltproc" "trufflehog" "anew" "interlace" "subjs" "katana")
missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done
if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e ""
    echo -e "${RED}[-]The following tools are not installed:${NC} ${missing_tools[*]}"
    exit 1
fi

function var_checker(){
  echo -e "${BLUE}[*] Checking for required arguments...${NC}"
	if [[ -z ${project} ]]; then
		echo -e "${RED}[-] ERROR: Project Name is not set${NC}"
		echo -e "${RED}[-] Missing -p ${NC}"
    #print_usage
    exit 1
  else
    domaindirectorycheck
  fi

  if [[ ${ipscan} == true ]] || [[ ${domainscan} == true || ${hostportscan} == true ]];then
    [[ ${domainscan} == true ]] && rundomainscan
    [[ ${ipscan} == true ]] && runipscan
    [[ ${hostportscan} == true ]] && runhostportscan
  else
    echo -e "${RED}[-] ERROR: IP or domain is not set\n[-] Missing -i or -d ${NC}"    
  fi
}


#######################################################
function declare(){
  echo -e "${MAGENTA}---------------------------------${NC}"
  echo -e "Results Dir: $results" && mkdir -p $results
  echo -e "Enum Dir: $enumscan" && mkdir -p $enumscan
  echo -e "${MAGENTA}---------------------------------${NC}"
}

function rundomainscan(){
  if [[ -n "$domain" && ! -f "$domain" && $singledomain != true ]];then
    echo -e "Domain Module $domain $domainscan - Domain Specified"
    results="$results/$domain"
    declared_paths
    declare
    #---------------------------------------------------#
    getsubdomains "$domain" "$results/subdomains.txt"
    [[ "$jsd" == true ]] && jsubfinder "$results/subdomains.txt" "$results/jsubfinder.txt"
    [[ "$dnsbrute" == true ]] && dnsreconbrute "$domain" "$results/dnsbruteout.txt"
    [[ -e $results/brutesubdomains.tmp ]] && httpprobing $results/brutesubdomains.tmp $results/httpxout.csv
    [[ "$takeover" == true ]] && subdomaintakeover
    [[ -e $results/newsubdomains.tmp ]] && httpprobing $results/newsubdomains.tmp "$results/httpxout.csv"
    [[ ! -e $results/newsubdomains.tmp ]] && httpprobing "$results/subdomains.txt" "$results/httpxout.csv"
    
    if [[ "$all" == true || "$pp" == true && -f "$results/httpxout.csv" ]]; then
      echo -e "${YELLOW}[*] Probing HTTP web services in ports other than 80 & 443${NC}"
      dnsresolve "$results/subdomains.txt" "$results/dnsreconout.txt" "$results/dnsxresolved.txt"
      portscanner "$results/dnsxresolved.txt" "$results/naabuout.csv" && portmapper
      cat $hostport | grep -v ":80\|:443" | anew -q $hostport-tmp
      echo -e "${YELLOW}[*] Rerunning HTTP Probing excluding port 80 & 443${NC}"
      httpprobing "$hostport-tmp" "$results/httpxout2.csv"
      [ -e $results/httpxout2.csv ] && csvstack $results/httpxout.csv $results/httpxout2.csv > $results/httpxmerge.csv
    fi
    
    if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ $reconurl == true || "$all" == true ]] && recon_url
        [[ $enumxnl == true && ! -f $domain || "$all" == true ]] && xnl
        [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
    fi
    #---------------------------------------------------#
  elif [ -n "$domain" ] && [ -f "$domain" ];then
    echo -e "Domain Module $domain $domainscan - List Specified"
    domainlist=true
    declared_paths
    declare
    #---------------------------------------------------#
    cat "$domain" | tee "$results/targets.txt" | anew -q "$results/subdomains.txt"
    [[ "$jsd" == true && -f "$domain" ]] && jsubfinder "$domain" "$results/jsubfinder.txt"
    [[ "$dnsbrute" == true && -f "$domain" ]] && dnsreconbrute "$domain" "$results/dnsbruteout.txt"
    [[ "$takeover" == true && -f "$domain" ]] && subdomaintakeover
    httpprobing "$results/subdomains.txt" "$results/httpxout.csv"
    
    [ ! -e $hostport ] && csvcut -c host,port $naabuout 2>/dev/null | tr ',' ':' | grep -v 'host:port' | anew $hostport -q &>/dev/null
    
    if [[ "$all" == true || "$pp" == true && -f "$results/httpxout.csv" ]]; then
      dnsresolve "$results/subdomains.txt" "$results/dnsreconout.txt" "$results/dnsxresolved.txt"
      portscanner "$results/subdomains.txt" "$results/naabuout.csv"
      cat $hostport | grep -v ":80\|:443" | anew -q $hostport-tmp
      echo -e "${MAGENTA}Http Probing excluding port 80 & 443${NC}"
      httpprobing "$hostport-tmp" "$results/httpxout2.csv"
      [ -e $results/httpxout2.csv ] && csvstack $results/httpxout.csv $results/httpxout2.csv > $results/httpxmerge.csv
    fi

    if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ $reconurl == true || "$all" == true ]] && recon_url
        [[ $enumxnl == true && ! -f $domain || "$all" == true ]] && xnl
        [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
    fi

    #---------------------------------------------------#
  elif [[ $singledomain == true && -n "$domain" ]];then
    echo -e "Single Domain Module $domain"
    results="$results/$domain"
    declared_paths
    declare
    portscanner "$domain" "$results/naabuout.csv"
    httpprobing "$hostport" "$results/httpxout.csv"

    if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ $reconurl == true || "$all" == true ]] && recon_url
        [[ $enumxnl == true && ! -f $domain || "$all" == true ]] && xnl
        [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
    fi
    #---------------------------------------------------#
  fi
}

function runipscan(){
  echo -e "IP Module $ip $ipscan"
  echo -e "${MAGENTA}[*] IP Scan is Running on $ip${NC}"
  declared_paths
  declare
  portscanner "$ip" "$results/naabuout.csv"
  httpprobing "$ipport" "$results/httpxout.csv"
  if [[ $enum == true || "$all" == true ]]; then
      [[ -e $httpxout || "$all" == true ]] && active_recon
      [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
  fi
}

function runhostportscan(){
  echo -e "${MAGENTA}[*] HostPort Scan is Running on $hostportlist${NC}"
  if [ -n "${hostportlist}" ];then
    declared_paths
    declare
    httpprobing "$hostportlist" "$results/httpxout.csv"

    if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
    fi

  fi
}

#######################################################

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      print_usage
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
    -sto|--takeover)
      takeover=true
      shift 
      ;;
    -i|--ip)
      ip="$2"
      ipscan=true
      shift
      ;;
    -a|--all)
      all=true
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
    -ex|--enumxnl)
      enumxnl=true
      shift
      ;;
    -jsd|--jsubfinder)
      jsd=true
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

if [[ ! -n $1 ]]; then
    print_usage
fi

var_checker
