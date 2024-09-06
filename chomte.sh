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

core="$PWD/core"

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
source $core/activeRecon.sh
source $core/urlRecon.sh
source $core/hostdiscovery.sh
source $core/enumVuln.sh
source $core/shodaner.sh

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

ip_flags(){
  naabu_flags=$(grep '^ip_naabu_flags=' flags.conf | awk -F= '{print $2}' | xargs)
  httpx_flags=$(grep '^ip_httpx_flags=' flags.conf | awk -F= '{print $2}' | xargs)
}

banner(){
echo -e '

 ██████╗██╗  ██╗ ██████╗ ███╗   ███╗████████╗███████╗   ███████╗██╗  ██╗
██╔════╝██║  ██║██╔═══██╗████╗ ████║╚══██╔══╝██╔════╝   ██╔════╝██║  ██║
██║     ███████║██║   ██║██╔████╔██║   ██║   █████╗     ███████╗███████║
██║     ██╔══██║██║   ██║██║╚██╔╝██║   ██║   ██╔══╝     ╚════██║██╔══██║
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║   ███████╗██╗███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
      '  | lolcat -a -d 1                          
}

function cleanup() {
  echo "Cleaning up before exit"
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
  echo "    -h   | --help                      : Show this help"
  echo "${NC}"
  exit
}

function domaindirectorycheck(){
    results=Results/$project
    if [ -d $results ]
    then
        echo -e
        echo -e "${yellowbg}[I] $results Directory already exists: $results\n${NC}"
    else
        mkdir -p $results
        echo -e "${BLUE}[I] $results Directory Created: $results\n${NC}" 
    fi
}

required_tools=("pv" "go" "python3" "ccze" "git" "pip" "knockknock" "subfinder" "naabu" "dnsx" "httpx" "csvcut" "dmut" "dirsearch" "ffuf" "nuclei" "nmap" "ansi2html" "xsltproc" "trufflehog" "anew" "interlace" "subjs" "katana")
missing_tools=()
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done
if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e ""
    echo -e "${redbg}[-]The following tools are not installed:${NC} ${missing_tools[*]}"
    exit 1
fi

function var_checker(){
  echo -e "${yellowbg}[*] Checking for required arguments...${NC}"
	if [[ -z ${project} ]]; then
		echo -e "${RED}[-] ERROR: Project Name is not set${NC}"
		echo -e "${RED}[-] Missing -p ${NC}"
    #print_usage
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
    echo -e "${RED}[-] ERROR: IP or domain is not set\n[-] Missing -i or -d ${NC}"    
  fi
}


#######################################################
function declare(){
  echo -e "${MAGENTA}---------------------------------${NC}"
  echo -e "Results Dir: $results" && mkdir -p $results
  echo -e "Enum Dir: ${enumscan#*/chomtesh/}" && mkdir -p $enumscan
  echo -e "${MAGENTA}---------------------------------${NC}"
}

function rundomainscan(){
  if [[ -n "$domain" && ! -f "$domain" && $singledomain != true ]];then
    echo -e ${BLUEBG}"Domain Module $domain $domainscan - Domain Specified"${NC}
    results="$results/$domain"
    declared_paths
    declare
    #---------------------------------------------------#
    [[ "$nosubdomainscan" != true ]] && getsubdomains "$domain" "$results/subdomains.txt"
    [[ "$dnsbrute" == true ]] && dnsreconbrute "$domain" "$results/dnsbruteout.txt"
    [[ "$shodan" == true ]] && shodun "$domain"
    [[ -s $results/brutesubdomains.tmp ]] && httpprobing $results/brutesubdomains.tmp "$httpxout-brute"
    [[ "$takeover" == true ]] && subdomaintakeover
    [[ -e $results/newsubdomains.tmp ]] && httpprobing $results/newsubdomains.tmp "$httpxout-new"
    [[ ! -e $results/newsubdomains.tmp ]] && httpprobing $subdomains $httpxout
    
    csvstack $httpxout.csv $httpxout-brute.csv $httpxout-new 2>/dev/null > $results/httpxmerge.csv 2>/dev/null
    jq -s add $results/httpx*.json > $results/httpxmerge.json 2>/dev/null
    
    if [[ "$all" == true || "$pp" == true && -f "$httpxout.json" ]]; then
      [[ ! -e $naabuout.json || $rerun == true ]] && echo -e "${YELLOW}[*] Probing HTTP web services excluding ports 80 & 443${NC}"
      dnsresolve "$results/subdomains.txt" "$results/dnsreconout.txt"
      portscanner "$results/subdomains.txt" $naabuout
      [[ -e $hostport ]] && cat $hostport | grep -vE ':80$|:443$' | anew -q $hostport-services
      [[ ! -e $httpxout-portprobe.json ]] && echo -e "${YELLOW}[*] Rerunning HTTP Probing excluding port 80 & 443${NC}"
      [[ -s $hostport-services ]] && httpprobing "$hostport-services" "$httpxout-portprobe"
      csvstack $httpxout.csv $httpxout-brute.csv $httpxout-portprobe.csv $httpxout-new 2>/dev/null > $results/httpxmerge.csv 2>/dev/null
      jq -s add $results/httpx*.json > $results/httpxmerge.json 2>/dev/null
      
      [[ $nmap == "true" ]] && nmapscanner "$ipport" "$nmapscans"
    fi
    if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ $reconurl == true || "$all" == true ]] && recon_url
        [[ $enumxnl == true && ! -f $domain || "$all" == true ]] && xnl
        [[ $vuln == true ]] && enumVuln
        [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
    fi
    #---------------------------------------------------#
  elif [ -n "$domain" ] && [ -f "$domain" ];then
    echo -e "Domain Module $domain $domainscan - List Specified"
    domainlist=true
    DomainListFolder=$(echo $domain | cut -d . -f 1)
    results="$results/$DomainListFolder"
    declared_paths
    declare
    #---------------------------------------------------#
    cat "$domain" | anew -q "$results/targets.txt"
    [ "$nosubdomainscan" != true ] && getsubdomains "$results/targets.txt" "$results/subdomains.txt"
    [ "$nosubdomainscan" == true ] && cat "$domain" | anew -q "$results/subdomains.txt"
    [[ "$dnsbrute" == true && -f "$domain" ]] && dnsreconbrute "$domain" "$results/dnsbruteout.txt"
    [[ "$takeover" == true && -f "$domain" ]] && subdomaintakeover
    httpprobing $subdomains $httpxout
    [[ -s $results/brutesubdomains.tmp ]] && httpprobing $results/brutesubdomains.tmp "$httpxout-brute"
    [[ "$takeover" == true ]] && subdomaintakeover
        
    [[ ! -e $hostport || $rerun == true ]] && cat  $naabuout.json | jq -r '"\(.host):\(.port)"' | anew $hostport -q &>/dev/null

    if [[ "$all" == true || "$pp" == true && -f "$results/httpxout.csv" ]]; then
      dnsresolve "$results/subdomains.txt" "$results/dnsreconout.txt" "$results/dnsxresolved.txt"
      portscanner "$results/dnsxresolved.txt" $naabuout
      [[ -e $dnsxresolved && -e $naabuout.csv ]] && portmapper
      [[ -e $hostport ]] && cat $hostport | grep -v ":80\|:443" | anew -q $hostport-services
      echo -e "${MAGENTA}Http Probing excluding port 80 & 443${NC}"
      [[ -s $hostport-services ]] && httpprobing "$hostport-services" "$httpxout-portprobe"
      [ -e $results/httpxout2.csv ] && csvstack $results/httpxout.csv $results/httpxout2.csv > $results/httpxmerge.csv
      [[ $nmap == "true" ]] && nmapscanner "$ipport" "$nmapscans"
    fi

    if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ $reconurl == true || "$all" == true ]] && recon_url
        [[ $enumxnl == true && ! -f $domain || "$all" == true ]] && xnl
        [[ "$vuln" == true ]] && enumVuln
        [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
    fi

    #---------------------------------------------------#
  elif [[ $singledomain == true && -n "$domain" ]];then
    echo -e "Single Domain Module $domain"
    results="$results/$domain"
    declared_paths
    declare
    portscanner "$domain" $naabuout
    httpprobing "$hostport" "$httpxout"
    [[ $nmap == "true" ]] && nmapscanner "$ipport" "$nmapscans" 

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
  ip_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  if [[ $ip =~ $ip_pattern ]] && [[ $ip != *"\/"* ]] && [[ $ip != *"AS"* ]] || [[ -f $ip ]]; then
    echo -e "IP Module $ip $ipscan"
    echo -e "${MAGENTA}[*] IP Scan is Running on $ip${NC}"
    [[ $ip =~ $ip_pattern ]] && ipdir=$(echo $ip | tr . _)
    [[ -f $ip ]] && ipdir=$(basename $ip | tr . _)
    results="$results/$ipdir"
    declared_paths
    declare
    portscanner "$ip" $naabuout
    httpprobing "$ipport" "$httpxout"
    [[ $nmap == "true" ]] && nmapscanner $ipport $nmapscans
      if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ "$vuln" == true ]] && enumVuln
        [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
      fi
  else
    echo -e "${RED}[*] IP Input is Wrong; Try Correct Flag --asn / --cidr $ip${NC}"
  fi
  
}

function runcidrscan(){
  echo -e "CIDR/ASN Module $casn"
  echo -e "${MAGENTA}[*] CIDR/ASN Scan is Running on $cidr $asn $casn${NC}"
  casndir=$(echo $casn | tr / _)
  results="$results/$casndir"
  declared_paths
  declare
  nmapdiscovery $casn
  portscanner "$aliveip" "$naabuout"
  httpprobing "$ipport" "$httpxout"
  [[ $nmap == "true" ]] && nmapscanner $ipport $nmapscans
  if [[ $enum == true || "$all" == true ]]; then
      [[ -e $httpxout || "$all" == true ]] && active_recon
      [[ "$vuln" == true ]] && enumVuln
      [[ $contentscan == true || "$all" == true ]] && { [[ $cdlist ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
  fi
}

function runhostportscan(){
  echo -e "${MAGENTA}[*] HostPort Scan is Running on $hostportlist${NC}"
  if [ -n "${hostportlist}" ];then
    declared_paths
    declare
    httpprobing "$hostportlist" "$httpxout"
    [[ $nmap == "true" ]] && nmapscanner "$hostportlist" "$nmapscans" 
    if [[ $enum == true || "$all" == true ]]; then
        [[ -e $httpxout || "$all" == true ]] && active_recon
        [[ "$vuln" == true ]] && enumVuln
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
    -sto|--takeover)
      takeover=true
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
	git pull origin main 2>/dev/null
  echo -e ${GREEN}Update Completed${NC} && exit 0
elif [[ -z $1 ]]; then
    print_usage
fi

var_checker
