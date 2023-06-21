#!/bin/bash
#title: CHOMTE.SH
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed | rushikeshhh-patil
#version:       4.0.0
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

function getsubdomains(){
  echo -e "${YELLOW}[*] Gathering Subdomains: $domain${NC}"
  domain=$1
  subdomains=$2
  [[ ! -e $subdomains || $rerun == true ]] && echo -e "${BLUE}[#] subfinder -d $domain | anew $subdomains ${NC}"
  [[ ! -e $subdomains ]] && subfinder -d $domain | anew -q $subdomains &>/dev/null 2>&1
  [[ $rerun == true ]] && subfinder -d $domain | anew -q $results/subdomains.tmp &>/dev/null 2>&1
  [[ -e $results/subdomains.tmp ]] && grep -Fxvf $subdomains $results/subdomains.tmp > $results/newsubdomains.tmp
  
  [[ -e $results/newsubdomains.tmp ]] && nsdc=$(<$results/newsubdomains.tmp wc -l)
  [[ $rerun == true ]] && echo -e "${GREEN}${BOLD}[$] New Subdomains Collected ${NC}[$nsdc] [$results/newsubdomains.tmp]"
  
  [[ -e $results/newsubdomains.tmp ]] && cat $results/newsubdomains.tmp | anew -q $subdomains
  [[ -e $results/subdomains.tmp ]] && rm $results/subdomains.tmp

  sdc=$(<$subdomains wc -l)
  echo -e "${GREEN}${BOLD}[$] Subdomains Collected ${NC}[$sdc] [$subdomains]"
}

function jsubfinder(){
  jsubfinderin=$1
  jsubfinderout=$2
  trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
  echo -e ""
  echo -e "${YELLOW}[*] Gathering Subdomains from Webpage and Javascript on $domain ${NC}"
  echo -e "${BLUE}[#] interlace -tL $jsubfinderin -o $jsubfinderout -c 'echo _target_ | jsubfinder search --crawl -t 20 -K | anew _output_ -q'${NC}"
  echo -e ""
  [ ! -e $jsubfinderout ] && interlace -tL $jsubfinderin -o $jsubfinderout -c "echo _target_ | jsubfinder search --crawl -t 20 -K | anew _output_ -q" --silent | pv -p -t -e -N "Gathering Subdomains from JS" >/dev/null
  jsub_sdc=$(cat $jsubfinderout | anew $subdomains | wc -l)
  total_sdc=$(cat $subdomains | wc -l)
  echo -e "${GREEN}[$] Unique Subdomains Collected from JSubfinder${NC}[$jsub_sdc]"
  echo -e "${GREEN}[$] Total Subdomains Collected ${NC}[$total_sdc]"
}

function dnsreconbrute(){
  # DNS Subdomain Bruteforcing
  domain=$1
  dnsbruteout=$2
  trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
  echo -e ""
  echo -e "${YELLOW}[*] Bruteforcing Subdomains DNSRecon${NC}"
  dmut --update-files &>/dev/null
  [[ ! -e $dnsbruteout  || $rerun == true ]] && echo -e "${BLUE}dmut -u "$domain" $dmut_flags -o $dnsbruteout ${NC}"
  [[ ! -e $dnsbruteout  || $rerun == true ]] && dmut -u "$domain" $dmut_flags -o $dnsbruteout
  [[ $alterx == true  && ! -e $dnsbruteout || $rerun == true ]] && echo -e "${YELLOW}[*] Performing Alterx Bruteforcing using DNSx ${NC}"
  [[ $alterx == true  && ! -e $dnsbruteout || $rerun == true ]] && echo -e "${BLUE}[#] cat $subdomains | alterx -silent | dnsx -silent -r /root/.dmut/resolvers.txt | anew -q $dnsbruteout ${NC}"
  [[ $alterx == true  && ! -e $dnsbruteout || $rerun == true ]] && cat $subdomains | alterx | dnsx -r /root/.dmut/resolvers.txt | anew $dnsbruteout | pv -p -t -e -N "Subdomain Bruteforcing using DNSx on Alterx Generated Domains" &>/dev/null 2>&1
  [[ -e $dnsbruteout ]] && grep -Fxvf $subdomains $dnsbruteout | anew -q $results/brutesubdomains.tmp
  [[ -e $dnsbruteout ]] && dnsbrute_sdc=$(cat $dnsbruteout | wc -l)
  [[ -e $dnsbruteout ]] && cat $dnsbruteout | anew -q $subdomains
  [[ -e $results/brutesubdomains.tmp ]] && dnsbrute_sdc=$(cat $results/brutesubdomains.tmp | wc -l)
  [[ -e $results/brutesubdomains.tmp ]] && cat $results/brutesubdomains.tmp | anew -q $subdomains 
  total_sdc=$(cat $subdomains | wc -l)

  echo -e ""
  echo -e "${GREEN}[$] New Unique Subdomains found by bruteforcing${NC} [$dnsbrute_sdc]"
  echo -e "${GREEN}[$] Total Subdomains Enumerated${NC} [$total_sdc]"
}

function subdomaintakeover(){
  mkdir -p $enumscan
  trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
  echo -e ""
  echo -e "${YELLOW}[*] Running Subdomain Takeover Scan\n${NC}" 

  if [ -e $urlprobed ]; then
      trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
      [ ! -e $enumscan/nuclei-takeover.txt || $rerun == true ] && echo -e "${BLUE}[#] nuclei -l $urlprobed -t ~/nuclei-templates/takeovers/ -silent | anew $enumscan/nuclei-takeover.txt ${NC}" 
      [ ! -e $enumscan/nuclei-takeover.txt || $rerun == true ] && nuclei -l $urlprobed -t ~/nuclei-templates/takeovers/ -silent | anew $enumscan/nuclei-takeover.txt 2>/dev/null
  fi
  if [ -e $subdomains ]; then
      trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
      [ ! -e $enumscan/subjack-takeover.txt || $rerun == true ] && echo -e "${BLUE}[#] subjack -w $subdomains -t 100 -timeout 30 -ssl -c ./MISC/fingerprints.json | anew $enumscan/subjack-takeover.txt ${NC}" 
      [ ! -e $enumscan/subjack-takeover.txt || $rerun == true ] && subjack -w $subdomains -t 100 -timeout 30 -ssl -c ./MISC/fingerprints.json | anew $enumscan/subjack-takeover.txt 2>/dev/null
  fi
}

function httpprobing(){
  webtechcheck(){
    urlprobed=$1 webtech=$2
    webanalyze -update &>/dev/null 2>&1
    echo -e ""
    echo -e "${YELLOW}[*] Running WebTechCheck\n${NC}"
    [[ ! -e $webtech || $rerun == true ]] && echo -e "${BLUE}[#] webanalyze -hosts $urlprobed $webanalyze_flags -output csv | anew $webtech ${NC}" 
    [[ ! -e $webtech || $rerun == true ]] && webanalyze -hosts $urlprobed $webanalyze_flags -output csv 2>/dev/null | anew -q $webtech &>/dev/null 2>&1
    echo -e "${GREEN}[+] WebTechCheck Scan Completed\n${NC}"
  }
  echo -e "${YELLOW}[*] HTTP Probing${NC}"
  hostlist=$1
  httpxout=$2
  
  if [ -f "$hostlist" ]; then
    [[ ! -e $httpxout || $rerun == true ]] && echo -e "${BLUE}[#] cat $hostlist | httpx $httpx_flags -csv | anew -q $httpxout ${NC}"
    [[ ! -e $httpxout || $rerun == true ]] && cat $hostlist | httpx $httpx_flags -csv | anew -q $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
    [ -e $httpxout ] && echo -e "${GREEN}[+] HTTP Probe Output:${NC} $httpxout"
  else
    echo "${BLUE}[#] echo $hostlist | httpx $httpx_flags -csv | anew -q $httpxout ${NC}"
    [[ ! -e $httpxout || $rerun == true ]] && echo $hostlist | httpx $httpx_flags -csv | anew -q $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
  fi

  [[ ! -e $urlprobed || $rerun == true ]] && csvcut $httpxout -c url 2>/dev/null | grep -v url | anew $urlprobed &>/dev/null 2>&1
  [[ "$all" == true && -f "$results/httpxout2.csv" ]] && csvstack $results/httpxout.csv $results/httpxout2.csv | csvcut -c url 2>/dev/null | grep -v url | anew $urlprobed &>/dev/null 2>&1
  urlpc=$(<$urlprobed wc -l)
  echo -e "${GREEN}${BOLD}[$] Total URL Probed ${NC}[$urlpc] [$urlprobed]"


  if [[ ${ipscan} == true ]] || [[ ${hostportscan} == true ]];then
      echo -e "${YELLOW}[*] Extracting Potential URLs${NC}"
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout | awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 ~ /^http/ {print $3}' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout | awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 == "" {print $1}' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
  fi
  
  if [[ ${domainscan} == true ]];then
      echo -e "${YELLOW}[*] Extracting Potential URLs${NC}"
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout | awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 ~ /^http/ {print $3}' | grep -oE "^https?://[^/]*\.$domain(:[0-9]+)?" | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout | awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 == "" {print $1}' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
  fi
       
  [ -e $potentialsdurls-tmp ] &&  cat $potentialsdurls-tmp | sed 's/\b:80\b//g;s/\b:443\b//g' | sort -u | anew -q $potentialsdurls &>/dev/null 2>&1
  rm $potentialsdurls-tmp 
        
  purlc=$(<$potentialsdurls wc -l)
  echo -e "${GREEN}${BOLD}[$] Potential URL Extracted ${NC}[$purlc] [$potentialsdurls]"

  # echo -e "${GREEN}[+] HTTPX Probe Completed\n${NC}"
  [ ! -e $webtech ] && webtechcheck $urlprobed $webtech
}

function dnsresolve(){
  dnsresolvein=$1
  dnsreconout=$2
  dnsxresolved=$3
  echo -e "${YELLOW}[*] DNS Resolving${NC}"
  dmut --update-files &>/dev/null  
  [[ ! -e $dnsreconout || $rerun == true ]] && echo -e "${BLUE}[#] cat $dnsresolvein | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew $dnsreconout ${NC}"
  [[ ! -e $dnsreconout || $rerun == true ]] && cat $dnsresolvein | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew -q $dnsreconout | pv -p -t -e -N "Running DNSx" >/dev/null
    
    dnspc=$(<$dnsreconout wc -l)
    echo -e "${GREEN}${BOLD}[$] Subdomains DNS Resolved ${NC}[$dnspc] [$dnsreconout]"
    
    echo -e "${YELLOW}[*] Extracting DNS Resolved IP's ${NC}"
    cat $dnsreconout | cut -d ' ' -f 2 | sort -u | awk -F'[][]' '{print $2}' | grep -vE 'autodiscover|microsoft' | anew -q $dnsxresolved
    dnsxr=$(<$dnsxresolved wc -l)
    echo -e "${GREEN}${BOLD}[$] Unique Host Resolved ${NC}[$dnsxr] [$dnsxresolved]"
}

function portscanner(){
  portscannerin=$1
  naabuout=$2
  
  scanner(){
    ports=$(cat $ipport| grep $iphost | cut -d ':' -f 2 | xargs | sed -e 's/ /,/g')
      if [ -z "$ports" ]
      then
          echo -e "No Ports found for $iphost"
      else
          echo -e ""
          echo -e ${CYAN}"[$] Running Nmap Scan on"${NC} $iphost ======${CYAN} $ports ${NC}
          if [ -n "$(find $nmapscans -maxdepth 1 -name 'nmapresult-$iphost*' -print -quit)" ]; then
            echo -e "${CYAN}Nmap result exists for $iphost, Skipping this host...${NC}"
          else
            [ ! -e $nmapscans/nmapresult-$iphost.nmap ] && nmap $iphost -p $ports $nmap_flags -oX $nmapscans/nmapresult-$iphost.xml -oN $nmapscans/nmapresult-$iphost.nmap &>/dev/null
          fi
      fi
    }

  nmapconverter(){
    rm $nmapscans/*.html &>/dev/null
    rm $nmapscans/*.csv &>/dev/null
    # Convert to csv
    ls $nmapscans/*.xml | xargs -I {} python3 $PWD/MISC/xml2csv.py -f {} -csv {}.csv &>/dev/null 
    echo -e "${GREEN}[+] All Nmap CSV Generated ${NC}"
    
    # Merge all csv
    [ ! -e $nmapscans/Nmap_Final_Merged.csv ] && csvstack $nmapscans/*.csv > $nmapscans/Nmap_Final_Merged.csv 2>/dev/null
    echo -e "${GREEN}[+] Merged Nmap CSV Generated ${NC}$nmapscans/Nmap_Final_Merged.csv"
    
    # Generating HTML Report Format
    ls $nmapscans/*.xml | xargs -I {} xsltproc -o {}_nmap.html ./MISC/nmap-bootstrap.xsl {} 2>$nmapscans/error.log
    echo -e "${GREEN}[+] HTML Report Format Generated ${NC}"
    
    # Generating RAW Colored HTML Format
    ls $nmapscans/*.nmap | xargs -I {} sh -c 'cat {} | ccze -A | ansi2html > {}_nmap_raw_colored.html' 2>$nmapscans/error.log
    echo -e "${GREEN}[+] HTML RAW Colored Format Generated ${NC}"
  }

  nmapscanner(){
      if [[ $nmap == "true" ]];then
          mkdir -p $nmapscans
          echo -e ${YELLOW}"[*] Running Nmap Scan"${NC}
          counter=0
          while read iphost; do
              scanner
              counter=$((counter+1))
              progress=$(($counter * 100 / $(wc -l < "$aliveip")))
              printf "Progress: [%-50s] %d%%\r" $(head -c $(($progress / 2)) < /dev/zero | tr '\0' '#') $progress
          done <"$aliveip"
          [ -e "$nmapscans/Nmap_Final_Merged.csv" ] && echo -e "$nmapscans/Nmap_Final_Merged.csv Exist" || nmapconverter
      fi
  }

  echo -e "${YELLOW}[*] Port Scanning on DNS Probed Hosts${NC}"

  # This will check if naaabuout file is present than extract aliveip and if nmap=true then run nmap on each ip on respective open ports.
  if [[ $hostportscan == true ]] && [ -f $portscannerin ]; then
      declared_paths
      cat $hostportlist | cut -d : -f 1 | anew $aliveip -q &>/dev/null
      ipport=$hostportlist
      nmapscanner
  elif [ -f "$naabuout" ]; then
      [ ! -e $aliveip ] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q &>/dev/null
      [ ! -e $ipport ] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
      nmapscanner
  # else run naabu to initiate port scan
  # starts from here
  else
    if [ -f "$portscannerin" ]; then
        echo -e ""
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -list $portscannerin $naabu_flags -o $naabuout -csv" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -list $portscannerin $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q &>/dev/null 2>&1   
        [[ ! -e $ipport || $rerun == true ]] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout" ${NC}
        nmapscanner
    else
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -host $portscannerin $naabu_flags -o $naabuout -csv" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -host $portscannerin $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q &>/dev/null
        [ ! -e $hostport ] && csvcut -c host,port $naabuout 2>/dev/null | tr ',' ':' | anew $hostport -q &>/dev/null         
        [[ ! -e $ipport || $rerun == true ]] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout" ${NC}
        nmapscanner
	  fi
  fi
}

function portmapper(){
    mapper(){
        while read dnshost; do
            if grep -q "$dnshost" $naabuout; then
                subdomains=($(grep "$dnshost" $dnsreconout | cut -d ' ' -f 1))
                ports=($(grep -w "$dnshost" $naabuout | awk -F ',' '{print $3}'))
                for subdomain in "${subdomains[@]}"; do
                    for port in "${ports[@]}"; do
                        echo "${subdomain}:${port}" | anew -q $hostport
                    done
                done
            fi
        done < $dnsxresolved
    }
    echo -e ${YELLOW}"[*] Mapping Ports to Subdomains${NC} $dnsprobe $naabuout" 
    [ ! -e $hostport ] && mapper
}

function active_recon(){
    
    techdetect(){
      [ -e $results/httpxmerge.csv ] && urls=($(csvcut -c url,tech $results/httpxmerge.csv | grep -i $1 | cut -d ',' -f 1))
      [ -e $results/httpxout.csv ] && urls=($(csvcut -c url,tech $results/httpxout.csv | grep -i $1 | cut -d ',' -f 1))
      urls+=($(csvcut -c Host,Category,App $webtech | grep -i $1 | cut -d ',' -f 1))
      result=$(printf "%s\n" "${urls[@]}")
      for url in $result; do
          echo $url | grep -oE "^https?://[^/]*(:[0-9]+)?"
      done
    }
    # techdetect function can be use to run with manual tools; see below examples; altough nuclei has automatic-scan feature now.
    wordpress_recon(){
        techdetect WordPress | anew $enumscan/wordpress_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/wordpress_urls.txt ];then
            echo -e ""
            echo -e "${YELLOW}[*] Running Wordpress Recon\n${NC}"
            echo -e "${BLUE}[*] nuclei -l $enumscan/wordpress_urls.txt -w ~/nuclei-templates/workflows/wordpress-workflow.yaml -o $enumscan/wordpress_nuclei_results.txt \n${NC}"
            [ ! -e $enumscan/wordpress_nuclei_results.txt ] && nuclei -l $enumscan/wordpress_urls.txt -w ~/nuclei-templates/workflows/wordpress-workflow.yaml -o $enumscan/wordpress_nuclei_results.txt
        #   [ ! -e $enumscan/*_wpscan_result.txt ] && interlace -tL $enumscan/wordpress_urls.txt -threads 5 -c "wpscan --url _target_ $wpscan_flags -o $enumscan/_cleantarget_wpscan_result.txt"
        fi
    }

    joomla_recon(){
        techdetect joomla | anew $enumscan/joomla_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/joomla_urls.txt ];then
            echo -e ""
            echo -e "${YELLOW}[*] Running Joomla Recon\n${NC}"
            echo -e "${BLUE}[*] nuclei -l $enumscan/joomla_urls.txt -w ~/nuclei-templates/workflows/joomla-workflow.yaml -o $enumscan/joomla_nuclei_results.txt\n${NC}"
            [ ! -e $enumscan/joomla_nuclei_results.txt ] && nuclei -l $enumscan/joomla_urls.txt -w ~/nuclei-templates/workflows/joomla-workflow.yaml -o $enumscan/joomla_nuclei_results.txt
        fi
    }

    drupal_recon(){
        techdetect Drupal | anew $enumscan/drupal_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/drupal_urls.txt ];then
            echo -e ""
            echo -e "${YELLOW}[*] Running Drupal Recon\n${NC}"
            echo -e "${BLUE}[*] nuclei -l $enumscan/drupal_urls.txt -w ~/nuclei-templates/workflows/drupal-workflow.yaml -o $enumscan/drupal_nuclei_results.txt\n${NC}"
            [ ! -e $enumscan/drupal_nuclei_results.txt ] && nuclei -l $enumscan/drupal_urls.txt -w ~/nuclei-templates/workflows/drupal-workflow.yaml -o $enumscan/drupal_nuclei_results.txt
        fi
    }

    jira_recon(){
        techdetect jira | anew $enumscan/jira_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/jira_urls.txt ];then
            echo -e ""
            echo -e "${YELLOW}[*] Running Jira Recon\n${NC}"
            echo -e "${BLUE}[*] nuclei -l $enumscan/jira_urls.txt -w ~/nuclei-templates/workflows/jira-workflow.yaml -o $enumscan/jira_nuclei_results.txt\n${NC}" 
            [ ! -e $enumscan/jira_nuclei_results.txt ] && nuclei -l $enumscan/jira_urls.txt -w ~/nuclei-templates/workflows/jira-workflow.yaml -o $enumscan/jira_nuclei_results.txt
        fi
    }

    jenkins_recon(){
        techdetect jenkins | anew $enumscan/jenkins_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/jenkins_urls.txt ];then
            echo -e ""
            echo -e "${YELLOW}[*] Running Jenkins Recon\n${NC}"
            echo -e "${BLUE}[*] nuclei -l $enumscan/jenkins_urls.txt -w ~/nuclei-templates/workflows/jenkins-workflow.yaml -o $enumscan/jenkins_nuclei_results.txt\n${NC}" 
            [ ! -e $enumscan/jenkins_nuclei_results.txt ] && nuclei -l $enumscan/jenkins_urls.txt -w ~/nuclei-templates/workflows/jenkins-workflow.yaml -o $enumscan/jenkins_nuclei_results.txt
        fi
    }

    azure_recon(){
        techdetect azure | anew $enumscan/azure_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/azure_urls.txt ];then
            echo -e ""
            echo -e "${YELLOW}[*] Running Azure Recon\n${NC}"
            echo -e "${BLUE}[*] nuclei -l $enumscan/azure_urls.txt -w ~/nuclei-templates/workflows/azure-workflow.yaml -o $enumscan/azure_nuclei_results.txt\n${NC}" 
            [ ! -e $enumscan/azure_nuclei_results.txt ] && nuclei -l $enumscan/azure_urls.txt -w ~/nuclei-templates/workflows/azure-workflow.yaml -o $enumscan/azure_nuclei_results.txt
        fi
    }
    
    # Add your custom function here; Refer above

    auto_nuclei(){
        echo -e ""
        echo -e "${YELLOW}[*] Running Nuclei Automatic-Scan\n${NC}"
        [[ ! -e $enumscan/nuclei_pot_autoscan.txt || $rerun == true ]] && echo "${BLUE}[#] nuclei -l $urlprobed $nuclei_flags -resume -as -silent | anew $enumscan/nuclei_pot_autoscan.txt ${NC}"
        [[ ! -e $enumscan/nuclei_pot_autoscan.txt || $rerun == true ]] && nuclei -l $urlprobed $nuclei_flags -resume -as -silent | anew $enumscan/nuclei_pot_autoscan.txt
    }

    full_nuclei(){
        echo -e ""
        echo -e "${YELLOW}[*] Running Nuclei Full-Scan\n${NC}"
        [[ ! -e $enumscan/nuclei_full.txt || $rerun == true ]] && echo "${BLUE}[#] nuclei -l $urlprobed $nuclei_flags -resume -silent | anew $enumscan/nuclei_full.txt ${NC}"
        [[ ! -e $enumscan/nuclei_full.txt || $rerun == true ]] && nuclei -l $urlprobed $nuclei_flags -resume -silent | anew $enumscan/nuclei_full.txt
    }

    js_recon(){
        echo -e ""
        echo -e "${YELLOW}[*] Performing JS Recon from Webpage and Javascript on $domain ${NC}"
        ## Thanks to @KathanP19 and Other Community members
        passivereconurl(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC} "' SIGINT
            
            [ ! -e $enumscan/URLs/gau-allurls.txt ] && echo -e "${BLUE}[*] Gathering URLs - Passive Recon using Gau >>${NC} $enumscan/URLs/gau-allurls.txt"
            [ ! -e $urlprobedsd ] && cat $urlprobed | awk -F[/:] '{print $4}' | anew $urlprobedsd -q &>/dev/null 2>&1
            [ ! -e $enumscan/URLs/gau-allurls.txt ] && interlace --silent -tL $urlprobedsd -o $enumscan -cL ./MISC/passive_recon.il 2>/dev/null | pv -p -t -e -N "Gathering URLs from Gau" >/dev/null
            
            [ ! -e $enumscan/URLs/subjs-allurls.txt ] && echo -e "${BLUE}[*] Gathering URLs - Passive Recon using Subjs >>${NC} $enumscan/URLs/subjs-allurls.txt"
            [ ! -e $enumscan/URLs/subjs-allurls.txt ] && interlace --silent -tL $urlprobed -o $enumscan -c "echo _target_ | subjs | anew _output_/URLs/subjs-allurls.txt -q" 2>/dev/null | pv -p -t -e -N "Gathering JS URLs from Subjs" >/dev/null
        }

        activereconurl(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/katana-allurls.txt ] && echo -e "${BLUE}[*] Gathering URLs - Active Recon using Katana >>${NC} $enumscan/URLs/katana-allurls.txt"
            [ ! -e $enumscan/URLs/katana-allurls.txt ] && katana -list $urlprobed -d 10 -c 50 -p 20 -ef "ttf,woff,woff2,svg,jpeg,jpg,png,ico,gif,css" -jc -kf robotstxt,sitemapxml -aff --silent | anew $enumscan/URLs/katana-allurls.txt -q | pv -p -t -e -N "Katana is running" >/dev/null
        }
        
        pot_url(){
            alluc=$(cat $enumscan/URLs/*-allurls.txt | wc -l)
            echo -e "${GREEN}${BOLD}[$] All URLs Gathered ${NC}[$alluc] [$enumscan/URLs/*-allurls.txt]"
            
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            
            [ ! -e $enumscan/URLs/potentialurls.txt ] && echo -e "${BLUE}[*] Taking out Potential URLs >>${NC} $enumscan/URLs/potentialurls.txt"
            [ ! -e $enumscan/URLs/potentialurls.txt ] && cat $enumscan/URLs/*-allurls.txt | gf excludeExt | anew $enumscan/URLs/potentialurls.txt -q &>/dev/null 2>&1
            
            potuc=$(<$enumscan/URLs/potentialurls.txt wc -l)
            echo -e "${GREEN}[$] Total Potential URLs ${NC}[$potuc]"
            
            [ ! -e $enumscan/URLs/paramurl.txt ] && echo -e "${BLUE}[*] QSInjecting Unique parameter URLs >>${NC} $enumscan/URLs/paramurl.txt"
            [ ! -e $enumscan/URLs/paramurl.txt ] && cat $enumscan/URLs/potentialurls.txt | qsinject -c MISC/qs-rules.yaml 2>/dev/null | anew $enumscan/URLs/paramurl.txt -q &>/dev/null
            
            purl=$(<$enumscan/URLs/paramurl.txt wc -l)
            echo -e "${GREEN}${BOLD}[$] Unique parameter URLs ${NC}[$purl] [$enumscan/URLs/paramurl.txt]"
        }

        jsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/alljsurls.txt ] && echo -e "${BLUE}[*] Extracting JS URLs >>${NC} $enumscan/URLs/*-allurls.txt"
            [ ! -e $enumscan/URLs/alljsurls.txt ] && cat $enumscan/URLs/*-allurls.txt | egrep -iv '\.json' | grep -iE "\.js$" | anew $enumscan/URLs/alljsurls.txt -q &>/dev/null 2>&1
            ajsuc=$(<$enumscan/URLs/alljsurls.txt wc -l)
            echo -e "${GREEN}${BOLD}[$] All JS URLs Gathered ${NC}[$ajsuc] [$enumscan/URLs/alljsurls.txt]"
        }
        
        validjsurlextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/validjsurls.txt ] && echo -e "${BLUE}[*] Finding All Valid JS URLs >>${NC} $enumscan/URLs/validjsurls.txt"
            [ ! -e $enumscan/URLs/validjsurls.txt ] && cat $enumscan/URLs/alljsurls.txt| python3 ./MISC/antiburl.py -N 2>&1 | grep '^200' | awk '{print $2}' | anew $enumscan/URLs/validjsurls.txt -q 2>/dev/null | pv -p -t -e -N "Finding All Valid JS URLs" >/dev/null
            vjsuc=$(<$enumscan/URLs/validjsurls.txt wc -l)
            echo -e "${GREEN}${BOLD}[$] Valid JS URLs Extracted ${NC}[$vjsuc] [$enumscan/URLs/validjsurls.txt]"
        }
        
        endpointsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/endpointsfromjs.txt ] && echo -e "${BLUE}[*] Enumerating Endpoints from valid JS files >> ${NC}$enumscan/URLs/endpointsfromjs.txt"
            [ ! -e $enumscan/URLs/endpointsfromjs.txt ] && interlace --silent -tL $enumscan/URLs/validjsurls.txt -c "python3 ./MISC/LinkFinder/linkfinder.py -d -i '_target_' -o cli | anew -q $enumscan/URLs/endpointsfromjs_tmp.txt" 2>/dev/null | pv -p -t -e -N "Enumerating Endpoints from valid js files" >/dev/null
            [ -e $enumscan/URLs/endpointsfromjs_tmp.txt ] && cat $enumscan/URLs/endpointsfromjs_tmp.txt | grep -vE 'Running against|Invalid input' | anew $enumscan/URLs/endpointsfromjs.txt -q 2>/dev/null && rm $enumscan/URLs/endpointsfromjs_tmp.txt
        }
        
        secretsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/secretsfromjs.txt ] && echo -e "${BLUE}[*] Enumerating Secrets from valid JS files >> ${NC}$enumscan/URLs/secretsfromjs.txt"
            [ ! -e $enumscan/URLs/secretsfromjs.txt ] && interlace --silent -tL $enumscan/URLs/validjsurls.txt -c "python3 MISC/SecretFinder/SecretFinder.py -i '_target_' -o cli 2>/dev/null| anew $enumscan/URLs/secretsfromjs.txt" 2>/dev/null | pv -p -t -e -N "Enumerating Secrets from valid js files" >/dev/null
        }

        domainfromjsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/domainfromjs.txt ] && echo -e "${BLUE}[*] Enumerating Domains from valid JS files >> ${NC}$enumscan/URLs/domainfromjs.txt"
            [ ! -e $enumscan/URLs/domainfromjs.txt ] && interlace --silent -tL $enumscan/URLs/validjsurls.txt -c "python3 MISC/SecretFinder/SecretFinder.py -i '_target_' -o cli  -r "\S+$domain" 2>/dev/null | anew $enumscan/URLs/domainfromjs.txt" 2>/dev/null | pv -p -t -e -N "Enumerating Domain from valid js files" >/dev/null
        }
        
        wordsfromjsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/wordsfromjs.txt ] && echo -e "${BLUE}[*] Gathering Words from valid JS files >> ${NC}$enumscan/URLs/wordsfromjs.txt"
            [ ! -e $enumscan/URLs/wordsfromjs.txt ] && cat $enumscan/URLs/validjsurls.txt | python3 ./MISC/getjswords.py 2>/dev/null | anew $enumscan/URLs/wordsfromjs.txt 2>/dev/null| pv -p -t -e -N "Gathering words from valid js files" >/dev/null
        }

        varjsurlsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
            [ ! -e $enumscan/URLs/varfromjs.txt ] && echo -e "${BLUE}[*] Gathering Variables from valid JS files >> ${NC}$enumscan/URLs/varfromjs.txt"
            [ ! -e $enumscan/URLs/varfromjs.txt ] && interlace --silent -tL $enumscan/URLs/validjsurls.txt -c "bash ./MISC/jsvar.sh _target_ 2>/dev/null | anew $enumscan/URLs/varfromjs.txt" 2>/dev/null | pv -p -t -e -N "Gathering Variables from valid js files" >/dev/null
        }

        if [ -s $urlprobed ]; then
            passivereconurl
            activereconurl
        fi  
        if [ -s $enumscan/URLs/gau-allurls.txt ]; then
            jsextractor
            pot_url
            validjsurlextractor
        fi
        if [ -s $enumscan/URLs/validjsurls.txt ]; then
            endpointsextractor
            secretsextractor
            domainfromjsextractor
            wordsfromjsextractor
            varjsurlsextractor
        fi
    }

    xnl(){
        echo -e "${BLUE}[*] python3 ./MISC/waymore/waymore.py -i $domain -mode B -oU $enumscan/URLs/waymore.txt -oR $enumscan/URLs/waymoreResponses/\n${NC}" 
        [ ! -f $enumscan/URLs/waymore.txt ] && python3 ./MISC/waymore/waymore.py -i $domain -mode B -oU $enumscan/URLs/waymore.txt -oR $enumscan/URLs/waymoreResponses/
        
        echo -e "${BLUE}[*] python3 ./MISC/xnLinkFinder/xnLinkFinder.py -i $enumscan/URLs/waymoreResponses/ -sp $urlprobed -sf $domain -o $enumscan/URLs/xnLinkFinder_links.txt -op $enumscan/URLs/xnLinkFinder_parameters.txt -owl $enumscan/URLs/xnLinkFinder_wordlist.txt \n${NC}" 
        [ -d $enumscan/URLs/waymoreResponses ] && python3 ./MISC/xnLinkFinder/xnLinkFinder.py -i $enumscan/URLs/waymoreResponses/ -sp $urlprobed -sf $domain -o $enumscan/URLs/xnLinkFinder_links.txt -op $enumscan/URLs/xnLinkFinder_parameters.txt -owl $enumscan/URLs/xnLinkFinder_wordlist.txt 
        
        echo -e "${BLUE}[*] trufflehog filesystem $enumscan/URLs/waymoreResponses --only-verified | anew -q $enumscan/URLs/trufflehog-results.txt\n${NC}" 
        [ -d $enumscan/URLs/waymoreResponses ] && trufflehog filesystem $enumscan/URLs/waymoreResponses --only-verified | anew -q $enumscan/URLs/trufflehog-results.txt
    }

    function content_discovery(){
      mergeffufcsv(){
          echo -e "${YELLOW}[*] Merging All Content Discovery Scan CSV - ${NC}\n"
          if [ -d $enumscan/contentdiscovery ] && [ ! -f $enumscan/contentdiscovery/all-cd.csv ]; then
              csvstack $enumscan/contentdiscovery/*.csv > $enumscan/contentdiscovery/all-cd.csv 2>/dev/null
              csvcut -c redirectlocation,content_length $enumscan/contentdiscovery/all-cd.csv | grep '200' | cut -d , -f 1 | anew $enumscan/contentdiscovery/all-cd.txt
              echo -e "${GREEN}[*] Merged All Content Discovery Scan CSV - ${NC}$enumscan/contentdiscovery/all-cd.csv\n"
          fi
      }
      
      ffuflist(){
          trap 'echo -e "${RED}Ctrl + C detected in content_discovery${NC}"' SIGINT
          echo -e "${YELLOW}[*] Running Content Discovery Scan - FFUF using dirsearch wordlist\n${NC}"
          echo -e "${BLUE}[*] interlace -tL $1 -o $enumscan/contentdiscovery -cL ./MISC/contentdiscovery.il --silent ${NC}"
          echo -e "${BLUE}[*contentdiscovery.il*] ffuf -u _target_/FUZZ -w /usr/share/dirb/wordlists/dicc.txt -sa -of csv -mc 200,201,202,203,403 -fl 0 -c -ac -recursion -recursion-depth 2 -s -v -o _output_/_cleantarget_-cd.csv ${NC}"
          if [ "$(ls -A $enumscan/contentdiscovery 2>/dev/null)" = "" ]; then
              echo -e ""
              mkdir -p $enumscan/contentdiscovery
              [ -e $1 ] && interlace -tL $1 -o $enumscan/contentdiscovery -cL ./MISC/contentdiscovery.il --silent 2>/dev/null| pv -p -t -e -N "Content Discovery using FFUF with Dirsearch wordlist" >/dev/null
              echo -e "${GREEN}[*] Content Discovery Scan Completed CSV - ${NC}\n"
          else
              echo -e "${RED}ContentDiscovery Directory already exist; Remove $enumscan/contentdiscovery directory if you want to re-run.${NC}"
          fi
          mergeffufcsv
      }

      nuclei_exposure(){
          trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
          echo -e ""
          echo -e "${YELLOW}[*] Running Nuclei Exposure Scan\n${NC}"
          
          if [[ -f "$1" ]]; then
              echo -e "${BLUE}[*] nuclei -l $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt\n${NC}"
              [ ! -e $enumscan/contentdiscovery/nuclei-exposure.txt ] && nuclei -l $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt
          else
              echo -e "${BLUE}[*] nuclei -u $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt\n${NC}"
              [ ! -e $enumscan/contentdiscovery/nuclei-exposure.txt ] && nuclei -u $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt
          fi
      }

      #[[ -f $1 ]] && cat $1 | dirsearch --stdin $dirsearch_flags --format csv -o $enumscan/dirsearch_results.csv 2>/dev/null
      [[ -f $1 ]] && ffuflist $1 && nuclei_exposure $1
      [[ ! -f $1 ]] && dirsearch $dirsearch_flags -u $1 -o $enumscan/$1_dirsearch.csv 2>/dev/null && nuclei_exposure $1
    }

    wordpress_recon
    joomla_recon
    drupal_recon
    jira_recon
    jenkins_recon
    azure_recon
    auto_nuclei || echo -e "${BLUE}[*] Nuclei Automatic Scan on $potentialsdurls >> ${NC}$enumscan/nuclei_pot_autoscan.txt"
    [[ "$all" == true ]] && full_nuclei || echo -e "${BLUE}[*] Nuclei Full Scan on $potentialsdurls >> ${NC}$enumscan/nuclei_full.txt"
    [[ ${jsrecon} == true ]] && js_recon
    [[ ${enumxnl} == true && ! -f $domain ]] && xnl

    [[ ${contentscan} == true || ${all} == true ]] && { [[ ${cdlist} ]] && content_discovery $cdlist || content_discovery $potentialsdurls; }
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
    [[ "$takeover" == true ]] && subdomaintakeover
    httpprobing "$results/subdomains.txt" "$results/httpxout.csv"
    [ -e $results/brutesubdomains.tmp ] && httpprobing $results/brutesubdomains.tmp $results/httpxout.csv
    if [[ "$all" == true && -f "$results/httpxout.csv" ]]; then
      dnsresolve "$results/subdomains.txt" "$results/dnsreconout.txt" "$results/dnsxresolved.txt"
      portscanner "$results/dnsxresolved.txt" "$results/naabuout.csv" && portmapper
      cat $hostport | grep -v ":80\|:443" | anew -q $hostport-tmp
      echo -e "${YELLOW}[*] Rerunning HTTP Probing excluding port 80 & 443${NC}"
      httpprobing "$hostport-tmp" "$results/httpxout2.csv"
      [ -e $results/httpxout2.csv ] && csvstack $results/httpxout.csv $results/httpxout2.csv > $results/httpxmerge.csv
    fi
    
    # [[ ${enum} == true || $all == true ]] && [[ -e $results/httpxmerge.csv ]] && active_recon
        if [[ ${enum} == true ]];then
            [[ -e ${httpxout} ]] && active_recon
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
    
    if [[ "$all" == true && -f "$results/httpxout.csv" ]]; then
      dnsresolve "$results/subdomains.txt" "$results/dnsreconout.txt" "$results/dnsxresolved.txt"
      portscanner "$results/subdomains.txt" "$results/naabuout.csv"
      cat $hostport | grep -v ":80\|:443" | anew -q $hostport-tmp
      echo -e "${MAGENTA}Http Probing excluding port 80 & 443${NC}"
      httpprobing "$hostport-tmp" "$results/httpxout2.csv"
      [ -e $results/httpxout2.csv ] && csvstack $results/httpxout.csv $results/httpxout2.csv > $results/httpxmerge.csv
    fi

    #[[ $enum == true || $all == true ]] && [[ -e $results/httpxmerge.csv ]] && active_recon
      if [[ ${enum} == true ]];then
          [[ -e ${httpxout} ]] && active_recon
      fi
    #---------------------------------------------------#
  elif [[ $singledomain == true && -n "$domain" ]];then
    echo -e "Single Domain Module $domain"
    results="$results/$domain"
    declared_paths
    declare
    portscanner "$domain" "$results/naabuout.csv"
    httpprobing "$hostport" "$results/httpxout.csv"
    #[[ $enum == true || $all == true ]] && [[ -e $results/httpxmerge.csv ]] && active_recon
    if [[ ${enum} == true ]];then
        [[ -e ${httpxout} ]] && active_recon
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
}

function runhostportscan(){
  echo -e "${MAGENTA}[*] HostPort Scan is Running on $hostportlist${NC}"
  if [ -n "${hostportlist}" ];then
    declared_paths
    declare
    httpprobing "$hostportlist" "$results/httpxout.csv"
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
    -js|--jsrecon)
      jsrecon=true
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
