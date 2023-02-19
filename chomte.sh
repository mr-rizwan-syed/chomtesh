#!/bin/bash
#title: CHOMTE.SH
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       3.5.8
#==============================================================================
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
NC=`tput sgr0`
wul=`tput smul`

# sed -i 's/\s\+/ /g' flags.conf

subfinder_flags=$(grep '^subfinder_flags=' flags.conf | awk -F= '{print $2}' | xargs)
dmut_flags=$(grep '^dmut_flags=' flags.conf | awk -F= '{print $2}' | xargs)
naabu_flags=$(grep '^naabu_flags=' flags.conf | awk -F= '{print $2}' | xargs)
httpx_flags=$(grep '^httpx_flags=' flags.conf | awk -F= '{print $2}' | xargs)
webanalyze_flags=$(grep '^webanalyze_flags=' flags.conf | awk -F= '{print $2}' | xargs)
nmap_flags=$(grep '^nmap_flags=' flags.conf | awk -F= '{print $2}' | xargs)


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

function trap_ctrlc ()
{
    echo "Ctrl-C caught...performing clean up"
    echo "Doing cleanup"
    trap "kill 0" EXIT
    exit 2
}

trap "trap_ctrlc" 4

# Show usage via commandline arguments
print_usage() {
  banner
  echo "${MAGENTA}"
  echo "~~~~~~~~~~~"
  echo " U S A G E"
  echo "~~~~~~~~~~~"
  echo "Usage: ./chomte.sh -p <ProjectName> -d <domain.com> -i <127.0.0.1> -brt -n"
  echo "Usage: ./chomte.sh -p <ProjectName> -i <127.0.0.1> [option]"
  echo "Usage: ./chomte.sh -p projectname -d example.com -brt"
  echo "Usage: ./chomte.sh -p projectname -d Domains-list.txt"
  echo "Usage: ./chomte.sh -p projectname -i 127.0.0.1"
  echo "Usage: ./chomte.sh -p projectname -i IPs-list.txt -n"
  echo "${NC}"
  echo "  Mandatory Flags:"
  echo "    -p  | --project         : Specify Project Name here"
  echo "    -d  | --domain          : Specify Root Domain here / Domain List here"
  echo "    -i  | --ip              : Specify IP / CIDR/ IPlist here"
  echo " Optional Flags "
  echo "    -n  | --nmap            : Nmap Scan against open ports"
  echo "    -brt | --dnsbrute       : DNS Recon Bruteforce"
  echo "    -hpl | --hostportlist   : HTTP Probing on Host:Port List "
  echo "    -h | --help             : Show this help"
  echo ""
  echo "${NC}"
  exit
}

domaindirectorycheck(){
    if [ -d Results/$project ]
    then
        echo -e
        echo -e "${BLUE}[I] Results/$project Directory already exists...\n${NC}"
    else
        mkdir -p Results/$project
        echo -e "${BLUE}[I] Results/$project Directory Created\n${NC}" 
    fi
    
}

function var_checker(){
    echo -e "${BLUE}[*] Checking for required arguments...${NC}"

	if [[ -z ${project} ]]; then
		echo -e "${RED}[-] ERROR: Project Name is not set${NC}"
		echo -e "${RED}[-] Missing -p ${NC}"
        print_usage
        exit 1
    else
        domaindirectorycheck
    fi
    #####################################################

    if [[ ${ipscan} == true ]] || [[ ${domainscan} == true || ${hostportscan} == true ]];then

        [[ ${domainscan} == true ]] && rundomainscan
        [[ ${ipscan} == true ]] && runipscan     
        [[ ${hostportscan} == true ]] && iphttpx $hostportlist

    else
        echo -e "${RED}[-] ERROR: IP or domain is not set\n[-] Missing -i or -d${NC}"    
    fi
}

function declared_paths(){
    subdomains="Results/$project/$domain/subdomains.txt"  
     
    if [[ ${domainscan} == true ]] && [[ ! -f $domain ]];then
        echo -e "DOMAINSCAN is $domainscan"
        dnsreconout="Results/$project/$domain/dnsrecon.txt"
        naabuout="Results/$project/$domain/naabu.csv"
        nmapscans="Results/$project/$domain/nmapscans"
        aliveip="Results/$project/$domain/aliveip.txt"
        httpxout="Results/$project/$domain/httpxout.csv"
        webtech="Results/$project/$domain/webtech.csv"
        hostport="Results/$project/$domain/hostport.txt"
        ipport="Results/$project/$domain/ipport.txt"
        urlprobed="Results/$project/$domain/urlprobed.txt"
    fi

    if [[ ${ipscan} == true ]];then
        echo -e "IPSCAN is $ipscan"
        naabuout="Results/$project/naabu.csv"
        nmapscans="Results/$project/nmapscans"
        aliveip="Results/$project/aliveip.txt"
        httpxout="Results/$project/httpxout.csv"
        webtech="Results/$project/webtech.csv"
        hostport="Results/$project/hostport.txt"
        ipport="Results/$project/ipport.txt"
        urlprobed="Results/$project/urlprobed.txt"
    fi

    if [[ ${hostportscan} == true ]] && [[ -f $hostportlist ]];then
        echo -e "HOSTPORTSCAN is $hostportscan"
        mkdir -p Results/$project/Domain_List
        # Declaring New Paths for Domain List
        naabuout="Results/$project/Domain_List/naabu.csv"
        nmapscans="Results/$project/Domain_List/nmapscans"
        aliveip="Results/$project/Domain_List/aliveip.txt"
        httpxout="Results/$project/Domain_List/httpxout.csv"
        webtech="Results/$project/Domain_List/webtech.csv"
        hostport="Results/$project/Domain_List/hostport.txt"
        ipport="Results/$project/Domain_List/ipport.txt"
        urlprobed="Results/$project/Domain_List/urlprobed.txt"
    fi

}

####################################################################
function dnsreconbrute(){
    # DNS Subdomain Bruteforcing
    if [[ "${dnsbrute}" == true ]]; then
        if [ ! -f "${dnsreconout}" ]; then
            echo -e ""
            echo -e "${YELLOW}[*] Bruteforcing Subdomains DNSRecon${NC}"
            echo -e "${BLUE}dmut -u "$domain" $dmut_flags -o $dnsreconout ${NC}"
            dmut --update-files &>/dev/null
            dmut -u "$domain" $dmut_flags -o $dnsreconout
            dnsbrute_sdc=$(cat $dnsreconout | anew $subdomains | wc -l)
            total_sdc=$(cat $subdomains | wc -l)
            echo -e "${GREEN}[+] New Unique Subdomains found by bruteforcing${NC}[$dnsbrute_sdc]"
            echo -e "${GREEN}[+] Total Subdomains Enumerated${NC}[$total_sdc]"
        else
            echo -e "${BLUE}[I] $dnsreconout already exists...SKIPPING...${NC}"
        fi
    fi
}

function getsubdomains(){
    # Subdomain gathering
    if [ -f ${subdomains} ]; then
        echo -e "${CYAN}[I] $subdomains already exists...SKIPPING...${NC}"
    else [ ! -f ${subdomains} ];
        echo -e ""
        echo -e "${YELLOW}[*] Gathering Subdomains${NC}"
        echo -e "${BLUE}[*] subfinder -d $1 | anew $subdomains ${NC}"
        subfinder -d $1 | anew $subdomains
        sdc=$(<$subdomains wc -l)
        echo -e "${GREEN}[+] Subdomains Collected ${NC}[$sdc]"
    fi
}

function nmapconverter(){
    # Convert to csv
    ls $nmapscans/*.xml | xargs -I {} python3 $PWD/MISC/xml2csv.py -f {} -csv {}.csv &>/dev/null 
    echo -e "${GREEN}[+] All Nmap CSV Generated ${NC}[$sdc]"
    
    # Merge all csv
    first_file=$(ls $nmapscans/*.csv | head -n 1)
    head -n 1 "$first_file" > $nmapscans/Nmap_Final_Merged.csv
    tail -q -n +2 $nmapscans/*.csv >> $nmapscans/Nmap_Final_Merged.csv
    echo -e "${GREEN}[+] Merged Nmap CSV Generated $nmapscans/Nmap_Final_Merged.csv${NC}[$sdc]"

    # Generating HTML Report Format
    ls $nmapscans/*.xml | xargs -I {} xsltproc -o {}_nmap.html MISC/nmap-bootstrap.xsl {}
    echo -e "${GREEN}[+] HTML Report Format Generated ${NC}[$sdc]"
    
    # Generating RAW Colored HTML Format
    ls $nmapscans/*.nmap | xargs -I {} sh -c 'cat {} | ccze -A | ansi2html > {}_nmap_raw_colored.html'
    echo -e "${GREEN}[+] HTML RAW Colored Format Generated ${NC}[$sdc]"
}

function portscanner(){
    # Port Scanning Start with Nmap
    scanner(){
        ports=$(cat $ipport| grep $iphost | cut -d ':' -f 2 | xargs | sed -e 's/ /,/g')
            if [ -z "$ports" ]
            then
                echo -e "No Ports found for $iphost"
            else
                echo -e ${CYAN}"[*] Running Nmap Scan on"${NC} $iphost ======${CYAN} $ports ${NC}
                if [ -n "$(find $nmapscans -maxdepth 1 -name 'nmapresult-$iphost*' -print -quit)" ]; then
                    echo -e "${CYAN}Nmap result exists for $iphost, Skipping this host...${NC}"
                else
                    nmap $iphost -p $ports $nmap_flags -oX $nmapscans/nmapresult-$iphost.xml -oN $nmapscans/nmapresult-$iphost.nmap &>/dev/null
                fi            
            fi
        }    
        
        # This will check if naaabuout file is present than extract aliveip and if nmap=true then run nmap on each ip on respective open ports.
        if [ -f "$naabuout" ]; then
            csvcut -c ip $naabuout | grep -v ip | anew $aliveip
            if [[ $nmap == "true" ]];then
                echo -e ${YELLOW}"[*]Running Nmap Service Enumeration Scan" ${NC}
                mkdir -p $nmapscans
                while read iphost; do
                    scanner  
                done <"$aliveip"
                [ -e "$nmapscans/Nmap_Final_Merged.csv" ] && echo "$nmapscans/Nmap_Final_Merged.csv Exist" || nmapconverter
            fi
        # else run naabu to initiate port scan
        # start from here
        else
            echo $ip   
            if [ -f "$1" ]; then
                echo -e ${YELLOW}"[*]Running Quick Port Scan on $1" ${NC}
                echo -e ${BLUE}"naabu -list $1 $naabu_flags -o $naabuout -csv" ${NC}
                naabu -list $1 $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" > /dev/null
                csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q
                csvcut -c host,port $naabuout 2>/dev/null | sort -u | grep -v 'host,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $hostport &>/dev/null
                csvcut -c ip,port $naabuout 2>/dev/null | sort -u | grep -v 'ip,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $ipport &>/dev/null
                echo -e ${GREEN}"[+]Quick Port Scan Completed$naabuout" ${NC}
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
            else
                echo -e ${YELLOW}"[*]Running Quick Port Scan on $1" ${NC}
                echo -e ${BLUE}"naabu -host $1 $naabu_flags -o $naabuout -csv" ${NC}
                naabu -host $1 $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" > /dev/null
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | anew $aliveip -q
                csvcut -c ip,port $naabuout 2>/dev/null | sort -u | grep -v 'ip,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $ipport
                echo -e ${GREEN}"[+]Quick Port Scan Completed$naabuout" ${NC}
                if [[ $nmap == "true" ]];then
                    mkdir -p $nmapscans
                    while read iphost; do
                        scanner
                    done <"$aliveip"
                    nmapconverter
                fi
	        fi
            mkdir -p $nmapscans
        fi    

}

function iphttpx(){

    webtechcheck(){
        webanalyze -update
        echo -e "[${BLUE}I${NC}]webanalyze -hosts $urlprobed $webanalyze_flags -output csv | tee $webtech  ${NC}" 
        webanalyze -hosts $urlprobed $webanalyze_flags -output csv 2>/dev/null | tee $webtech
    }

    if [ -f "$naabuout" ] && [ -f "$1" ] && [ ! -f $httpxout ]; then
        echo -e "${YELLOW}[*] HTTPX Probe Started on $1 ${NC}"
        echo -e "${BLUE}cat $1 | httpx $httpx_flags -csv -o $httpxout ${NC}"
        cat $1 | httpx $httpx_flags -csv -o $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
        csvcut $httpxout -c url 2>/dev/null | grep -v url | anew $urlprobed
        echo -e "${GREEN}[+] HTTPX Probe Completed\n${NC}"
        echo -e "${YELLOW}[*] Running WebTechCheck\n${NC}" 
        webtechcheck
     
    elif [ -f "$naabuout" ] && [ ! -f "$1" ] && [ ! -f $httpxout ]; then
        echo -e "${YELLOW}[*] HTTPX Probe Started on $1 ${NC}"
        echo "${BLUE}echo $1 | httpx $httpx_flags -csv -o $httpxout ${NC}"
        echo $1 | httpx $httpx_flags -csv -o $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
        csvcut $httpxout -c url 2>/dev/null| grep -v url | anew $urlprobed
        echo -e "${GREEN}[+] HTTPX Probe Completed\n${NC}"
        echo -e "${YELLOW}[*] Running WebTechCheck\n${NC}"
        webtechcheck
        
    elif [ ${hostportscan} == true ] && [ -f $1 ]; then
        declared_paths
        echo -e "${YELLOW}[*] HTTPX Probe Started on $1 ${NC}"
        echo -e "${BLUE}cat $1 | httpx $httpx_flags -csv -o $httpxout ${NC}"
        cat $1 | httpx $httpx_flags -csv -o $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
        csvcut $httpxout -c url 2>/dev/null | grep -v url | anew $urlprobed
        echo -e "${GREEN}[+] HTTPX Probe Completed\n${NC}"
        echo -e "${YELLOW}[*] Running WebTechCheck\n${NC}" 
        webtechcheck
  
    else
        echo $1
        echo -e "Need to scan port"
    fi
}    

####################################################################
function rundomainscan(){
    if [ -n "${domain}" ] && [ ! -f "${domain}" ];then
        declared_paths
        echo -e "Domain Module $domain $domainscan - Domain Specified"
        mkdir -p Results/$project/$domain
        getsubdomains $domain
        dnsreconbrute
        portscanner $subdomains
        iphttpx $hostport
    elif [ -n "${domain}" ] && [ -f "${domain}" ];then
        echo -e "Domain Module $domain $domainscan - List Specified"
        hostportscan=true
        declared_paths
        # Running Functions
        portscanner $domain
        iphttpx $hostport
    else
        echo -e "${RED}[-] Domain / Domain List not specified.. Check -d again${NC}"
    fi
}

function runipscan(){
    if [ -n "${ip}" ];then
        declared_paths
        echo IP Module $ip $ipscan
        portscanner $ip
        iphttpx $ipport
    else
        echo -e "${RED}[-] IP not specified.. Check -i again${NC}"
    fi
}
#######################################################################

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
    -i|--ip)
      ip="$2"
      ipscan=true
      shift 
      ;;
    -n|--nmap)
      nmap=true
      shift 
      ;;
    -brt|--dnsbrute)
      dnsbrute=true
      shift
      ;;
    -naabu|--portscan)
      portscan=true
      shift 
      ;;
    -hpl|--hostportlist)
      hostportlist="$2"
      hostportscan=true
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