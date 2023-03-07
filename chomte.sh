#!/bin/bash
#title: CHOMTE.SH
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       3.6.2
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
dirsearch_flags=$(grep '^dirsearch_flags=' flags.conf | awk -F= '{print $2}' | xargs)

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
  echo "    -p   | --project         : Specify Project Name here"
  echo "    -d   | --domain          : Specify Root Domain here / Domain List here"
  echo "    -i   | --ip              : Specify IP / CIDR/ IPlist here"
  echo " Optional Flags "
  echo "    -n   | --nmap            : Nmap Scan against open ports"
  echo "    -brt | --dnsbrute        : DNS Recon Bruteforce"
  echo "    -hpl | --hostportlist    : HTTP Probing on Host:Port List "
  echo "    -e   | --enum            : Active Recon "
  echo "    -jsd | --jsubfinder      : Get Subdomains from WebPage and JS file by crawling "
  echo "    -h   | --help            : Show this help"
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

required_tools=("subfinder" "naabu" "httpx" "csvcut" "dmut" "dirsearch" "nuclei" "nmap" "ansi2html" "xsltproc" "anew" "interlace" "subjs" "katana")
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
        httpxresume="Results/$project/$domain/httpxresume.cfg"
        webtech="Results/$project/$domain/webtech.csv"
        hostport="Results/$project/$domain/hostport.txt"
        ipport="Results/$project/$domain/ipport.txt"
        urlprobed="Results/$project/$domain/urlprobed.txt"
        potentialsdurls="Results/$project/$domain/potentialsdurls.txt"
        urlprobedsd="Results/$project/$domain/urlprobedsd.txt"
        enumscan="$PWD/Results/$project/$domain/enumscan"
        jsubfinderout="Results/$project/$domain/jsubfinder.txt"
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
        potentialsdurls="Results/$project/potentialsdurls.txt"
        urlprobedsd="Results/$project/urlprobedsd.txt"
        enumscan="$PWD/Results/$project/enumscan"
    fi

    if [[ ${hostportscan} == true ]] || [[ ${domainlist} == true ]] && [[ -f $hostportlist ]] || [[ -f $domain ]];then
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
        potentialsdurls="Results/$project/Domain_List/potentialsdurls.txt"
        urlprobedsd="Results/$project/Domain_List/urlprobedsd.txt"
        enumscan="$PWD/Results/$project/Domain_List/enumscan"
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
        
        runjsubfinder(){
            echo -e ""
            echo -e "${YELLOW}[*] Gathering Subdomains from Webpage and Javascript on $domain ${NC}"
            echo -e "${BLUE}cat $subdomains | xargs -I {} sh -c 'echo {} | jsubfinder search --crawl -t 20 -K | anew $jsubfinderout'${NC}"
            echo -e ""
            cat $subdomains | xargs -I {} sh -c 'echo {} | jsubfinder search --crawl -t 20 -K | anew $jsubfinderout'
            dnsbrute_sdc=$(cat $jsubfinderout | anew $subdomains | wc -l)
            total_sdc=$(cat $subdomains | wc -l)
            echo -e "${GREEN}[+] Subdomains Collected ${NC}[$total_sdc]"
        }

        [ "$jsd" = true ] && runjsubfinder
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
    ls $nmapscans/*.xml | xargs -I {} xsltproc -o {}_nmap.html ./MISC/nmap-bootstrap.xsl {}
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
                echo -e ${CYAN}"[$] Running Nmap Scan on"${NC} $iphost ======${CYAN} $ports ${NC}
                if [ -n "$(find $nmapscans -maxdepth 1 -name 'nmapresult-$iphost*' -print -quit)" ]; then
                    echo -e "${CYAN}Nmap result exists for $iphost, Skipping this host...${NC}"
                else
                    trap 'echo -e "${RED}Ctrl + C detected in Nmap Scan${NC}"' SIGINT
                    nmap $iphost -p $ports $nmap_flags -oX $nmapscans/nmapresult-$iphost.xml -oN $nmapscans/nmapresult-$iphost.nmap &>/dev/null
                fi            
            fi
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
        # This will check if naaabuout file is present than extract aliveip and if nmap=true then run nmap on each ip on respective open ports.
        
        if [ -f "$naabuout" ]; then
            csvcut -c ip $naabuout | grep -v ip | anew $aliveip
            nmapscanner
        # else run naabu to initiate port scan
        # start from here
        else
            echo $ip
            if [ -f "$1" ]; then
                echo -e ${YELLOW}"[*]Running Quick Port Scan on $1" ${NC}
                echo -e ${BLUE}"[#] naabu -list $1 $naabu_flags -o $naabuout -csv" ${NC}
                naabu -list $1 $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" > /dev/null
                echo -e ${GREEN}"[+]Quick Port Scan Completed $naabuout" ${NC}
                nmapscanner
            else
                echo -e ${YELLOW}"[*]Running Quick Port Scan on $1" ${NC}
                echo -e ${BLUE}"[#] naabu -host $1 $naabu_flags -o $naabuout -csv" ${NC}
                naabu -host $1 $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" > /dev/null
                cat $naabuout | cut -d ',' -f 2 | grep -v ip | anew $aliveip -q
                csvcut -c ip,port $naabuout 2>/dev/null | sort -u | grep -v 'ip,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $ipport
                echo -e ${GREEN}"[+]Quick Port Scan Completed$naabuout" ${NC}
                nmapscanner
	        fi
            mkdir -p $nmapscans
        fi
}

function iphttpx(){

    webtechcheck(){
        webanalyze -update > /dev/null
        echo -e "${YELLOW}[*] Running WebTechCheck\n${NC}" 
        echo -e "${BLUE}[#] webanalyze -hosts $urlprobed $webanalyze_flags -output csv | anew $webtech ${NC}" 
        webanalyze -hosts $urlprobed $webanalyze_flags -output csv | anew $webtech -q 2>/dev/null
        echo -e "${GREEN}[+] WebTechCheck Scan Completed\n${NC}"
    }

    httpxcheck(){
        [ ! -f $aliveip ] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q
        [ ! -f $hostport ] && csvcut -c host,port $naabuout 2>/dev/null | sort -u | grep -v 'host,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $hostport -q &>/dev/null
        [ ! -f $ipport ] && csvcut -c ip,port $naabuout 2>/dev/null | sort -u | grep -v 'ip,port' | awk '{ sub(/,/, ":") } 1' | sed '1d' | anew $ipport -q &>/dev/null
        echo -e "${YELLOW}[*] HTTPX Probe Started on $1 ${NC}"
        if [ -f "$1" ]; then
            echo -e "${BLUE}[#] cat $1 | httpx $httpx_flags -csv -o $httpxout ${NC}"
            cat $1 | httpx $httpx_flags -csv -o $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
        else
            echo "${BLUE}[#] echo $1 | httpx $httpx_flags -csv -o $httpxout ${NC}"
            echo $1 | httpx $httpx_flags -csv -o $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
        fi
        csvcut $httpxout -c url 2>/dev/null | grep -v url | anew $urlprobed
        csvcut -c url,status_code,final_url $httpxout | awk -F ',' '$2 == "200"' | awk -F ',' '$3 ~ /^http/ {print $3}' | grep -oE "^https?://[^/]*\.$domain(:[0-9]+)?" | anew $potentialsdurls
        csvcut -c url,status_code,final_url $httpxout | awk -F ',' '$2 == "200"' | awk -F ',' '$3 == "" {print $1}' | anew $potentialsdurls
        echo -e "${GREEN}[+] HTTPX Probe Completed\n${NC}"
        webtechcheck
    }

    if [ ! -f "$httpxout" ]; then
        echo "The file $httpxout does not exist. Running command..."
        
        if [ -f "$naabuout" ] && [ -f "$1" ] && [ ! -f $httpxout ]; then
            httpxcheck $1   
        elif [ -f "$naabuout" ] && [ ! -f "$1" ] && [ ! -f $httpxout ]; then
            httpxcheck $1          
        elif [ ${hostportscan} == true ] && [ -f $1 ]; then
            declared_paths
            httpxcheck $1
        else
            echo $1
            echo -e "Need to scan port"
        fi
    else
        echo -e "${CYAN}The file $httpxout already exists. Skipping command...${NC}"
    fi
}    

function content_discovery(){
    mergeffufcsv(){
        echo -e "${YELLOW}[*] Merging All Content Discovery Scan CSV - ${NC}$enumscan/contentdiscovery/all-cd.csv\n"
        if [ -d $enumscan/contentdiscovery ]; then
            cat $enumscan/contentdiscovery/*.csv | head -n1 > $enumscan/contentdiscovery/all-cd.csv
            cat $enumscan/contentdiscovery/*.csv | grep -v 'FUZZ,url,redirectlocation' >> $enumscan/contentdiscovery/all-cd.csv
        fi
    }
    
    ffuflist(){
        trap 'echo -e "${RED}Ctrl + C detected in content_discovery${NC}"' SIGINT
        echo -e "${YELLOW}[*] Running Content Discovery Scan - FFUF using dirsearch wordlist\n${NC}"
        if [ "$(ls -A $enumscan/contentdiscovery 2>/dev/null)" = "" ]; then
            echo -e ""
            echo "$enumscan/contentdiscovery -- Directory is empty, continuing..."
            mkdir -p $enumscan/contentdiscovery
            interlace -tL $1 -o $enumscan/contentdiscovery -cL ./MISC/contentdiscovery.il --silent &>/dev/null 2>&1 | pv -p -t -e -N "Content Discovery using FFUF with Dirsearch wordlist"
        else
            echo -e "${RED}ContentDiscover Directory Already Exist; Remove $enumscan/contentdiscovery directory if you want to re-run.${NC}"
            exit 0
        fi
    }

    #[[ -f $1 ]] && cat $1 | dirsearch --stdin $dirsearch_flags --format csv -o $enumscan/dirsearch_results.csv 2>/dev/null
    [[ -f $1 ]] && ffuflist $1 && mergeffufcsv
    [[ ! -f $1 ]] && dirsearch $dirsearch_flags -u $1 -o $enumscan/$1_dirsearch.csv 2>/dev/null
}

function active_recon(){
    
    techdetect(){
        urls=($(csvcut -c url,tech $httpxout | grep -i $1 | cut -d ',' -f 1))
        urls+=($(csvcut -c Host,Category,App $webtech | grep -i $1 | cut -d ',' -f 1))
        result=$(printf "%s\n" "${urls[@]}")
        for url in $result; do
            echo $url | grep -oE "^https?://[^/]*(:[0-9]+)?"
        done
    }

    wordpress_recon(){
        techdetect WordPress | anew $enumscan/wordpress_urls.txt -q
        if [ -s $enumscan/wordpress_urls.txt ];then
            echo -e "${YELLOW}[*] Running Wordpress Recon on Below URL\n${NC}"
            echo -e ""
            [ ! -f $enumscan/wordpress_nuclei_results.txt ] && nuclei -l $enumscan/wordpress_urls.txt -w ~/nuclei-templates/workflows/wordpress-workflow.yaml -o $enumscan/wordpress_nuclei_results.txt
            # wpscan with apitoken
        fi
    }

    joomla_recon(){
        techdetect joomla | anew $enumscan/joomla_urls.txt -q
        if [ -s $enumscan/joomla_urls.txt ];then
            echo -e "${YELLOW}[*] Running Joomla Recon on Below URL\n${NC}"
            echo -e ""
            [ ! -f $enumscan/joomla_nuclei_results.txt ] && nuclei -l $enumscan/joomla_urls.txt -w ~/nuclei-templates/workflows/joomla-workflow.yaml -o $enumscan/joomla_nuclei_results.txt
        fi
    }

    drupal_recon(){
        techdetect Drupal | anew $enumscan/drupal_urls.txt -q
        if [ -s $enumscan/drupal_urls.txt ];then
            echo -e "${YELLOW}[*] Running Drupal Recon on Below URL\n${NC}"
            echo -e ""
            [ ! -f $enumscan/drupal_nuclei_results.txt ] && nuclei -l $enumscan/drupal_urls.txt -w ~/nuclei-templates/workflows/drupal-workflow.yaml -o $enumscan/drupal_nuclei_results.txt
        fi
    }

    jira_recon(){
        techdetect jira | anew $enumscan/jira_urls.txt -q
        if [ -s $enumscan/jira_urls.txt ];then
            echo -e "${YELLOW}[*] Running Jira Recon on Below URL\n${NC}"
            echo -e ""
            [ ! -f $enumscan/jira_nuclei_results.txt ] && nuclei -l $enumscan/jira_urls.txt -w ~/nuclei-templates/workflows/drupal-workflow.yaml -o $enumscan/jira_nuclei_results.txt
        fi
    }

    js_recon(){
        echo -e "${YELLOW}[*] Performing JS Recon from Webpage and Javascript on $domain ${NC}"
        ## Thanks to @KathanP19 and Other Community members
        passivereconurl(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said "' SIGINT
            echo -e "${BLUE}[*] Gathering URLs - Passive Recon using Gau and Subjs >>${NC} $enumscan/URLs/gau-allurls.txt ${BLUE}and${NC} $enumscan/URLs/subjs-allurls.txt"
            cat $urlprobed | awk -F[/:] '{print $4}' | anew $urlprobedsd -q &>/dev/null 2>&1
            [ ! -f $enumscan/URLs/gau-allurls.txt ] && interlace -tL $urlprobedsd -o $enumscan -cL ./MISC/passive_recon.il --silent &>/dev/null 2>&1 | pv -p -t -e -N "Gathering URLs from Gau"
            [ ! -f $enumscan/URLs/subjs-allurls.txt ] && interlace -tL $urlprobed -o $enumscan -c "echo _target_ | subjs | anew _output_/URLs/subjs-allurls.txt -q" --silent &>/dev/null 2>&1 | pv -p -t -e -N "Gathering JS URLs from Subjs"
        }

        activereconurl(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Gathering URLs - Active Recon using Katana >>${NC} $enumscan/URLs/katana-allurls.txt"
            [ ! -f $enumscan/URLs/katana-allurls.txt ] && katana -list $urlprobed -d 10 -jc -kf robotstxt,sitemapxml -aff -silent | anew $enumscan/URLs/katana-allurls.txt -q &>/dev/null 2>&1 | pv -p -t -e -N "Katana is running"
        }
        
        jsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Extracting JS URLs >>${NC} $enumscan/URLs/*-allurls.txt"
            [ ! -f $enumscan/URLs/alljsurls.txt ] && cat $enumscan/URLs/*-allurls.txt | egrep -iv '\.json' | grep -iE "\.js$" | anew $enumscan/URLs/alljsurls.txt -q &>/dev/null 2>&1
        }
        
        pot_url(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Taking out Potential URLs >>${NC} $enumscan/URLs/potentialurls.txt"
            [ ! -f $enumscan/URLs/potentialurls.txt ] && cat $enumscan/URLs/*-allurls.txt | gf excludeExt | anew $enumscan/URLs/potentialurls.txt -q &>/dev/null 2>&1
        }

        validjsurlextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Finding All Valid JS URLs >>${NC} $enumscan/URLs/validjsurls.txt"
            [ ! -f $enumscan/URLs/validjsurls.txt ] && cat $enumscan/URLs/alljsurls.txt| python3 ./MISC/antiburl.py -N &>/dev/null 2>&1 | grep '^200' | awk '{print $2}' | anew $enumscan/URLs/validjsurls.txt -q &>/dev/null 2>&1 | pv -p -t -e -N "Finding All Valid JS URLs "
        }
        
        endpointsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Enumerating Endpoints from valid JS files >> ${NC}$enumscan/URLs/endpointsfromjs.txt"
            [ ! -f $enumscan/URLs/endpointsfromjs.txt ] && interlace -tL $enumscan/URLs/validjsurls.txt -c "python3 ./MISC/LinkFinder/linkfinder.py -d -i '_target_' -o cli | anew $enumscan/URLs/endpointsfromjs_tmp.txt" &>/dev/null 2>&1 | pv -p -t -e -N "Enumerating Endpoints from valid js files"
            [ -f $enumscan/URLs/endpointsfromjs_tmp.txt ] && cat $enumscan/URLs/endpointsfromjs_tmp.txt | grep -vE 'Running against|Invalid input' | anew $enumscan/URLs/endpointsfromjs.txt -q &>/dev/null 2>&1 && rm $enumscan/URLs/endpointsfromjs_tmp.txt
        }
        
        secretsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Enumerating Secrets from valid JS files >> ${NC}$enumscan/URLs/secretsfromjs.txt"
            [ ! -f $enumscan/URLs/secretsfromjs.txt ] && interlace -tL $enumscan/URLs/validjsurls.txt -c "python3 MISC/SecretFinder/SecretFinder.py -i '_target_' -o cli | anew $enumscan/URLs/secretsfromjs.txt" &>/dev/null 2>&1 | pv -p -t -e -N "Enumerating Secrets from valid js files"
        }

        domainfromjsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Enumerating Domains from valid JS files >> ${NC}$enumscan/URLs/domainfromjs.txt"
            [ ! -f $enumscan/URLs/domainfromjs.txt ] && interlace -tL $enumscan/URLs/validjsurls.txt -c "python3 MISC/SecretFinder/SecretFinder.py -i '_target_' -o cli  -r "\S+$domain" &>/dev/null 2>&1| anew $enumscan/URLs/domainfromjs.txt" &>/dev/null 2>&1 | pv -p -t -e -N "Enumerating Domain from valid js files"
        }
        
        wordsfromjsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Gathering Words from valid JS files >> ${NC}$enumscan/URLs/wordsfromjs.txt"
            [ ! -f $enumscan/URLs/wordsfromjs.txt ] && cat $enumscan/URLs/validjsurls.txt | python3 ./MISC/getjswords.py &>/dev/null 2>&1 | anew $enumscan/URLs/wordsfromjs.txt &>/dev/null 2>&1 | pv -p -t -e -N "Gathering words from valid js files"
        }

        varjsurlsextractor(){
            trap 'echo -e "${RED}Ctrl + C detected, Thats what she said"' SIGINT
            echo -e "${BLUE}[*] Gathering Variables from valid JS files >> ${NC}$enumscan/URLs/varfromjs.txt"
            [ ! -f $enumscan/URLs/varfromjs.txt ] && interlace -tL $enumscan/URLs/validjsurls.txt -c "bash ./MISC/jsvar.sh _target_ | anew $enumscan/URLs/varfromjs.txt" &>/dev/null 2>&1 | pv -p -t -e -N "Gathering Variables from valid js files"
        }
    
        passivereconurl
        activereconurl
        jsextractor
        pot_url
        validjsurlextractor
        endpointsextractor
        secretsextractor
        domainfromjsextractor
        wordsfromjsextractor
        varjsurlsextractor
    }

    xnl(){
        [ ! -f $enumscan/URLs/waymore.txt ] && python3 ./MISC/waymore/waymore.py -i $domain -mode B -oU $enumscan/URLs/waymore.txt -oR $enumscan/URLs/waymoreResponses/
        [ -d $enumscan/URLs/waymoreResponses ] && python3 ./MISC/xnLinkFinder/xnLinkFinder.py -i $enumscan/URLs/waymoreResponses/ -sp $urlprobed -sf $domain -o $enumscan/URLs/xnLinkFinder_links.txt -op $enumscan/URLs/xnLinkFinder_parameters.txt -owl $enumscan/URLs/xnLinkFinder_wordlist.txt 
    }

    wordpress_recon
    joomla_recon
    drupal_recon
    jira_recon
    [[ ${jsrecon} == true ]] && js_recon
    [[ ${enumxnl} == true ]] && xnl

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
        if [[ ${contentscan} == true ]];then
            mkdir -p $enumscan
            [[ ${cdlist} ]] && content_discovery $cdlist || content_discovery $potentialsdurls
        fi
        if [[ ${enum} == true ]];then
            mkdir -p $enumscan
            [[ ${httpxout} ]] && active_recon
            # activescan $httpxout
        fi
    elif [ -n "${domain}" ] && [ -f "${domain}" ];then
        echo -e "Domain Module $domain $domainscan - List Specified"
        domainlist=true
        declared_paths
        # Running Functions
        portscanner $domain
        iphttpx $hostport
        if [[ ${contentscan} == true ]];then
            mkdir -p $enumscan
            [[ ${cdlist} ]] && content_discovery $cdlist || content_discovery $potentialsdurls
        fi
        if [[ ${enum} == true ]];then
            mkdir -p $enumscan
            [[ ${httpxout} ]] && active_recon
            # activescan $httpxout
        fi
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
        if [[ ${contentscan} == true ]];then
            mkdir -p $enumscan
            [[ ${cdlist} ]] && content_discovery $cdlist || content_discovery $potentialsdurls
        fi
        if [[ ${enum} == true ]];then
            mkdir -p $enumscan
            [[ ${httpxout} ]] && active_recon
            # activescan $httpxout
        fi
    else
        echo -e "${RED}[-] IP not specified.. Check -i again${NC}"
    fi
}


#######################################################################

#########################################################################
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
