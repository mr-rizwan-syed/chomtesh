#!/bin/bash
#title: CHOMTE.SH - shodaner.sh
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
# This shell script is just a recreation Karma_v2 of #- twitter.com/Dheerajmadhukar : @me_dheeraj
# Thanks to Dheeraj Madhukar for his contributions to InfoSec Community
#==============================================================================

shodunbanner(){
    echo -e '

   ▄▄▄▄▄    ▄  █ ████▄ ██▄   ██      ▄          ▄▄▄▄▄    ▄  █ ████▄ ██▄     ▄      ▄       ██▄   ▄█ █    ██   
  █     ▀▄ █   █ █   █ █  █  █ █      █        █     ▀▄ █   █ █   █ █  █     █      █      █  █  ██ █    █ █  
▄  ▀▀▀▀▄   ██▀▀█ █   █ █   █ █▄▄█ ██   █     ▄  ▀▀▀▀▄   ██▀▀█ █   █ █   █ █   █ ██   █     █   █ ██ █    █▄▄█ 
 ▀▄▄▄▄▀    █   █ ▀████ █  █  █  █ █ █  █      ▀▄▄▄▄▀    █   █ ▀████ █  █  █   █ █ █  █     █  █  ▐█ ███▄ █  █ 
              █        ███▀     █ █  █ █                   █        ███▀  █▄ ▄█ █  █ █     ███▀   ▐     ▀   █ 
             ▀                 █  █   ██                  ▀                ▀▀▀  █   ██                     █  
                              ▀                                                                           ▀                                                                                                                                                  
' | lolcat -a -d 1
}

api_check() {
    SHODAN_API_KEY=$(grep 'SHODAN_API_KEY: ' config.yml | awk -F'[][]' '{print $2}' | xargs)

    if [ -z "$shodan_api_key" ]; then
        printf "\n${redbg} No Premium Shodan API key found. Make sure you store the API key in flags.conf file ${NC}\n\n"
        exit 0
    else
        shodan init "$SHODAN_API_KEY" &> /dev/null
    fi
}


dork(){
    shodan stats --facets ssl.cert.fingerprint ssl:"${target}"|grep -Eo "[[:xdigit:]]{40}" | grep -v "^[[:blank:]]*$" | anew -q $shodanresults/fingerprints.txt;sleep 2
    shodan stats --facets ssl.cert.fingerprint org:"${target}"|grep -Eo "[[:xdigit:]]{40}" | grep -v "^[[:blank:]]*$" | anew -q $shodanresults/fingerprints.txt;sleep 2
    shodan stats --facets ssl.cert.fingerprint ssl.cert.issuer.cn:"${target}"|grep -Eo "[[:xdigit:]]{40}" | grep -v "^[[:blank:]]*$" | anew -q $shodanresults/fingerprints.txt;sleep 2
    shodan stats --facets ssl.cert.fingerprint ssl.cert.subject.cn:"${target}"|grep -Eo "[[:xdigit:]]{40}" | grep -v "^[[:blank:]]*$" | anew -q $shodanresults/fingerprints.txt;sleep 2
    shodan stats --facets ssl.cert.fingerprint ssl.cert.expired:true hostname:"*.${target}"|grep -Eo "[[:xdigit:]]{40}"|grep -v "^[[:blank:]]*$" | anew -q $shodanresults/fingerprints.txt;sleep 2
    shodan stats --facets ssl.cert.fingerprint ssl.cert.subject.commonName:"*.${target}"|grep -Eo "[[:xdigit:]]{40}"|grep -v "^[[:blank:]]*$" | anew -q $shodanresults/fingerprints.txt;sleep 2

    cat $shodanresults/fingerprints.txt | while read -r line;do echo "ssl_SHA1_${line}::ssl.cert.fingerprint:\"$line\"";done | anew -q $shodanresults/targetdork.txt && rm $shodanresults/fingerprints.txt
    sed "s/\$targetdomain/$target/g" ./MISC/shodan_dorks.txt | anew -q $shodanresults/targetdork.txt
}

count(){
    echo -e "${bluebg}Counting Shodan Results${NC}"
    result_count=$(
        cat "$shodanresults/targetdork.txt" | while IFS='::' read a b c; do
            z=$(shodan count "${c}" 2> /dev/null; sleep 2)
            printf "${a} ${z}\n"
        done | awk '{ if ($NF > 0) print $1 " " $NF }' | sed 's/ /,|,/g' | column -s ',' -t
    )
    echo -e "${greenbg}Total Shodan Results Count Below${NC}"
    echo -e "\n${result_count}" | lolcat -a -d 1
    echo -e "\n${result_count}" | anew -q $shodanresults/resultscount.txt
    echo "$shodanresults/resultscount.txt" | sed 's/ /,/g' | awk -F"," '{print $1}' > /tmp/results
}

collect(){
    echo -e "${bluebg}Collecting all $target results from Shodan${NC}"
    cat "$shodanresults/resultscount.txt" | sed 's/ /,/g' | awk -F"," '{print $1}' > /tmp/results

    limit=$(cat $shodanresults/resultscount.txt | cut -d '|' -f 2 | tr -d ' ' | sort -n -r | head -n1 )
    echo -e Limit set to $limit
    cat "$shodanresults/targetdork.txt" | grep -E $(cat /tmp/results | tr '\n' '|' | sed 's/^|//; s/|$//') | while IFS='::' read a b c; do
        z=$(shodan download "$shodanresults/Collect/${a}_${target}" --limit "$limit" "${c}" | grep "Saved"; sleep 5)
        zero=$(echo "${z}" | awk '{print $2}')
            if [[ ${zero} -gt 0 ]]; then
                echo ">>${z}" | lolcat -a -d 1
            fi
    done
}

parse(){
    echo -e "${bluebg}Parsing Collected Data${NC}"
    shodan parse --fields ip_str,asn,hostnames,port,product,org,os --separator "::" $shodanresults/Collect/*.json.gz | anew -q $shodanresults/main_${target}.data
}

inscope_ip(){
    echo -e "${bluebg}Extracting In-Scope-IPs from Collected Data [ Validated by CN=*.${target} ] ${NC}"

    cat $shodanresults/main_${target}.data \
    | awk -F"::" '{print $1":"$4}' \
    | sort -u \
    | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    | httpx -silent | anew -q $shodanresults/httprobe_${target}.txt

    echo -e "${greenbg}HTTP Probe All IP:Port - $shodanresults/httprobe_${target}.txt:${NC} $(cat $shodanresults/httprobe_${target}.txt | wc -l)"

    cat $shodanresults/httprobe_${target}.txt \
    | tlsx -silent -san -cn | anew -q $shodanresults/allhttpCN_${target}.txt

    cat $shodanresults/allhttpCN_${target}.txt | cut -d ' ' -f 2 | sort -u | sed 's/^\[//; s/\]$//' | grep $target | anew -q $shodanresults/domains.txt
    echo -e "${greenbg}New Subdomains Collected via Shodan:${NC} $(cat $shodanresults/domains.txt | anew -d $subdomains| wc -l)"
    echo -e "Subdomains appended to $subdomains file: $(cat $shodanresults/domains.txt | anew $subdomains)"

    cat $shodanresults/httprobe_${target}.txt \
    | tlsx -silent -so | anew -q $shodanresults/subjectOrg_${target}.txt

    cat $shodanresults/allhttpCN_${target}.txt | grep ${target} | cut -d ' ' -f 1 | anew -q $shodanresults/ips_inscope_${target}.txt
    echo -e "${greenbg}In-Scope-IPs from Collected Data Count:${NC} $(cat $shodanresults/ips_inscope_${target}.txt | wc -l)"
}

out_of_scope_ip(){
	echo -e "${bluebg}Extracting Out-of-Scope-IPs from Collected Data [ Verified by SSL/TLS certificate subject CN ]${NC}"
    
    cat $shodanresults/main_${target}.data \
    | awk -F"::" '{print $1":"$4}' \
    | sort -u \
    | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    | grep -Ev "$(cat $shodanresults/ips_inscope_${target}.txt | cut -d"/" -f3 | cut -d":" -f1 | paste -sd "|")" \
    | sort -u \
    | grep -v "^[[:blank:]]*$" \
    | anew -q $shodanresults/out_of_scope_ip_${target}.txt

    echo -e "${greenbg}Out-of-Scope-IPs from Collected Data Count:${NC} $(cat $shodanresults/out_of_scope_ip_${target}.txt | wc -l)"
}

favicons(){
    echo -e "${bluebg}Favicons [ Validated URLs via Shodan Collects ]${NC}"
    zcat $shodanresults/Collect/*.json.gz | jq -r '.http.favicon.location|select (.!= null)'| sort -u | grep -v "^data:" | anew -q $shodanresults/favicons_${target}.txt

    echo -e "${bluebg}Favicon Hash [ Generated Favicon Hash using HTTPX ]${NC}"
    [[ -s $shodanresults/favicons_${target}.txt ]] && cat $shodanresults/favicons_${target}.txt | httpx -silent -favicon | anew -q $shodanresults/favicons_hashes${target}.txt

    echo -e "${bluebg}Technology Detection of Favicon Hash${NC} >> $shodanresults/favicons_hash_tech_${target}.txt"
    [[ -s $shodanresults/favicons_hashes${target}.txt ]] && cat $shodanresults/favicons_${target}.txt | nuclei -t MISC/favicon-detect.yaml | anew -q $shodanresults/favicons_hash_tech_${target}.txt
}

asn(){
    echo -e "${bluebg}ASN [ Autonomous System Lookup (AS / ASN / IP) ]${NC}"
    asn=$(zcat $shodanresults/Collect/*.json.gz | jq -r 'select(.asn != null)|.asn' 2> /dev/null | sort -u)
	printf "${asn}\n" | while read -r asnline; do
		name=$(host -t TXT "${asnline}.asn.cymru.com" | grep -v "NXDOMAIN" | awk -F'|' 'NR==1{print substr($NF,2,length($NF)-2)}')
		echo $name | sort -u | anew -q $shodanresults/asn_${target}.txt
	done
}

shodun(){
    target="$1"
    shodanresults=$results/Shodan
    if [ $# -ne 1 ]; then
        banner
        echo "Usage: $0 <target>"
        exit 1
    fi

    mkdir -p $shodanresults/Collect
    api_check
    shodunbanner
    [[ ! -s "$shodanresults/targetdork.txt" ]] && dork
    [[ ! -s "$shodanresults/resultscount.txt" ]] && count || cat "$shodanresults/resultscount.txt" | lolcat -a
    [[ ! -n $(find "$shodanresults/Collect/" -type f) ]] && collect
    [[ -n $(find "$shodanresults/Collect/" -type f) ]] && parse
    [[ -s "$shodanresults/main_${target}.data" && ! -e "$shodanresults/ips_inscope_${target}.txt" ]] && inscope_ip
    [[ -s "$shodanresults/main_${target}.data" && ! -e "$shodanresults/out_of_scope_ip_${target}.txt" ]] && out_of_scope_ip
    [[ ! -s $shodanresults/favicons_${target}.txt ]] && favicons
    [[ ! -s $shodanresults/asn_${target}.txt ]] && asn
}


