#!/bin/bash
#title: CHOMTE.SH - portmapper
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function portmapper(){
    mapper(){
        while read dnshost; do
            if grep -q "$dnshost" $naabuout.csv; then
                subdomains=($(grep "$dnshost" $dnsreconout | cut -d ' ' -f 1))
                ports=($(grep -w "$dnshost" $naabuout.csv | awk -F ',' '{print $2}'))
                for subdomain in "${subdomains[@]}"; do
                    for port in "${ports[@]}"; do
                        echo "${subdomain}:${port}" | anew -q $hostport
                    done
                done
            fi
        done < $dnsxresolved
    }
    [[ ! -e $hostport || $rerun == true ]] && echo -e ${YELLOW}"[*] Mapping Ports to Subdomains${NC} $dnsprobe $naabuout.csv" 
    mapper
    hostportcount=$(<$hostport wc -l)
    echo -e "${GREEN}${BOLD}[$] Host Port Count ${NC}[$hostportcount] [$hostport]"
}
