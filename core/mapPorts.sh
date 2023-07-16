#!/bin/bash
#title: CHOMTE.SH - portmapper
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

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
    mapper
}