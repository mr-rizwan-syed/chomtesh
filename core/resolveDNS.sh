#!/bin/bash
#title: CHOMTE.SH - dnsresolve
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function dnsresolve(){
  dnsresolvein=$1
  dnsreconout=$2
  dnsxresolved=$3
  [[ ! -e $dnsreconout || $rerun == true ]] && echo -e "${YELLOW}[*] DNS Resolving Subdomains${NC}"
  dmut --update-files &>/dev/null
  [[ ! -e $dnsreconout || $rerun == true ]] && echo -e "${BLUE}[#] cat $dnsresolvein | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew $dnsreconout ${NC}"
  [[ ! -e $dnsreconout || $rerun == true ]] && cat $dnsresolvein | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew -q $dnsreconout | pv -p -t -e -N "Running DNSx" >/dev/null
    
    dnspc=$(<$dnsreconout wc -l)
    echo -e "${GREEN}${BOLD}[$] Subdomains DNS Resolved ${NC}[$dnspc] [$dnsreconout]"
    
    [[ ! -e $dnsxresolved || $rerun == true ]] && echo -e "${YELLOW}[*] Extracting DNS Resolved IP's ${NC}"
    cat $dnsreconout | cut -d ' ' -f 2 | sort -u | awk -F'[][]' '{print $2}' | grep -vE 'autodiscover|microsoft' | anew -q $dnsxresolved
    dnsxr=$(<$dnsxresolved wc -l)
    echo -e "${GREEN}${BOLD}[$] Unique Host Resolved ${NC}[$dnsxr] [$dnsxresolved]"
}