#!/bin/bash
#title: CHOMTE.SH - dnsresolve
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function dnsresolve(){
  dnsresolvein=$1
  dnsreconout=$2
  [[ ! -e $dnsreconout || $rerun == true ]] && echo -e "${YELLOW}[*] DNS Resolving Subdomains${NC}"
  dmut --update-files &>/dev/null
  [[ ! -e $dnsreconout || $rerun == true ]] && echo -e "${BLUE}[#] cat $dnsresolvein | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew $dnsreconout ${NC}"
  [[ ! -e $dnsreconout || $rerun == true ]] && cat $dnsresolvein | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew -q $dnsreconout
    
    dnspc=$(<$dnsreconout wc -l)
    echo -e "${GREEN}${BOLD}[$] Subdomains DNS Resolved ${NC}[$dnspc] [$dnsreconout]"
}