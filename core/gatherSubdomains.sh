#!/bin/bash
#title: CHOMTE.SH - getsubdomains
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function getsubdomains(){
  echo -e "${YELLOW}[*] Gathering Subdomains: $domain${NC}"
  domain=$1
  subdomains=$2

  [[ ! -e $subdomains ]] && echo -e "${BLUE}[#] subfinder -d $domain | anew -q $subdomains ${NC}"
  [[ ! -e $subdomains ]] && subfinder -d $domain | anew -q $subdomains &>/dev/null 2>&1
  
  [[ -e $subdomains && $rerun == true ]] && echo -e "${BLUE}[#] subfinder -d $domain | anew -q $results/subdomains.tmp ${NC}"
  [[ -e $subdomains && $rerun == true ]] && subfinder -d $domain | anew -q $results/subdomains.tmp &>/dev/null 2>&1
  [[ -e "$results/subdomains.tmp" ]] && grep -Fxvf $subdomains $results/subdomains.tmp > $results/newsubdomains.tmp

  [[ -e $results/newsubdomains.tmp ]] && nsdc=$(<$results/newsubdomains.tmp wc -l)
  [[ $rerun == true ]] && echo -e "${GREEN}${BOLD}[$] New Subdomains Collected ${NC}[$nsdc] [$results/newsubdomains.tmp]"
  
  [[ -e $results/newsubdomains.tmp ]] && cat $results/newsubdomains.tmp | anew -q $subdomains
  [[ -e $results/subdomains.tmp ]] && rm $results/subdomains.tmp

  sdc=$(<$subdomains wc -l)
  echo -e "${GREEN}${BOLD}[$] Subdomains Collected ${NC}[$sdc] [$subdomains]"
}