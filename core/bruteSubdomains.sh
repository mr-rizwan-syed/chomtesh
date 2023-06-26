#!/bin/bash
#title: CHOMTE.SH - dnsreconbrute
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

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
  [[ $alterx == true && ! -e $results/alterx || $rerun == true ]] && echo -e "${YELLOW}[*] Performing AlterX Bruteforcing using DNSx ${NC}" || echo "${RED}AlterX is already done${NC}"
  [[ $alterx == true && ! -e $results/alterx || $rerun == true ]] && echo -e "${BLUE}[#] cat $subdomains | alterx -silent | dnsx -silent -r /root/.dmut/resolvers.txt | anew -q $dnsbruteout ${NC}"
  [[ $alterx == true && ! -e $results/alterx || $rerun == true ]] && cat $subdomains | alterx | dnsx -r /root/.dmut/resolvers.txt | anew $results/alterx && cat $results/alterx | anew $dnsbruteout | pv -p -t -e -N "Subdomain Bruteforcing using DNSx on Alterx Generated Domains" &>/dev/null 2>&1
  [[ -e $dnsbruteout ]] && grep -Fxvf $subdomains $dnsbruteout > $results/brutesubdomains.tmp
  [[ -e $dnsbruteout ]] && dnsbrute_sdc=$(cat $dnsbruteout | wc -l)
  [[ -e $dnsbruteout ]] && cat $dnsbruteout | anew -q $subdomains
  [[ -e $results/brutesubdomains.tmp ]] && dnsbrute_sdc=$(cat $results/brutesubdomains.tmp | wc -l)
  [[ -e $results/brutesubdomains.tmp ]] && cat $results/brutesubdomains.tmp | anew -q $subdomains 
  total_sdc=$(cat $subdomains | wc -l)

  echo -e ""
  echo -e "${GREEN}[$] New Unique Subdomains found by bruteforcing${NC} [$dnsbrute_sdc]"
  echo -e "${GREEN}[$] Total Subdomains Enumerated${NC} [$total_sdc]"
}