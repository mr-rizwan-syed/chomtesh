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
  total_sdc=$(cat $subdomains | wc -l)
  echo -e "${GREEN}[$] Existing Subdomains Count${NC} [$total_sdc]"

  [[ ! -e $dnsbruteout  || $rerun == true ]] && echo -e "${YELLOW}[*] Bruteforcing Subdomains DNSRecon${NC}"
  dmut --update-files &>/dev/null
  [[ ! -e $dnsbruteout  || $rerun == true ]] && echo -e "${BLUE}[#] dmut -u "$domain" $dmut_flags -o $dnsbruteout ${NC}"
  [[ ! -e $dnsbruteout  || $rerun == true ]] && dmut -u "$domain" $dmut_flags -o $dnsbruteout
  [[ $alterx == true && ! -e $results/alterx || $rerun == true ]] && echo -e "${YELLOW}[*] Performing AlterX Bruteforcing using DNSx ${NC}"
  [[ $alterx == true && ! -e $results/alterx || $rerun == true ]] && echo -e "${BLUE}[#] cat $subdomains | alterx | dnsx -silent -r /root/.dmut/resolvers.txt -wd $domain| anew -q $dnsbruteout ${NC}"
  [[ $alterx == true && ! -e $results/alterx || $rerun == true ]] && cat $subdomains | alterx | dnsx -silent -r /root/.dmut/resolvers.txt -wd $domain| anew $results/alterx && cat $results/alterx | anew -q $dnsbruteout | pv -p -t -e -N "Subdomain Bruteforcing using DNSx on Alterx Generated Domains" &>/dev/null 2>&1
  [[ -e $dnsbruteout ]] && grep -Fxvf $subdomains $dnsbruteout > $results/brutesubdomains.tmp
  [[ -e $dnsbruteout ]] && dnsbrute_sdc=$(cat $dnsbruteout | wc -l)
  [[ -e $dnsbruteout ]] && cat $dnsbruteout | anew -q $subdomains
  [[ -e $results/brutesubdomains.tmp ]] && brute_sdc=$(cat $results/brutesubdomains.tmp | wc -l)
  [[ -e $results/brutesubdomains.tmp ]] && cat $results/brutesubdomains.tmp | anew -q $subdomains
  
  echo -e "${GREEN}[$] New Unique Subdomains found by DNS bruteforcing${NC} [$brute_sdc]"
  total_sdc=$(cat $subdomains | wc -l)
  echo -e "${GREEN}[$] Total Subdomains Enumerated${NC} [$total_sdc]"
}