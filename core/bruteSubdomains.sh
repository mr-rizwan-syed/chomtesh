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

  [[ ! -e $dnsbruteout  || $rerun == true ]] && echo -e "${YELLOW}[*] DNSRecon: Bruteforcing Subdomains using DMUT ${NC}"
  dmut --update-files &>/dev/null
  [[ ! -e $dnsbruteout  || $rerun == true ]] && echo -e "${BLUE}[#] dmut -u $domain $dmut_flags -o $dnsbruteout ${NC}"
  [[ ! -e $dnsbruteout  || $rerun == true ]] && dmut -u "$domain" $dmut_flags -o $dnsbruteout
  
  [[ $alterx == true && ! -e $results/alterx_mutated.txt || $rerun == true ]] && echo -e "${YELLOW}[*] DNSRecon: Performing AlterX Bruteforcing using PureDNS ${NC}"
  dmut --update-files &>/dev/null
  [[ $alterx == true && ! -e $results/alterx_mutated.txt || $rerun == true ]] && echo -e "${BLUE}[#] cat $subdomains | alterx | anew -q $results/alterx_mutated.txt ${NC}"
  [[ $alterx == true && ! -e $results/alterx_mutated.txt || $rerun == true ]] && cat $subdomains | alterx | anew -q $results/alterx_mutated.txt &>/dev/null 2>&1
  [[ -s $results/alterx_mutated.txt ]] && alterx_mutated_count=$(cat $results/alterx_mutated.txt | wc -l)
  [[ -s $results/alterx_mutated.txt ]] && echo -e "${GREEN}[$] AlterX Mutated Domains Generated${NC} [$alterx_mutated_count]"

  [[ $alterx == true && ! -e $results/valid_domains.txt || $rerun == true ]] && echo -e "${BLUE}[#] puredns resolve $results/alterx_mutated.txt $domain -r /root/.dmut/resolvers.txt --wildcard-batch 1000 --write $results/valid_domains.txt --write-wildcards $results/wildcards.txt ${NC}"
  [[ $alterx == true && ! -e $results/valid_domains.txt || $rerun == true ]] && puredns resolve $results/alterx_mutated.txt $domain -r /root/.dmut/resolvers.txt --wildcard-batch 1000 --write $results/valid_domains.txt --write-wildcards $results/wildcards.txt 2>/dev/null
  [[ -s $results/valid_domains.txt ]] && cat $results/valid_domains.txt | anew -q $dnsbruteout &>/dev/null 2>&1

  [[ -e $dnsbruteout ]] && grep -Fxvf $subdomains $dnsbruteout > $results/brutesubdomains.tmp
  [[ -e $dnsbruteout ]] && dnsbrute_sdc=$(cat $dnsbruteout | wc -l)
  [[ -e $dnsbruteout ]] && cat $dnsbruteout | anew -q $subdomains
  [[ -e $results/brutesubdomains.tmp ]] && brute_sdc=$(cat $results/brutesubdomains.tmp | wc -l)
  [[ -e $results/brutesubdomains.tmp ]] && cat $results/brutesubdomains.tmp | anew -q $subdomains
  
  echo -e "${GREEN}[$] New Unique Subdomains found by DNS bruteforcing${NC} [$brute_sdc]"
  [[ -s $results/valid_domains.txt ]] && puredns_count=$(cat $results/valid_domains.txt | wc -l) && echo -e "${GREEN}[$] PureDNS Resolved Valid Domains${NC} [$puredns_count]"
  [[ -s $results/wildcards.txt ]] && wildcard_count=$(cat $results/wildcards.txt | wc -l) && echo -e "${GREEN}[$] Wildcard Domains Detected${NC} [$wildcard_count]"
  total_sdc=$(cat $subdomains | wc -l)
  echo -e "${GREEN}[$] Total Subdomains Enumerated${NC} [$total_sdc]"
}