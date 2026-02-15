#!/bin/bash
#title: CHOMTE.SH - dnsresolve
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function dnsresolve(){
  dnsresolvein=$1
  dnsreconout=$2
  dnsresolved=$3
  
  [[ ! -e $dnsreconout || $rerun == true ]] && echo -e "${YELLOW}[*] DNS Resolving Subdomains${NC}"
  dmut --update-files &>/dev/null
  
  # Ensure output directory exists (just in case)
  mkdir -p "$(dirname "$dnsreconout")"
  
  [[ ! -e $dnsreconout || $rerun == true ]] && echo -e "${BLUE}[#] cat $dnsresolvein | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew $dnsreconout ${NC}"
  
  # Run DNSx
  if [[ ! -e $dnsreconout || $rerun == true ]]; then
      cat "$dnsresolvein" | dnsx $dnsx_flags -r /root/.dmut/top20.txt | anew -q "$dnsreconout"
      
      # If a 3rd argument is provided, copy the resolved domains there too
      if [[ -n "$dnsresolved" ]]; then
          cp "$dnsreconout" "$dnsresolved" 2>/dev/null
      fi
  fi
    
    dnspc=$(wc -l < "$dnsreconout" 2>/dev/null || echo 0)
    echo -e "${GREEN}${BOLD}[$] Subdomains DNS Resolved ${NC}[$dnspc] [$dnsreconout]"
}