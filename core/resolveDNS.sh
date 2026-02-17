#!/bin/bash
#title: CHOMTE.SH - dnsresolve
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function dnsresolve(){
  dnsresolvein=$1
  dnsreconout=$2
  dnsresolved=$3
  
  local resolvers="$RES_DIR/top20.txt"
  
  if [[ ! -e "$dnsreconout" || "$rerun" == true ]]; then
      ui_step_start "DNS Resolution (dnsx)" "cat $dnsresolvein | dnsx $dnsx_flags -r $resolvers"
      dmut --update-files 2>$ERR_LOG >/dev/null
      cat "$dnsresolvein" | dnsx $dnsx_flags -r "$resolvers" 2>$ERR_LOG | anew -q "$dnsreconout"
      
      # If a 3rd argument is provided, copy the resolved domains there too
      if [[ -n "$dnsresolved" ]]; then
          cp "$dnsreconout" "$dnsresolved" 2>$ERR_LOG
      fi
      ui_step_end
  fi
    
    dnspc=$(wc -l < "$dnsreconout" 2>/dev/null || echo 0)
    echo -e "${GREEN}${BOLD}[$] Subdomains DNS Resolved ${NC}[$dnspc] [$dnsreconout]"
}