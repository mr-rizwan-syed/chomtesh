#!/bin/bash
#title: CHOMTE.SH - subdomaintakeover
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function subdomaintakeover(){
  mkdir -p $enumscan
  trap 'ui_handle_sigint' SIGINT
  echo -e ""
  
  # Determine target list (All vs New)
  local target_list=""
  local msg_type="ALL"
  
  if [ -s "$results/newsubdomains.tmp" ]; then
      target_list="$results/newsubdomains.tmp"
      msg_type="NEW"
  elif [ -s "$subdomains" ]; then
      target_list="$subdomains"
  fi
  
  if [ -s "$target_list" ]; then
      echo -e "${YELLOW}[*] Running Subdomain Takeover Scan on $msg_type subdomains${NC}"
      
      # 1. Nuclei Takeover (HTTP/DNS)
      # We use the domain list; Nuclei will handle probing/connection.
      if [[ ! -e "$enumscan/nuclei-takeover.txt" || "$rerun" == true ]]; then
           echo -e "${BLUE}[#] nuclei -l $target_list -t ~/nuclei-templates/http/takeovers/ -silent | anew $enumscan/nuclei-takeover.txt ${NC}" 
           nuclei -l "$target_list" -t ~/nuclei-templates/http/takeovers/ -silent 2>/dev/null | anew "$enumscan/nuclei-takeover.txt"
      fi

      # 2. Subjack Takeover (CNAME)
      if [[ ! -e "$enumscan/subjack-takeover.txt" || "$rerun" == true ]]; then
           echo -e "${BLUE}[#] subjack -w $target_list -t 100 -timeout 30 -ssl -c ./MISC/fingerprints.json | anew $enumscan/subjack-takeover.txt ${NC}" 
           subjack -w "$target_list" -t 100 -timeout 30 -ssl -c "$MISC_DIR/fingerprints.json" -v 3 2>$ERR_LOG | grep -v "Not Vulnerable" | anew "$enumscan/subjack-takeover.txt"
      fi
  fi
}
