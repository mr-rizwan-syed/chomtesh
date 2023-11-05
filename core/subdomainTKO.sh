#!/bin/bash
#title: CHOMTE.SH - subdomaintakeover
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function subdomaintakeover(){
  mkdir -p $enumscan
  trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
  echo -e ""
  echo -e "${YELLOW}[*] Running Subdomain Takeover Scan\n${NC}" 

  if [ -e $urlprobed ]; then
      trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
      [[ ! -e $enumscan/nuclei-takeover.txt || $rerun == true ]] && echo -e "${BLUE}[#] nuclei -l $urlprobed -t ~/nuclei-templates/takeovers/ -silent | anew $enumscan/nuclei-takeover.txt ${NC}" 
      [[ ! -e $enumscan/nuclei-takeover.txt || $rerun == true ]] && nuclei -l $urlprobed -t ~/nuclei-templates/http/takeovers/ -silent | anew $enumscan/nuclei-takeover.txt 2>/dev/null
  fi
  if [ -e $subdomains ]; then
      trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
      [[ ! -e $enumscan/subjack-takeover.txt || $rerun == true ]] && echo -e "${BLUE}[#] subjack -w $subdomains -t 100 -timeout 30 -ssl -c ./MISC/fingerprints.json | anew $enumscan/subjack-takeover.txt ${NC}" 
      [[ ! -e $enumscan/subjack-takeover.txt || $rerun == true ]] && subjack -w $subdomains -t 100 -timeout 30 -ssl -c ./MISC/fingerprints.json | anew $enumscan/subjack-takeover.txt 2>/dev/null
  fi
}
