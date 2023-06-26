#!/bin/bash
#title: CHOMTE.SH - content_discovery
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function content_discovery(){
  mergeffufcsv(){
      echo -e "${YELLOW}[*] Merging All Content Discovery Scan CSV - ${NC}\n"
      if [ -d $enumscan/contentdiscovery ] && [ ! -f $enumscan/contentdiscovery/all-cd.csv ]; then
          csvstack $enumscan/contentdiscovery/*.csv > $enumscan/contentdiscovery/all-cd.csv 2>/dev/null
          csvcut -c redirectlocation,content_length $enumscan/contentdiscovery/all-cd.csv | grep '200' | cut -d , -f 1 | anew $enumscan/contentdiscovery/all-cd.txt
          echo -e "${GREEN}[*] Merged All Content Discovery Scan CSV - ${NC}$enumscan/contentdiscovery/all-cd.csv\n"
      fi
  }
  
  ffuflist(){
      trap 'echo -e "${RED}Ctrl + C detected in content_discovery${NC}"' SIGINT
      echo -e "${YELLOW}[*] Running Content Discovery Scan - FFUF using dirsearch wordlist\n${NC}"
      echo -e "${BLUE}[*] interlace -tL $1 -o $enumscan/contentdiscovery -cL ./MISC/contentdiscovery.il --silent ${NC}"
      echo -e "${BLUE}[*contentdiscovery.il*] ffuf -u _target_/FUZZ -w /usr/share/dirb/wordlists/dicc.txt -sa -of csv -mc 200,201,202,203,403 -fl 0 -c -ac -recursion -recursion-depth 2 -s -v -o _output_/_cleantarget_-cd.csv ${NC}"
      if [ "$(ls -A $enumscan/contentdiscovery 2>/dev/null)" = "" ]; then
          echo -e ""
          mkdir -p $enumscan/contentdiscovery
          [ -e $1 ] && interlace -tL $1 -o $enumscan/contentdiscovery -cL ./MISC/contentdiscovery.il --silent 2>/dev/null| pv -p -t -e -N "Content Discovery using FFUF with Dirsearch wordlist" >/dev/null
          echo -e "${GREEN}[*] Content Discovery Scan Completed CSV - ${NC}\n"
      else
          echo -e "${RED}ContentDiscovery Directory already exist; Remove $enumscan/contentdiscovery directory if you want to re-run.${NC}"
      fi
      mergeffufcsv
  }

nuclei_exposure(){
    trap 'echo -e "${RED}Ctrl + C detected, Thats what she said${NC}"' SIGINT
    echo -e ""
    echo -e "${YELLOW}[*] Running Nuclei Exposure Scan\n${NC}"
    if [[ -f "$1" ]]; then
        echo -e "${BLUE}[*] nuclei -l $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt\n${NC}"
        [ ! -e $enumscan/contentdiscovery/nuclei-exposure.txt ] && nuclei -l $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt
    else
        echo -e "${BLUE}[*] nuclei -u $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt\n${NC}"
        [ ! -e $enumscan/contentdiscovery/nuclei-exposure.txt ] && nuclei -u $1 -t ~/nuclei-templates/exposures/ -silent | anew $enumscan/contentdiscovery/nuclei-exposure.txt
    fi
}

    #[[ -f $1 ]] && cat $1 | dirsearch --stdin $dirsearch_flags --format csv -o $enumscan/dirsearch_results.csv 2>/dev/null
    [[ -f $1 ]] && ffuflist $1 && nuclei_exposure $1
    [[ ! -f $1 ]] && dirsearch $dirsearch_flags -u $1 -o $enumscan/$1_dirsearch.csv 2>/dev/null && nuclei_exposure $1
}

