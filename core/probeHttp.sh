#!/bin/bash
#title: CHOMTE.SH - httpprobing
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function httpprobing(){
  webtechcheck(){
    urlprobed=$1 webtech=$2
    webanalyze -update &>/dev/null 2>&1
    echo -e ""
    echo -e "${YELLOW}[*] Running WebTechCheck\n${NC}"
    [[ ! -e $webtech || $rerun == true ]] && echo -e "${BLUE}[#] webanalyze -hosts $urlprobed $webanalyze_flags -output csv | anew $webtech ${NC}" 
    [[ ! -e $webtech || $rerun == true ]] && webanalyze -hosts $urlprobed $webanalyze_flags -output csv 2>/dev/null | anew -q $webtech &>/dev/null 2>&1
    echo -e "${GREEN}[+] WebTechCheck Scan Completed\n${NC}"
  }
  
  echo -e "${YELLOW}[*] HTTP Probing${NC}"
  hostlist=$1
  httpxout=$2
  
  if [ -f "$hostlist" ]; then
    [[ ! -e $httpxout || $rerun == true ]] && echo -e "${BLUE}[#] cat $hostlist | httpx $httpx_flags -csv | anew -q $httpxout ${NC}"
    [[ ! -e $httpxout || $rerun == true ]] && cat $hostlist | httpx $httpx_flags -csv 2>/dev/null| anew -q $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
    [ -e $httpxout ] && echo -e "${GREEN}[+] HTTP Probe Output:${NC} $httpxout"
  else
    echo "${BLUE}[#] echo $hostlist | httpx $httpx_flags -csv | anew -q $httpxout ${NC}"
    [[ ! -e $httpxout || $rerun == true ]] && echo $hostlist | httpx $httpx_flags -csv 2>/dev/null| anew -q $httpxout | pv -p -t -e -N "HTTPX Probing is Ongoing" > /dev/null
  fi

  [[ ! -e $urlprobed || $rerun == true ]] && csvcut $httpxout -c url 2>/dev/null | grep -v url | anew $urlprobed &>/dev/null 2>&1
  [[ "$all" == true && -f "$results/httpxout2.csv" ]] && csvstack $results/httpxout.csv $results/httpxout2.csv 2>/dev/null | csvcut -c url 2>/dev/null | grep -v url | anew $urlprobed &>/dev/null 2>&1
  
  urlpc=$(<$urlprobed wc -l)
  echo -e "${GREEN}${BOLD}[$] Total Subdomain URL Probed ${NC}[$urlpc] [$urlprobed]"


  if [[ ${ipscan} == true ]] || [[ ${hostportscan} == true ]];then
      echo -e "${YELLOW}[*] Extracting Potential Host URLs${NC}"
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout 2>/dev/null| awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 ~ /^http/ {print $3}' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout 2>/dev/null| awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 == "" {print $1}' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
  fi
  
  if [[ ${domainscan} == true ]];then
      echo -e "${YELLOW}[*] Extracting Potential Subdomain URLs${NC}"
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout 2>/dev/null| awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 ~ /^http/ {print $3}' | grep -oE "^https?://[^/]*\.$domain(:[0-9]+)?" | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      [[ -e $httpxout || $rerun == true ]] && csvcut -c url,status_code,final_url $httpxout 2>/dev/null| awk -F ',' '$2 == "200" || $2 == "302"' | awk -F ',' '$3 == "" {print $1}' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
  fi
       
  [ -e $potentialsdurls-tmp ] &&  cat $potentialsdurls-tmp | sed 's/\b:80\b//g;s/\b:443\b//g' 2>/dev/null| sort -u| anew -q $potentialsdurls &>/dev/null 2>&1
  rm $potentialsdurls-tmp 2>/dev/null
        
  purlc=$(<$potentialsdurls wc -l 2>/dev/null)
  echo -e "${GREEN}${BOLD}[$] Potential Subdomain URLs Extracted ${NC}[$purlc] [$potentialsdurls]"

  # echo -e "${GREEN}[+] HTTPX Probe Completed\n${NC}"
  [ ! -e $webtech ] && webtechcheck $urlprobed $webtech
}
