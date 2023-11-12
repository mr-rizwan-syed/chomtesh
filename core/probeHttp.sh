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
    [[ ! -e $webtech && ! -e $urlprobed-new || $rerun == true ]] && echo -e "${BLUE}[#] webanalyze -hosts $urlprobed $webanalyze_flags -output json | anew $webtech ${NC}" 
    [[ ! -e $webtech && ! -e $urlprobed-new || $rerun == true ]] && webanalyze -hosts $urlprobed $webanalyze_flags -output json 2>/dev/null | anew -q $webtech &>/dev/null 2>&1
    [[ -e $urlprobed-new || $rerun == true ]] && webanalyze -hosts $urlprobed-new $webanalyze_flags -output json 2>/dev/null | anew -q $webtech &>/dev/null 2>&1
    echo -e "${GREEN}[+] WebTechCheck Scan Completed\n${NC}"
  }
  
  [[ ! -e $httpxout || $rerun == true ]] && echo -e "${YELLOW}[*] HTTP Probing${NC}"
  hostlist=$1
  httpxout=$2
  
  if [ -f "$hostlist" ]; then
    [[ ! -e $httpxout || $rerun == true ]] && echo -e "${BLUE}[#] cat $hostlist | httpx -silent |httpx $httpx_flags -csv -csvo utf-8 -o $httpxout -oa ${NC}"
    [[ ! -e $httpxout || $rerun == true ]] && cat $hostlist | httpx -silent | httpx $httpx_flags -csvo utf-8 -o $httpxout -oa 2>/dev/null | pv -p -t -e -N "HTTPX Probing is Ongoing"
    [ -e $httpxout ] && echo -e "${GREEN}[+] HTTP Probe Output:${NC} $httpxout"
  else
    echo "${BLUE}[#] echo $hostlist | httpx -silent | httpx $httpx_flags -csvo utf-8 -o $httpxout -oa ${NC}"
    [[ ! -e $httpxout || $rerun == true ]] && echo $hostlist | httpx -silent | httpx $httpx_flags -csvo utf-8 -o $httpxout -oa 2>/dev/null | pv -p -t -e -N "HTTPX Probing is Ongoing"
  fi

  

  if [[ ${ipscan} == true ]] || [[ ${hostportscan} == true ]] || [[ ${casnscan} == true ]];then
      [[ ! -e $potentialsdurls || $rerun == true ]] && echo -e "${YELLOW}[*] Extracting Potential Host URLs${NC}"
      [[ -e $httpxout.json || $rerun == true ]] && cat $httpxout.json | jq -r 'select(.status_code | tostring | test("^(20|30)")) | .final_url' | grep -v null | grep '^http' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      [[ -e $httpxout.json || $rerun == true ]] && cat $httpxout.json | jq -r 'select(.status_code | tostring | test("^(20|30)")) | select(.final_url == null) | .url' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
  fi
  
  if [[ ${domainscan} == true ]];then
      cat $results/httpx*.json | jq -r '.url' 2>/dev/null | anew -q $urlprobed
      urlpc=$(<$urlprobed wc -l)
      echo -e "${GREEN}[$] Total Subdomain URL Probed ${NC}[$urlpc] [$urlprobed]"

      [[ -e $results/httpxout-new.json ]] && cat $results/httpxout-new.json | jq -r '.url' > $urlprobed-new
      [[ -e $urlprobed-new ]] && newurlpc=$(<$urlprobed-new wc -l)
      [[ -e $urlprobed-new ]] && echo -e "${GREEN}[$] New Subdomain URL Probed Count${NC}[$newurlpc] [$urlprobed-new]"

      [[ ! -e $potentialsdurls || $rerun == true ]] && echo -e "${YELLOW}[*] Extracting Potential Subdomain URLs${NC}"
      [[ -e $httpxout || $rerun == true ]] && cat $httpxout.json | jq -r 'select(.status_code | tostring | test("^(20|30)")) | .final_url' | grep -v null | grep $domain | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      [[ -e $httpxout || $rerun == true ]] && cat $httpxout.json | jq -r 'select(.status_code | tostring | test("^(20|30)")) | select(.final_url == null) | .url' | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
  fi
       
  [ -e $potentialsdurls-tmp ] &&  cat $potentialsdurls-tmp | sed 's/\b:80\b//g;s/\b:443\b//g' 2>/dev/null| sort -u| anew -q $potentialsdurls &>/dev/null 2>&1
  rm $potentialsdurls-tmp 2>/dev/null
        
  purlc=$(<$potentialsdurls wc -l 2>/dev/null)
  echo -e "${GREEN}[$] Potential Subdomain URLs Extracted ${NC}[$purlc] [$potentialsdurls]"

  [ ! -e $webtech ] && webtechcheck $urlprobed $webtech
}
