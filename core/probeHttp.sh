#!/bin/bash
#title: CHOMTE.SH - httpprobing
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function httpprobing(){
  webtechcheck(){
    urlprobed=$1 webtech=$2
    wappscan -update &>/dev/null 2>&1
    ui_print_header "WEBTECH CHECK (WAPPSCAN)"
    
    local wapp_cmd="wappscan -l $urlprobed $wappscan_flags -json -o $webtech"
    if [[ -e $urlprobed-new || $rerun == true ]]; then
        wapp_cmd="wappscan -l $urlprobed-new $wappscan_flags -json -o $webtech"
    fi
    ui_box_command "Wappscan" "$wapp_cmd"
    
    # Run wappscan
    [[ ! -e $webtech && ! -e $urlprobed-new || $rerun == true ]] && wappscan -l $urlprobed $wappscan_flags -json -o $webtech 2>/dev/null
    [[ -e $urlprobed-new || $rerun == true ]] && wappscan -l $urlprobed-new $wappscan_flags -json -o $webtech 2>/dev/null
    echo "" # Spacer
    ui_print_success "WebTechCheck Scan Completed"
  }
  
  [[ ! -e $httpxout || $rerun == true ]] && ui_print_header "HTTP PROBING"
  hostlist=$1
  httpxout=$2
  
  if [ -f "$hostlist" ]; then
    local httpx_cmd="cat $hostlist | httpx $httpx_flags -csv -csvo utf-8 -o $httpxout -oa"
    [[ ! -e $httpxout || $rerun == true ]] && ui_box_command "HTTPX" "$httpx_cmd"
    [[ ! -e $httpxout || $rerun == true ]] && cat $hostlist | httpx $httpx_flags -csv -csvo utf-8 -o $httpxout -oa 2>/dev/null
    [ -e $httpxout ] && ui_print_success "HTTP Probe Output: $httpxout"
  else
    local httpx_cmd="echo $hostlist | httpx $httpx_flags -csvo utf-8 -o $httpxout -oa"
    ui_box_command "HTTPX" "$httpx_cmd"
    [[ ! -e $httpxout || $rerun == true ]] && echo $hostlist | httpx $httpx_flags -csv -csvo utf-8 -o $httpxout -oa 2>/dev/null
  fi

  if [[ ${ipscan} == true ]] || [[ ${hostportscan} == true ]] || [[ ${casnscan} == true ]];then
      cat $results/httpx*.json | jq -r '.url' 2>/dev/null | anew -q $urlprobed
      urlpc=$(<$urlprobed wc -l)
      
      local results_data=()
      results_data+=("Total Probed URLs    : $urlpc")
      results_data+=("Probed List          : $urlprobed")
      ui_box_results "Probing Results" "${results_data[@]}"
      
      [[ ! -e $potentialsdurls || $rerun == true ]] && ui_print_info "Extracting Potential Host URLs"
      if [[ -e $httpxout.json || $rerun == true ]]; then
          # Logic:
          # 1. Select interesting status codes (2xx, 3xx, 401, 405)
          # 2. Output .url (always interesting if status matches)
          # 3. Output .final_url (if it exists and is different from .url)
          cat $httpxout.json | jq -r 'select((.status_code >= 200 and .status_code < 400) or .status_code == 401 or .status_code == 405) | .url, (.final_url // empty)' | sort -u | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      fi
  fi
  
  if [[ ${domainscan} == true ]];then
      cat $results/httpx*.json | jq -r '.url' 2>/dev/null | anew -q $urlprobed
      urlpc=$(<$urlprobed wc -l)
      
      local results_data=()
      results_data+=("Total Probed URLs    : $urlpc ($urlprobed)")

      [[ -e $results/httpxout-new.json ]] && cat $results/httpxout-new.json | jq -r '.url' > $urlprobed-new
      [[ -e $urlprobed-new ]] && newurlpc=$(<$urlprobed-new wc -l)
      [[ -e $urlprobed-new ]] && results_data+=("New Probed URLs      : $newurlpc ($urlprobed-new)")

      ui_box_results "Probing Results" "${results_data[@]}"

      [[ ! -e $potentialsdurls || $rerun == true ]] && ui_print_info "Extracting Potential Subdomain URLs"
      if [[ -e $httpxout || $rerun == true ]]; then
          # Logic:
          # Capture both initial URL and Final URL if they are in scope (contain domain)
          cat $httpxout.json | jq -r 'select((.status_code >= 200 and .status_code < 400) or .status_code == 401 or .status_code == 405) | .url, (.final_url // empty)' | grep "$domain" | sort -u | anew -q $potentialsdurls-tmp &>/dev/null 2>&1
      fi
  fi
       
  [ -e $potentialsdurls-tmp ] &&  cat $potentialsdurls-tmp | sed 's/\b:80\b//g;s/\b:443\b//g' 2>/dev/null| sort -u| anew -q $potentialsdurls &>/dev/null 2>&1
  rm $potentialsdurls-tmp 2>/dev/null
        
  purlc=$(<$potentialsdurls wc -l 2>/dev/null)
  
  local potential_data=()
  potential_data+=("Potential URLs       : $purlc")
  potential_data+=("File                 : $potentialsdurls")
  ui_box_results "Extraction Results" "${potential_data[@]}"

  [ ! -e $webtech ] && webtechcheck $urlprobed $webtech
}
