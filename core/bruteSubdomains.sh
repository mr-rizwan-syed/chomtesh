#!/bin/bash
#title: CHOMTE.SH - dnsreconbrute
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function dnsreconbrute(){
  # DNS Subdomain Bruteforcing
  local target="$1"
  local dnsbruteout="$2"
  
  ui_print_header "DNS RECONNAISSANCE" "Bruteforcing Subdomains"
  trap 'ui_handle_sigint' SIGINT
  
  local total_sdc=$(wc -l < "$subdomains" 2>/dev/null || echo 0)
  ui_print_info "Existing Subdomains Count: $total_sdc"

  # 1. DMUT Bruteforce
  if [[ ! -e "$dnsbruteout" || "$rerun" == true ]] && [[ "$dnsbrute" == true || "$all" == true ]]; then
      ui_step_start "DMUT Bruteforce" "dmut -u $target $dmut_flags -o $dnsbruteout"
      dmut --update-files 2>$ERR_LOG >/dev/null
      dmut -u "$target" $dmut_flags -o "$dnsbruteout" 2>$ERR_LOG
      ui_step_end
  elif [[ "$dnsbrute" == true || "$all" == true ]]; then
      ui_print_info "DMUT results already exist, skipping."
  fi
  
  # 2. AlterX Mutation & Resolution
  if [[ "$alterx" == true || "$all" == true ]]; then
      local alterx_mutated="$results/alterx_mutated.txt"
      local valid_domains="$results/valid_domains.txt"
      local wildcards="$results/wildcards.txt"
      local resolvers="$RES_DIR/resolvers.txt"
      
      if [[ ! -e "$alterx_mutated" || "$rerun" == true ]]; then
          ui_step_start "AlterX Mutation" "cat $subdomains | alterx | anew -q $alterx_mutated"
          cat "$subdomains" | alterx 2>$ERR_LOG | anew -q "$alterx_mutated" >/dev/null
          local mutation_count=$(wc -l < "$alterx_mutated" 2>/dev/null || echo 0)
          ui_print_success "AlterX Mutated Domains Generated: $mutation_count"
          ui_step_end
      fi

      if [[ -s "$alterx_mutated" ]] && [[ ! -e "$valid_domains" || "$rerun" == true ]]; then
          ui_step_start "Domain Resolution (PureDNS)" "puredns resolve $alterx_mutated ..."
          puredns resolve "$alterx_mutated" "$target" -r "$resolvers" --wildcard-batch 1000 --write "$valid_domains" --write-wildcards "$wildcards" 2>$ERR_LOG >/dev/null
          
          local valid_count=$(wc -l < "$valid_domains" 2>/dev/null || echo 0)
          local wildcard_count=$(wc -l < "$wildcards" 2>/dev/null || echo 0)
          
          ui_print_success "Valid Domains Found    : $valid_count"
          ui_print_success "Wildcards Detected     : $wildcard_count"
          
          # Add to main brute output
          [ -s "$valid_domains" ] && cat "$valid_domains" | anew -q "$dnsbruteout"
          ui_step_end
      fi
  fi

  # 3. Consolidation
  if [[ -e "$dnsbruteout" ]]; then
      local brute_tmp="$results/brutesubdomains.tmp"
      grep -Fxvf "$subdomains" "$dnsbruteout" > "$brute_tmp" 2>/dev/null
      local new_brute_count=$(wc -l < "$brute_tmp" 2>/dev/null || echo 0)
      
      cat "$dnsbruteout" | anew -q "$subdomains"
      [ -e "$brute_tmp" ] && cat "$brute_tmp" | anew -q "$subdomains"
      
      ui_print_success "New Unique Subdomains Found: $new_brute_count"
      rm -f "$brute_tmp" 2>/dev/null
  fi
  
  local final_sdc=$(wc -l < "$subdomains" 2>/dev/null || echo 0)
  ui_print_info "Total Subdomains Now: $final_sdc"
}