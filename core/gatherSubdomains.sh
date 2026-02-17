#!/bin/bash
#title: CHOMTE.SH - getsubdomains
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function getsubdomains(){
  local target="$1"
  local output_file="$2"
  
  if [ -z "$target" ] || [ -z "$output_file" ]; then
      ui_print_error "gatherSubdomains requires target and output file arguments"
      return 1
  fi

  ui_print_header "SUBDOMAIN ENUMERATION" "$target"
  
  # Determine subfinder flag based on input type (-d for single, -dL for list)
  local subfinder_flag="-d"
  if [ -f "$target" ]; then
      subfinder_flag="-dL"
  fi

  # Prepare temporary file for new subdomains
  local new_subs_file="$results/newsubdomains.tmp"
  
  # Option 2: Unified Step Box
  ui_step_start "Subfinder" "subfinder $subfinder_flag $target $subfinder_flags | anew -q $output_file"
  
  # Optimize: Check if output file exists.
  # If it exists, we track NEW subdomains in new_subs_file.
  # If it doesn't exist (fresh scan), we just populate output_file directly.
  # This avoids redundant httpx probing on "new" domains that are actually ALL domains.
  
  if [ -s "$output_file" ] && [ "$rerun" != true ]; then
      ui_print_info "Existing results found. Skipping passive enumeration."
  else
      if [ -s "$output_file" ]; then
          : > "$new_subs_file"
          subfinder "$subfinder_flag" "$target" $subfinder_flags 2>$ERR_LOG | anew "$output_file" > "$new_subs_file"
      else
          subfinder "$subfinder_flag" "$target" $subfinder_flags 2>$ERR_LOG | anew "$output_file" > /dev/null
          rm -f "$new_subs_file" 2>/dev/null # Ensure clean state
      fi
  fi

  # Reporting
  local new_count=0
  if [ -f "$new_subs_file" ]; then
      new_count=$(wc -l < "$new_subs_file")
  fi
  local total_count=$(wc -l < "$output_file")
  
  # Build results array for boxed output
  local results_data=()
  results_data+=("Total Subdomains : $total_count")
  
  if [ "$new_count" -gt 0 ]; then
      results_data+=("New Subdomains   : $new_count ($new_subs_file)")
  else
      results_data+=("New Subdomains   : 0")
  fi
  results_data+=("Output File      : $output_file")

  ui_step_results "${results_data[@]}"
  ui_step_end
  
  # Cleanup if empty
  if [ "$new_count" -eq 0 ]; then
      rm -f "$new_subs_file"
  fi
}
