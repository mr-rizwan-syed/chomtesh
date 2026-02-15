#!/bin/bash
# Report Module for CHOMTE.SH

# Function: generate_report
# Description: Displays a single-window summary of the scan results.
# Usage: generate_report "$project" "$domain"
generate_report() {
    local project_name="$1"
    local target_domain="$2"

    if [[ -z "$project_name" ]]; then
         ui_print_error "Project name check failed for report."
         return
    fi
    
    # Check if target is domain or IP based on directory structure usually set in chomte.sh
    # We'll try to deduce the results path.
    # Logic from run*scan functions:
    local base_results="Results/$project_name"
    local results_dir=""
    
    if [[ -n "$target_domain" ]]; then
        if [ -f "$target_domain" ]; then
             local list_name=$(basename "$target_domain" | cut -d . -f 1)
             results_dir="$base_results/$list_name"
        else
             results_dir="$base_results/$target_domain"
        fi
    else
        # Try to find the first directory in the project folder if domain not specified?
        # Or just Error?
        # Ideally the user passes -p and -d with -r.
        # If they miss -d, we might check if Results/$project has only one child.
        if [ -d "$base_results" ]; then
            local first_dir=$(ls -d "$base_results"/*/ 2>/dev/null | head -n 1)
            if [ -n "$first_dir" ]; then
                results_dir="${first_dir%/}"
                target_domain=$(basename "$results_dir")
            fi
        fi
    fi
    
    if [[ ! -d "$results_dir" ]]; then
        ui_print_error "Results directory not found for Project: $project_name"
        return
    fi

    # clear  <-- Removed to preserve scrollback
    
    # Custom Banner for Report
    echo -e "${C_BOLD}${C_NEON_BLUE}"
    echo "  REPORT DASHBOARD: $target_domain" 
    echo -e "${C_RESET}"

    # Status Config
    local STAT_DONE="${C_NEON_GREEN}COMPLETED${C_RESET}"
    local STAT_PEND="${C_NEON_YELLOW}PENDING  ${C_RESET}"
    local STAT_MISS="${C_NEON_RED}MISSING  ${C_RESET}"
    local STAT_SKIP="${C_DIM}SKIPPED  ${C_RESET}"
    
    # Check Files & Counts
    
    # 1. Subdomains
    local sub_file="$results_dir/subdomains.txt"
    local sub_stat="$STAT_PEND"
    local sub_count="0"
    if [ -f "$sub_file" ]; then
        sub_stat="$STAT_DONE"
        sub_count=$(wc -l < "$sub_file")
    elif [ ! -f "$sub_file" ]; then
        sub_stat="$STAT_MISS"
    fi
     
    # 2. HTTP Probing
    local http_file="$results_dir/httpxout"
    local http_stat="$STAT_PEND"
    local http_count="0"
    if [ -f "$http_file" ]; then
        http_stat="$STAT_DONE"
        http_count=$(wc -l < "$http_file")
    elif [ ! -f "$http_file" ] && [ "$sub_stat" == "$STAT_DONE" ]; then
         # If subdomains done but no httpx, likely pending or skipped
         :
    fi
    
    # 3. Port Scan (Naabu)
    # Naabu creates .json file
    local port_file="$results_dir/naabuout.json"
    local port_list="$results_dir/ipport.txt"
    local port_stat="$STAT_PEND"
    local port_count="0"
    if [ -f "$port_file" ]; then
        port_stat="$STAT_DONE"
        if [ -f "$port_list" ]; then
             port_count=$(wc -l < "$port_list")
        else
             # Fallback if ipport.txt missing but json exists (shouldn't happen with current logic)
             port_count=$(grep -c "ip" "$port_file") 
        fi
    fi
    
    # 4. Vuln Scan (Nuclei)
    # Check for any nuclei results in enumscan
    local enum_dir="$results_dir/enumscan"
    local vuln_stat="$STAT_PEND"
    local vuln_count="0"
    
    if [ -d "$enum_dir" ]; then
        local nucleifiles=$(find "$enum_dir" -name "*_nuclei_results.txt" 2>/dev/null)
        if [ -n "$nucleifiles" ]; then
             vuln_stat="$STAT_DONE"
             # Sum lines of all results
             vuln_count=$(cat $nucleifiles 2>/dev/null | wc -l)
        fi
    fi
    
    # Draw Dashboard Box
    local b_col="${C_GRAY}"
    local t_col="${C_NEON_BLUE}${C_BOLD}"
    
    echo -e "${b_col}┌──[ ${t_col}SCAN SUMMARY${C_RESET}${b_col} ]───────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${b_col}│${C_RESET}"
    
    printf "${b_col}│${C_RESET}   %-30s : %b (%s found)\n" "Subdomain Enumeration" "$sub_stat" "$sub_count"
    printf "${b_col}│${C_RESET}   %-30s : %b (%s alive)\n" "HTTP Probing" "$http_stat" "$http_count"
    printf "${b_col}│${C_RESET}   %-30s : %b (%s open)\n" "Port Scanning" "$port_stat" "$port_count"
    printf "${b_col}│${C_RESET}   %-30s : %b (%s issues)\n" "Vulnerability Scan" "$vuln_stat" "$vuln_count"
    
    echo -e "${b_col}│${C_RESET}"
    echo -e "${b_col}└───────────────────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""
}
