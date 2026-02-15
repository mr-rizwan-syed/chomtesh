#!/bin/bash
#title: CHOMTE.SH - content_discovery
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function content_discovery() {
    local target="$1"

    # --- Worker Functions ---
    
    merge_results() {
        if [ -d "$enumscan/contentdiscovery" ]; then
            ui_print_info "Merging Content Discovery Results..."
            
            # Merge CSVs
            if [ ! -f "$enumscan/contentdiscovery/all-cd.csv" ]; then
                # Check if there are any CSV files to merge
                if compgen -G "$enumscan/contentdiscovery/*.csv" > /dev/null; then
                     cat $enumscan/contentdiscovery/*.csv | head -n1 > "$enumscan/contentdiscovery/all-cd.csv"
                     cat $enumscan/contentdiscovery/*.csv | grep -v 'FUZZ,url,redirectlocation' | anew "$enumscan/contentdiscovery/all-cd.csv" >/dev/null
                fi
            fi

            # Extract 200 OKs
            if [ -f "$enumscan/contentdiscovery/all-cd.csv" ]; then
                csvcut -c redirectlocation,status_code "$enumscan/contentdiscovery/all-cd.csv" 2>/dev/null | grep '200' | cut -d , -f 1 | anew -q "$enumscan/contentdiscovery/all-cd.txt"
                if [ -s "$enumscan/contentdiscovery/all-cd.txt" ]; then
                    ui_print_success "Merged Results: $enumscan/contentdiscovery/all-cd.txt"
                fi
            fi
        fi
    }

    run_ffuf_scan() {
        local list_file="$1"
        
        ui_step_start "Content Discovery (FFUF)" "Mass scan using Interlace & FFUF"
        ui_print_box_line "${C_DIM}Wordlist: /usr/share/dirb/wordlists/dicc.txt${C_RESET}"
        
        # Check output directory
        if [ -d "$enumscan/contentdiscovery" ] && [ "$(ls -A $enumscan/contentdiscovery 2>/dev/null)" ] && [ "$rerun" != true ]; then
            ui_print_warning "Directory $enumscan/contentdiscovery already exists and is not empty."
            ui_print_info "Skipping FFUF scan to prevent overwrite. Use -rr to force rerun."
        else
            mkdir -p "$enumscan/contentdiscovery"
            
            ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
            ui_print_cmd "${SYM_INFO} interlace -tL ${list_file} -cL ./MISC/contentdiscovery.il ..."
            
            ui_start_spinner "Running FFUF on list: $(wc -l < "$list_file") targets"
            
            # Execute Interlace -> FFUF
            if [ -f "$list_file" ]; then
                interlace -tL "$list_file" -o "$enumscan/contentdiscovery" -cL ./MISC/contentdiscovery.il --silent 2>/dev/null >/dev/null
            fi
            
            ui_stop_spinner
            
            # Count results
            local count=$(ls "$enumscan/contentdiscovery"/*.csv 2>/dev/null | wc -l)
            ui_print_result_item "Scanned Targets" "$enumscan/contentdiscovery/" "$count"
        fi
        
        merge_results
        ui_step_end
    }

    run_nuclei_exposure() {
        local input="$1"
        local input_flag=""
        
        ui_step_start "Nuclei Exposure Scan" "Checking for sensitive files & exposures"
        
        mkdir -p "$enumscan/contentdiscovery"
        
        if [ -f "$input" ]; then
            input_flag="-l $input"
            ui_print_box_line "${C_DIM}Target: List ($input)${C_RESET}"
        else
            input_flag="-u $input"
             ui_print_box_line "${C_DIM}Target: URL ($input)${C_RESET}"
        fi

        ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
        ui_print_cmd "${SYM_INFO} nuclei $input_flag -t ~/nuclei-templates/exposures/ ..."

        if [ ! -s "$enumscan/contentdiscovery/nuclei-exposure.txt" ] || [ "$rerun" == true ]; then
            ui_start_spinner "Running Nuclei Exposures"
            nuclei $input_flag -t ~/nuclei-templates/exposures/ -silent 2>/dev/null | anew "$enumscan/contentdiscovery/nuclei-exposure.txt" >/dev/null
            ui_stop_spinner
        else
             ui_print_info "Nuclei exposure results already exist, skipping."
        fi
        
        local count=$(wc -l < "$enumscan/contentdiscovery/nuclei-exposure.txt" 2>/dev/null || echo 0)
        ui_print_result_item "Exposures Found" "$enumscan/contentdiscovery/nuclei-exposure.txt" "$count"
        
        ui_step_end
    }

    run_dirsearch_single() {
        local url="$1"
        
        ui_step_start "Content Discovery (Dirsearch)" "Single Target Scan"
        ui_print_box_line "${C_DIM}Target: $url${C_RESET}"
        
        mkdir -p "$enumscan/contentdiscovery"
        local output_file="$enumscan/contentdiscovery/dirsearch-single.csv" # Standardized name
        
        # Note: Original script used "$enumscan/$1_dirsearch.csv", which might be messy if $1 is a full URL.
        # Using a fixed name or sanitized name is better.
        # Let's try to sanitize or just use a standard standard name for single runs if it's just one.
        # Actually, let's stick to a safe name.
        
        ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
        ui_print_cmd "${SYM_INFO} dirsearch $dirsearch_flags -u $url ..."
        
        if [ ! -f "$output_file" ] || [ "$rerun" == true ]; then
             ui_start_spinner "Running Dirsearch"
             [ "$rerun" == true ] && rm -f "$output_file"
             dirsearch $dirsearch_flags -u "$url" --format csv -o "$output_file" 2>/dev/null >/dev/null
             ui_stop_spinner
        else
             ui_print_info "Dirsearch results already exist, skipping."
        fi
        
        local count=$(grep -c "^" "$output_file" 2>/dev/null || echo 0)
        ui_print_result_item "Dirsearch Results" "$output_file" "$count"
        
        ui_step_end
    }

    # --- Main Execution Logic ---
    
    ui_print_header "Content Discovery" "Directory Fuzzing & Exposure Checks"
    trap 'ui_handle_sigint' SIGINT

    if [ -f "$target" ]; then
        # Target is a list of URLs/Domains
        run_ffuf_scan "$target"
        run_nuclei_exposure "$target"
    else
        # Target is a single URL
        run_dirsearch_single "$target"
        run_nuclei_exposure "$target"
    fi
}
