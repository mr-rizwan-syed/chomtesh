#!/bin/bash
#title: CHOMTE.SH - active_recon
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function active_recon(){
    
    ui_print_header "ACTIVE RECONNAISSANCE" "Dynamic Technology + Vulnerability Scan"
    
    # Identify technologies using the new module
    identify_technologies

    # Concurrency Limit (Max 3 parallel jobs)
    local MAX_JOBS=3
    local current_jobs=0

    for tech in $detected_techs; do
        # 1. Validate against allowlist (mixed case allowed, match robustly)
        if grep -F -q -x -i "$tech" "$MISC_DIR/tech-list.tags"; then
            
            # Check parallel job limit
            # count jobs that are running or stopped (to be safe)
            while [[ $(jobs -r | wc -l) -ge $MAX_JOBS ]]; do
                # Wait for at least one job to finish before starting another
                wait -n 2>$ERR_LOG
            done
            
            # 2. Extract URLs
            local url_file="$enumscan/${tech}_urls.txt"
            
            # Use anew to append new unique URLs and capture them
            # We must capture the output of anew to know if new URLs were found
            local new_urls
            # techdetect outputs all current URLs for this tech
            # anew appends only new ones to url_file and prints them to stdout
            new_urls=$(techdetect "$tech" | anew "$url_file")
            
            local result_file="$enumscan/${tech}_nuclei_results.txt"
            local workflow_file="$HOME/nuclei-templates/workflows/${tech}-workflow.yaml"
            
            # 3. Determine Execution Strategy
            # Case A: Result file missing -> Scan EVERYTHING (Full Scan)
            # Case B: Result file exists + New URLs found -> Scan NEW URLs ONLY (Incremental Scan)
            
            if [ ! -e "$result_file" ] || [ -n "$new_urls" ] || [ "$rerun" == true ]; then
                
                (
                    local target_list=""
                    local append_mode=false
                    local scan_type="Tag Scan"
                    local url_count=0
                    
                    if [ ! -e "$result_file" ] || [ "$rerun" == true ]; then
                         # Full Scan
                         target_list="$url_file"
                         url_count=$(wc -l < "$url_file")
                         scan_type="Tag Scan ($url_count URLs)"
                    else
                         # Incremental Scan
                         target_list="$enumscan/${tech}_urls_new_$(date +%s%N).tmp"
                         echo "$new_urls" > "$target_list"
                         url_count=$(wc -l < "$target_list")
                         scan_type="Incremental Scan ($url_count NEW URLs)"
                         append_mode=true
                    fi
                    
                    # Run Nuclei on target_list
                    # If append_mode is true, we output to temp file then append to main result
                    
                    local current_output="$result_file"
                    if [ "$append_mode" = true ]; then
                        current_output="${result_file}.tmp"
                    fi

                    local nuclei_cmd=""
                     if [ -f "$workflow_file" ]; then
                          nuclei_cmd="nuclei -l '$target_list' -w '$workflow_file' $nuclei_flags -o '$current_output'"
                          ui_box_command "Nuclei: $tech [$scan_type]" "$nuclei_cmd"
                          nuclei -l "$target_list" -w "$workflow_file" $nuclei_flags -o "$current_output" 2>$ERR_LOG
                     else
                          nuclei_cmd="nuclei -l '$target_list' -tags '$tech' $nuclei_flags -o '$current_output'"
                          ui_box_command "Nuclei: $tech [$scan_type]" "$nuclei_cmd"
                          nuclei -l "$target_list" -tags "$tech" $nuclei_flags -o "$current_output" 2>$ERR_LOG
                     fi
                    
                    # Merge results if appending
                    if [ "$append_mode" = true ]; then
                        if [ -e "$current_output" ]; then
                             local new_res_count=$(wc -l < "$current_output")
                             cat "$current_output" >> "$result_file"
                             ui_print_success "$tech Incremental Scan: $new_res_count new results"
                             rm "$current_output"
                        fi
                        rm "$target_list" 2>$ERR_LOG
                    else
                         if [ -e "$result_file" ]; then
                             local res_count=$(wc -l < "$result_file")
                             ui_print_success "$tech Recon Completed: $res_count results found"
                         fi
                    fi
                ) &
            fi
        fi
    done

    wait
    ui_print_success "Active Recon Completed"
}
