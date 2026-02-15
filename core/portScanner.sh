#!/bin/bash
#title: CHOMTE.SH - portscanner
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================
# Function to extract naabu results
function naabuextract(){
    # Convert JSON to CSV if needed
    [[ ! -e $naabuout.csv || $rerun == true ]] && python3 ./core/naabu_json2csv.py $naabuout.json $naabuout.csv 2>/dev/null
    
    # Extract Alive IPs
    cat $naabuout.json 2>/dev/null | jq -r 'select(.cdn == null) | "\(.ip)"' | anew $aliveip -q 2>/dev/null
    
    # Extract IP:Port
    cat $naabuout.json 2>/dev/null | jq -r 'select(.cdn == null) | "\(.ip):\(.port)"' | anew $ipport -q 2>/dev/null
    
    # Extract Host:Port
    cat $naabuout.json 2>/dev/null | jq -r '"\(.host):\(.port)"' | grep -v null | anew $hostport -q 2>/dev/null
}

function portscanner(){
    ui_print_header "Port Scanning" "Identifying Open Ports with Naabu"
    
    local target="$1"
    naabuout="$2"

    # Input validation
    if [ -z "$target" ]; then
        ui_print_error "Port scanning target is missing!"
        return
    fi
    
    # Determine scan mode
    local scan_cmd=""
    local scan_msg=""
    
    if [ -f "$target" ]; then
        scan_msg="Scanning list of hosts from file: $target"
        # Check if we should use specialized hostportlist logic
        if [[ $hostportscan == true ]] && [ -e "$hostportlist" ]; then
             scan_msg="Using provided host:port list"
        else
             scan_cmd="naabu -list $target ${naabu_flags} -j -o $naabuout.json"
        fi
    else
        scan_msg="Scanning single target: $target"
        scan_cmd="naabu -host $target ${naabu_flags} -j -o $naabuout.json"
    fi
    
    ui_step_start "Naabu Scan" "$scan_msg"
    ui_print_cmd "${SYM_INFO} Cmd: $scan_cmd"
    
    # Special case: HostPort Scan (Skip Naabu if list exists)
    if [[ $hostportscan == true ]] && [ -f "$target" ] && [ -e "$hostportlist" ]; then
        ui_print_info "Skipping Naabu, importing $hostportlist..."
        declared_paths
        cat "$hostportlist" | cut -d : -f 1 | anew "$aliveip" -q 2>/dev/null
    
    elif [ -f "$naabuout.json" ] && [ "$rerun" != true ]; then
        ui_print_info "Existing results found. Skipping scan."
        naabuextract
    
    else
        # Run Naabu
        ui_start_spinner "Running Naabu..."
        
        # Ensure output dir exists
        mkdir -p "$(dirname "$naabuout")"
        
        # Run command, capture stderr to log
        eval "$scan_cmd >/dev/null 2> $naabuout.err"
        local exit_code=$?
        
        ui_stop_spinner
        
        if [ $exit_code -ne 0 ]; then
            ui_print_error "Naabu failed with exit code $exit_code"
            ui_print_error "Check log: $naabuout.err"
            # Optional: print last few lines of error
            tail -n 3 "$naabuout.err" | while read -r line; do ui_print_cmd "${C_NEON_RED}> $line${C_RESET}"; done
        fi
        
        naabuextract
    fi
    
    # Statistics
    local alive_cnt=$(wc -l < "$aliveip" 2>/dev/null || echo 0)
    local ipport_cnt=$(wc -l < "$ipport" 2>/dev/null || echo 0)
    local hostport_cnt=$(wc -l < "$hostport" 2>/dev/null || echo 0)
    
    ui_print_result_item "Alive IPs Found" "$aliveip" "$alive_cnt"
    ui_print_result_item "IP:Port Pairs" "$ipport" "$ipport_cnt"
    ui_print_result_item "Host:Port Pairs" "$hostport" "$hostport_cnt"
    ui_step_end
}
