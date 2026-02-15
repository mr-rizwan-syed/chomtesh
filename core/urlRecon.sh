#!/bin/bash
#title: CHOMTE.SH - recon_url
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

recon_url(){
    trap 'ui_handle_sigint' SIGINT
    mkdir -p "$enumscan/URLs"

    ui_print_header "URL Reconnaissance" "Passive & Active Enumeration + JS Analysis"

    # --- Worker Functions (Silent) ---
    passivereconurl(){
        # Extract subdomains
        if [ ! -e "$urlprobedsd" ] || [ "$rerun" == true ]; then 
            cat "$urlprobed" | awk -F[/:] '{print $4}' | sort -u | anew -q "$urlprobedsd" &>/dev/null
        fi
        
        # Gau - Passive Recon
        if [ ! -e "$enumscan/URLs/gau-allurls.txt" ] || [ "$rerun" == true ]; then
            cat "$urlprobedsd" | gau --threads 10 2>/dev/null | anew "$enumscan/URLs/gau-allurls.txt" >/dev/null
        fi
        
        # Subjs - Passive Recon
        if [ ! -e "$enumscan/URLs/subjs-allurls.txt" ] || [ "$rerun" == true ]; then
             cat "$urlprobed" | subjs 2>/dev/null | anew "$enumscan/URLs/subjs-allurls.txt" >/dev/null
        fi
    }

    activereconurl(){
        if [ ! -e "$enumscan/URLs/katana-allurls.txt" ] || [ "$rerun" == true ]; then
            katana -list "$urlprobed" $katana_flags 2>/dev/null | anew "$enumscan/URLs/katana-allurls.txt" >/dev/null
        fi
    }

    pot_url(){
        ([ ! -e $enumscan/URLs/potentialurls.txt ] || [ "$rerun" == true ]) && cat $enumscan/URLs/*-allurls.txt | gf excludeExt | anew $enumscan/URLs/potentialurls.txt -q &>/dev/null 2>&1
        ([ ! -e $enumscan/URLs/paramurl.txt ] || [ "$rerun" == true ]) && cat $enumscan/URLs/potentialurls.txt | qsinject -c MISC/qs-rules.yaml 2>/dev/null | anew $enumscan/URLs/paramurl.txt -q &>/dev/null
    }

    jsextractor(){
        ([ ! -e $enumscan/URLs/alljsurls.txt ] || [ "$rerun" == true ]) && cat $enumscan/URLs/*-allurls.txt | egrep -iv '\.json' | grep -iE "\.js$" | anew $enumscan/URLs/alljsurls.txt -q &>/dev/null 2>&1
    }

    validjsurlextractor(){
        if [ ! -e "$enumscan/URLs/validjsurls.txt" ] || [ "$rerun" == true ]; then
            httpx -l "$enumscan/URLs/alljsurls.txt" -mc 200 -silent 2>/dev/null | anew "$enumscan/URLs/validjsurls.txt" >/dev/null
        fi
    }

    jsleak_scan(){
        mkdir -p "$enumscan/URLs/JSLeak"
        
        if [ ! -e "$enumscan/URLs/JSLeak/jsleak_secret_output.txt" ] || [ "$rerun" == true ]; then
            cat "$enumscan/URLs/validjsurls.txt" | jsleak -s > "$enumscan/URLs/JSLeak/jsleak_secret_output.txt" 2>/dev/null
        fi
        
        if [ ! -e "$enumscan/URLs/JSLeak/jsleak_link_output.txt" ] || [ "$rerun" == true ]; then
            cat "$enumscan/URLs/validjsurls.txt" | jsleak -l -c 30 > "$enumscan/URLs/JSLeak/jsleak_link_output.txt" 2>/dev/null
        fi

        # Parse Secrets
        grep "\[" "$enumscan/URLs/JSLeak/jsleak_secret_output.txt" | sort -u | anew "$enumscan/URLs/secretsfromjs.txt" >/dev/null

        # Parse Endpoints
        cat "$enumscan/URLs/JSLeak/jsleak_link_output.txt" | sort -u | anew "$enumscan/URLs/endpointsfromjs.txt" >/dev/null
    }

    wordsfromjsextractor(){
        ([ ! -e $enumscan/URLs/wordsfromjs.txt ] || [ "$rerun" == true ]) && cat $enumscan/URLs/validjsurls.txt | python3 ./MISC/getjswords.py 2>/dev/null | anew -q $enumscan/URLs/wordsfromjs.txt 2>/dev/null
    }

    varjsurlsextractor(){
        ([ ! -e $enumscan/URLs/varfromjs.txt ] || [ "$rerun" == true ]) && interlace --silent -tL $enumscan/URLs/validjsurls.txt -c "bash ./MISC/jsvar.sh _target_ 2>/dev/null | anew -q $enumscan/URLs/varfromjs.txt" 2>/dev/null
    }

    # --- Phase 1: URL Gathering ---
    if [ -s "$urlprobed" ]; then
        ui_step_start "URL Discovery" ""
        ui_print_box_line "${C_DIM}Running Passive (Gau, Subjs) & Active (Katana) scans parallelly${C_RESET}"
        ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
        ui_print_cmd "${SYM_INFO} gau --threads 10 ..."
        ui_print_cmd "${SYM_INFO} subjs ..."
        ui_print_cmd "${SYM_INFO} katana -list $urlprobed $katana_flags ..."
        
        ui_start_spinner "Enumerating URLs from $(wc -l < "$urlprobed") sources"
        
        passivereconurl &
        PID_PASSIVE=$!
        
        activereconurl &
        PID_ACTIVE=$!
        
        wait $PID_PASSIVE $PID_ACTIVE
        ui_stop_spinner
        
        # Count Results
        gau_count=$(wc -l < "$enumscan/URLs/gau-allurls.txt" 2>/dev/null || echo 0)
        subjs_count=$(wc -l < "$enumscan/URLs/subjs-allurls.txt" 2>/dev/null || echo 0)
        katana_count=$(wc -l < "$enumscan/URLs/katana-allurls.txt" 2>/dev/null || echo 0)
        total_urls=$(cat $enumscan/URLs/*-allurls.txt 2>/dev/null | sort -u | wc -l)

        ui_print_result_item "Gau (Passive)" "$enumscan/URLs/gau-allurls.txt" "$gau_count"
        ui_print_result_item "Subjs (Passive)" "$enumscan/URLs/subjs-allurls.txt" "$subjs_count"
        ui_print_result_item "Katana (Active)" "$enumscan/URLs/katana-allurls.txt" "$katana_count"
        ui_print_result_item "Total Unique URLs" "$enumscan/URLs/potentialurls.txt" "$total_urls"
        
        ui_step_end
    fi

    # --- Phase 2: Processing & Filtering ---
    if [ -s "$enumscan/URLs/gau-allurls.txt" ] || [ -s "$enumscan/URLs/katana-allurls.txt" ]; then
        ui_step_start "URL Processing" ""
        ui_print_box_line "${C_DIM}Filtering Potential URLs & Parameter Injection${C_RESET}"
        ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
        ui_print_cmd "${SYM_INFO} gf excludeExt (Filtering)"
        ui_print_cmd "${SYM_INFO} qsinject (Param Discovery)"
        ui_print_cmd "${SYM_INFO} grep .js (JS Extraction)"
        
        ui_start_spinner "Processing $total_urls URLs"

        jsextractor
        pot_url
        validjsurlextractor
        
        ui_stop_spinner

        js_count=$(wc -l < "$enumscan/URLs/alljsurls.txt" 2>/dev/null || echo 0)
        pot_count=$(wc -l < "$enumscan/URLs/potentialurls.txt" 2>/dev/null || echo 0)
        param_count=$(wc -l < "$enumscan/URLs/paramurl.txt" 2>/dev/null || echo 0)
        valid_js_count=$(wc -l < "$enumscan/URLs/validjsurls.txt" 2>/dev/null || echo 0)

        ui_print_result_item "All JS URLs" "$enumscan/URLs/alljsurls.txt" "$js_count"
        ui_print_result_item "Potential URLs" "$enumscan/URLs/potentialurls.txt" "$pot_count"
        ui_print_result_item "Param URLs" "$enumscan/URLs/paramurl.txt" "$param_count"
        ui_print_result_item "Valid JS (200)" "$enumscan/URLs/validjsurls.txt" "$valid_js_count"
        
        ui_step_end
    fi
    # --- Phase 3: JS Analysis ---
    if [ -s "$enumscan/URLs/validjsurls.txt" ]; then
        ui_step_start "JS Analysis" ""
        ui_print_box_line "${C_DIM}Extracting Secrets, Endpoints, Words & Variables from JS${C_RESET}"
        ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
        ui_print_cmd "${SYM_INFO} jsleak -s (Secrets)"
        ui_print_cmd "${SYM_INFO} jsleak -l (Endpoints)"
        ui_print_cmd "${SYM_INFO} Regular Expressions (Words, Vars)"
        
        ui_start_spinner "Analyzing $(wc -l < "$enumscan/URLs/validjsurls.txt") JS files"

        jsleak_scan &
        PID_JSLEAK=$!
        
        wordsfromjsextractor &
        PID_WORDS=$!
        
        varjsurlsextractor &
        PID_VARS=$!
        
        wait $PID_JSLEAK $PID_WORDS $PID_VARS
        ui_stop_spinner
        
        sec_count=$(wc -l < "$enumscan/URLs/secretsfromjs.txt" 2>/dev/null || echo 0)
        end_count=$(wc -l < "$enumscan/URLs/endpointsfromjs.txt" 2>/dev/null || echo 0)
        word_count=$(wc -l < "$enumscan/URLs/wordsfromjs.txt" 2>/dev/null || echo 0)
        var_count=$(wc -l < "$enumscan/URLs/varfromjs.txt" 2>/dev/null || echo 0)
        
        ui_print_result_item "Secrets Found" "$enumscan/URLs/secretsfromjs.txt" "$sec_count"
        ui_print_result_item "Endpoints Found" "$enumscan/URLs/endpointsfromjs.txt" "$end_count"
        ui_print_result_item "Words Extracted" "$enumscan/URLs/wordsfromjs.txt" "$word_count"
        ui_print_result_item "Vars Extracted" "$enumscan/URLs/varfromjs.txt" "$var_count"
        
        ui_step_end
    fi
}

xnl(){
    trap 'ui_handle_sigint' SIGINT
    mkdir -p "$enumscan/URLs"

    # Fix for Config Path
    WAYMORE_CONFIG_FILE="config.yml"
    if [ -f "$WAYMORE_CONFIG_FILE" ]; then
        URLSCAN_API_KEY=$(grep "URLSCAN_API_KEY:" "$WAYMORE_CONFIG_FILE" | awk -F'[][]' '{print $2}')
        # Ensure we are editing the correct file or a copy if needed. 
        # Assuming in-place edit is fine for now as per original script logic.
        sed -i "s/URLSCAN_API_KEY:.*/URLSCAN_API_KEY: $URLSCAN_API_KEY/" "$WAYMORE_CONFIG_FILE"
    else
        ui_print_error "Waymore config.yml not found at $WAYMORE_CONFIG_FILE"
    fi

    ui_step_start "Deep Enumeration (XNL)" ""
    ui_print_box_line "${C_DIM}Running Waymore -> xnLinkFinder -> Trufflehog${C_RESET}"
    ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
    
    # Define commands for display
    local waymore_cmd="waymore -i $domain -mode B -oU $enumscan/URLs/waymore.txt -oR $enumscan/URLs/waymoreResponses/"
    local xnl_cmd="xnLinkFinder -i $enumscan/URLs/waymoreResponses/ -sp $urlprobed -sf $domain -o ...params.txt -owl ...wordlist.txt"
    local hog_cmd="trufflehog filesystem $enumscan/URLs/waymoreResponses --only-verified"

    # Print all commands upfront (or as they run? user asked for upfront or indented under [#] Command)
    # User sample:
    # │ [#] Command: Running Waymore -> xnLinkFinder -> Trufflehog
    # [*] Cmd: waymore ...
    # This implies mixed execution feedback. 
    # Let's try to match: Header -> Description -> Command Title -> Indented Commands
    
    ui_print_cmd "${SYM_INFO} Cmd: ${waymore_cmd}"
    ui_print_cmd "${SYM_INFO} Cmd: ${xnl_cmd}"
    ui_print_cmd "${SYM_INFO} Cmd: ${hog_cmd}"
    
    # 1. Waymore
    if [ ! -f "$enumscan/URLs/waymore.txt" ] || [ "$rerun" == true ]; then
        ui_start_spinner "Running Waymore (Mode B)"
        waymore -i $domain -mode B -oU $enumscan/URLs/waymore.txt -oR $enumscan/URLs/waymoreResponses/ >/dev/null 2>&1
        ui_stop_spinner
    fi
    local waymore_cnt=$(wc -l < "$enumscan/URLs/waymore.txt" 2>/dev/null || echo 0)
    
    # 2. xnLinkFinder
    if [ -d "$enumscan/URLs/waymoreResponses" ]; then
        if [ ! -f "$enumscan/URLs/xnLinkFinder_links.txt" ] || [ "$rerun" == true ]; then
            ui_start_spinner "Running xnLinkFinder on Responses"
            xnLinkFinder -i $enumscan/URLs/waymoreResponses/ -sp $urlprobed -sf $domain -o $enumscan/URLs/xnLinkFinder_links.txt -op $enumscan/URLs/xnLinkFinder_parameters.txt -owl $enumscan/URLs/xnLinkFinder_wordlist.txt >/dev/null 2>&1
            ui_stop_spinner
        fi
    fi
    local xnl_links=$(wc -l < "$enumscan/URLs/xnLinkFinder_links.txt" 2>/dev/null || echo 0)
    
    # 3. Trufflehog
    if [ -d "$enumscan/URLs/waymoreResponses" ]; then
        if [ ! -f "$enumscan/URLs/trufflehog-results.txt" ] || [ "$rerun" == true ]; then
            ui_start_spinner "Scanning for Secrets (Trufflehog)"
            trufflehog filesystem $enumscan/URLs/waymoreResponses --only-verified 2>/dev/null | anew -q $enumscan/URLs/trufflehog-results.txt
            ui_stop_spinner
        fi
    fi
    local hog_cnt=$(wc -l < "$enumscan/URLs/trufflehog-results.txt" 2>/dev/null || echo 0)

    ui_print_result_item "Waymore URLs" "$enumscan/URLs/waymore.txt" "$waymore_cnt"
    ui_print_result_item "xnLinkFinder Links" "$enumscan/URLs/xnLinkFinder_links.txt" "$xnl_links"
    ui_print_result_item "Trufflehog Secrets" "$enumscan/URLs/trufflehog-results.txt" "$hog_cnt"
    
    ui_step_end
}
