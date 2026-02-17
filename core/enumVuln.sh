#!/bin/bash
#title: CHOMTE.SH - enumVuln
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

nuclei_fuzzer(){
    local input_file="$enumscan/URLs/paramurl.txt"
    local output_file="$enumscan/URLs/nuclei_fuzzing_results.txt"
    
    if [ ! -s "$input_file" ]; then
        ui_print_warning "Skipping Nuclei Fuzzer: $input_file is empty or missing."
        return 1
    fi

    if [[ ! -e "$output_file" || "$rerun" == true ]]; then
        ui_step_start "Nuclei DAST (Fuzzing)" "nuclei -silent -dast -list $input_file"
        nuclei -silent -dast -list "$input_file" 2>$ERR_LOG | anew "$output_file"
        ui_step_end
    fi

    if [ -s "$output_file" ]; then
        local count=$(wc -l < "$output_file")
        ui_step_start "Nuclei DAST (Fuzzing) Results" ""
        ui_print_result_item "Fuzzing Findings" "$output_file" "$count"
        ui_step_end
    fi
}

auto_nuclei(){
    local input_file="$urlprobed"
    local output_file="$enumscan/nuclei_pot_autoscan.txt"

    if [ ! -s "$input_file" ]; then
        ui_print_warning "Skipping Auto Nuclei: $input_file is empty or missing."
        return 1
    fi

    if [[ ! -e "$output_file" || "$rerun" == true ]]; then
        ui_step_start "Nuclei Automatic Scan" "nuclei -l $input_file $nuclei_flags -resume -as -silent"
        nuclei -l "$input_file" $nuclei_flags -resume -as -silent 2>$ERR_LOG | anew "$output_file"
        ui_step_end
    fi

    if [ -s "$output_file" ]; then
        local count=$(wc -l < "$output_file")
        ui_step_start "Auto Nuclei Results" ""
        ui_print_result_item "Vulnerabilities" "$output_file" "$count"
        ui_step_end
    fi
}

full_nuclei(){
    local input_file="$urlprobed"
    local output_file="$enumscan/nuclei_full.txt"

    if [ ! -s "$input_file" ]; then
        ui_print_warning "Skipping Full Nuclei: $input_file is empty or missing."
        return 1
    fi

    if [[ ! -e "$output_file" || "$rerun" == true ]]; then
        ui_step_start "Nuclei Full Scan" "nuclei -l $input_file $nuclei_flags -resume -silent"
        nuclei -l "$input_file" $nuclei_flags -resume -silent 2>$ERR_LOG | anew "$output_file"
        ui_step_end
    fi

    if [ -s "$output_file" ]; then
        local count=$(wc -l < "$output_file")
        ui_step_start "Full Nuclei Results" ""
        ui_print_result_item "Vulnerabilities" "$output_file" "$count"
        ui_step_end
    fi
}

function enumVuln(){
    ui_print_header "VULNERABILITY ENUMERATION" "Active Scans & Fuzzing"

    # Nucli Fuzzer
    if [[ "$vuln" == true || "$nucleifuzz" == true || "$all" == true ]]; then
        nuclei_fuzzer
    fi

    # This does not make sense, We've our own tech-detect engine
    # Auto Nuclei
    # if [[ "$vuln" == true || "$all" == true ]]; then
    #     auto_nuclei
    # fi

    # Full Nuclei
    if [[ "$all" == true ]]; then
        full_nuclei
    fi

}
