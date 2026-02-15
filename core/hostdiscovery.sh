#!/bin/bash

# Define colors for output
RED=$(tput setaf 1)
BLUEBG=$(tput setab 4)
NC=$(tput sgr0)

# Check if the argument is a valid CIDR notation
is_cidr() {
    local cidr_pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    if [[ $1 =~ $cidr_pattern ]]; then
        return 0
    else
        return 1
    fi
}
# Function to check if the argument is a valid ASN (Autonomous System Number)
is_asn() {
    local asn_pattern="^AS[0-9]+$"
    if [[ $1 =~ $asn_pattern ]]; then
        return 0
    else
        return 1
    fi
}

# Function to check if an IP address is private
is_private_ip() {
    local ip="$1"
    local -a private_ranges=("10." "192.168." "172.16." "172.17." "172.18." "172.19." "172.20." "172.21." "172.22." "172.23." "172.24." "172.25." "172.26." "172.27." "172.28." "172.29." "172.30." "172.31.")

    for range in "${private_ranges[@]}"; do
        if [[ "$ip" == "$range"* ]]; then
            return 1
        fi
    done

    return 0
}

# Function for host discovery
hostdiscovery() {
    ui_print_header "Host Discovery" "Identifying Alive Hosts"
    
    # Input Processing
    if [ -f "$1" ]; then
        input_file="$1"
    else
        input_file="/tmp/hostdiscovery_input.txt"
        echo "$1" > "$input_file"
    fi
    
    local target_count=$(wc -l < "$input_file")
    ui_step_start "Discovery Scan" "Nmap Ping Scan (PE/PS/PA/PU) on $target_count targets"
    ui_start_spinner "Scanning for alive hosts..."

    # Consolidated Nmap Scan
    # -sn: Ping Scan (No Port Scan)
    # -PE/PS/PA/PU: ICMP Echo, TCP SYN/ACK, UDP Probes
    # -n: No DNS resolution (faster)
    # --min-rate: Speed optimization
    nmap -sn -PE -PS443 -PA80 -PU53 -PP -n --min-rate 1000 -iL "$input_file" -oG "$results/hostdiscovery.gnmap" >/dev/null 2>&1
    
    ui_stop_spinner
    
    # Process Results
    if [ -e "$results/hostdiscovery.gnmap" ]; then
        cat "$results/hostdiscovery.gnmap" | grep "Status: Up" | cut -d ' ' -f 2 | anew -q "$results/aliveip.txt"
    fi

    local alive_count=$(wc -l < "$results/aliveip.txt" 2>/dev/null || echo 0)
    ui_print_result_item "Alive Hosts" "$results/aliveip.txt" "$alive_count"
    ui_step_end

    # Cleanup
    rm "$results/hostdiscovery.gnmap" 2>/dev/null
    [ "$input_file" == "/tmp/hostdiscovery_input.txt" ] && rm "$input_file" 2>/dev/null
    
    # Backup input if file
    if [ -f "$1" ] && [ "$1" != "$results/aliveip.txt" ]; then
        cp "$1" "$results/" 2>/dev/null
    fi
}
nmapdiscovery(){
    # Main script
    if [ $# -ne 1 ]; then
        echo "hostdiscovery.sh: $0 <argument>"
        exit 1
    fi

    # Check if it's a valid CIDR
    if is_cidr "$casn"; then
        ui_step_start "CIDR Scan" "Target: $casn"
        [[ ! -e $results/aliveip.txt || $rerun == true ]] && hostdiscovery $casn
        ui_step_end
    fi
    
    # Check if it's a valid ASN
    if is_asn "$casn"; then
        ui_step_start "ASN Scan" "Target: $casn (Enumerating prefixes)"
        ui_start_spinner "Resolving ASN to CIDRs..."
        
        # Resolve ASN to CIDRs
        [ ! -f "$casn" ] && asnmap -a $casn -silent | anew -q $results/asnip.txt >/dev/null 2>&1
        [ ! -f "$casn" ] && whois -h whois.radb.net -- "-i origin $casn" | grep route: | cut -d ':' -f 2 | tr -d ' ' | grep -Eo "([0-9.]+){4}/[0-9]+" | anew -q "$results/asnip.txt" >/dev/null 2>&1
        
        ui_stop_spinner
        
        local cidr_count=$(wc -l < "$results/asnip.txt" 2>/dev/null || echo 0)
        ui_print_result_item "CIDRs Found" "$results/asnip.txt" "$cidr_count"
        ui_step_end

        # Add-on: PTR Fingerprinting
        ui_step_start "ASN PTR Fingerprinting" "nuclei -id ptr-fingerprint"
        echo "$casn" | nuclei -id ptr-fingerprint -silent | anew "$results/ptr_findings.txt"
        
        local ptr_count=$(wc -l < "$results/ptr_findings.txt" 2>/dev/null || echo 0)
        ui_print_result_item "PTR Findings" "$results/ptr_findings.txt" "$ptr_count"
        ui_step_end
        
        # Scan found CIDRs
        if [ -e "$results/asnip.txt" ]; then
            ui_print_info "Scanning identified CIDRs..."
            while IFS= read -r cidr; do
                [[ ! -e $results/aliveip.txt || $rerun == true ]] && hostdiscovery $cidr
            done < "$results/asnip.txt"
        fi
    fi
}   
