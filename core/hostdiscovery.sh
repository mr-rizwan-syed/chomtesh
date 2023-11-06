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
    trap 'echo -e "${RED}Ctrl + C detected, That'\''s what she said${NC}"' SIGINT

    if [ -f "$1" ]; then
        # Input is a file containing a list of hostnames or IP addresses
        input_file="$1"
    else
        # Input is a single hostname or IP address
        input_file="/tmp/hostdiscovery_input.txt"
        echo "$1" > "$input_file"
    fi

    echo -e "${BLUEBG}1. Nmap Ping Scan Only $1 ${NC}"
    nmap -sn -iL "$input_file" -oG "$results/hostdiscovery1.gnmap" &>/dev/null
    [ -e "$results/hostdiscovery1.gnmap" ] && cat "$results/hostdiscovery1.gnmap" | grep Host | cut -d ' ' -f 2 | anew -q "$results/aliveip.txt"

    echo -e "${BLUEBG}2. Nmap TCP SYN ping scan $1 ${NC}"
    nmap -sn -PS -iL "$input_file" -oG "$results/hostdiscovery2.gnmap" &>/dev/null
    [ -e "$results/hostdiscovery2.gnmap" ] && cat "$results/hostdiscovery2.gnmap" | grep Host | cut -d ' ' -f 2 | anew -q "$results/aliveip.txt"

    echo -e "${BLUEBG}3. Nmap TCP ACK ping scan $1 ${NC}"
    nmap -sn -PA -iL "$input_file" -oG "$results/hostdiscovery3.gnmap" &>/dev/null
    [ -e "$results/hostdiscovery3.gnmap" ] && cat "$results/hostdiscovery3.gnmap" | grep Host | cut -d ' ' -f 2 | anew -q "$results/aliveip.txt"

    is_private_ip "$(cat "$input_file")"
    
    if [[ "$is_private" -eq 1 ]]; then
        echo -e "${BLUEBG}4. Nmap ARP Ping Scan $1 ${NC}"
        nmap -sn -PR -iL "$input_file" -oG "$results/hostdiscovery4.gnmap" &>/dev/null
        [ -e "$results/hostdiscovery4.gnmap" ] && cat "$results/hostdiscovery4.gnmap" | grep Host | cut -d ' ' -f 2 | anew -q "$results/aliveip.txt"

        echo -e "${BLUEBG}5. Nmap ICMP Echo Request Scan $1 ${NC}"
        nmap -sn -PE -iL "$input_file" -oG "$results/hostdiscovery5.gnmap" &>/dev/null
        [ -e "$results/hostdiscovery5.gnmap" ] && cat "$results/hostdiscovery5.gnmap" | grep Host | cut -d ' ' -f 2 | anew -q "$results/aliveip.txt"

        echo -e "${BLUEBG}6. Nmap UDP Ping Scan $1 ${NC}"
        nmap -sn -PU -iL "$input_file" -oG "$results/hostdiscovery6.gnmap" &>/dev/null
        [ -e "$results/hostdiscovery6.gnmap" ] && cat "$results/hostdiscovery6.gnmap" | grep Host | cut -d ' ' -f 2 | anew -q "$results/aliveip.txt"
    fi

    rm "$results/hostdiscovery*.gnmap"

    # Remove the temporary input file if it was created
    if [ -f "$1" ]; then
        cp $1 $results
    fi
}
nmapdiscovery(){
    # Main script
    if [ $# -ne 1 ]; then
        echo "hostdiscovery.sh: $0 <argument>"
        exit 1
    fi

    [[ -f "$casn" ]] && echo "CIDR File" && hostdiscovery $casn
 
   # Check if it's a valid CIDR
    if is_cidr "$casn"; then
        echo "CIDR notation: $casn"
        [[ ! -e $results/aliveip.txt || $rerun == true ]] && hostdiscovery $casn
    fi
    # Check if it's a valid ASN
    if is_asn "$casn"; then
        echo -e "ASN: $casn \n"
        [ ! -f "$casn" ] && echo -e "${BLUE}[#] asnmap -a $casn -silent | anew -q $results/asnip.txt ${NC}"
        [ ! -f "$casn" ] && asnmap -a $casn -silent | anew -q $results/asnip.txt
        [ ! -f "$casn" ] && echo -e "${BLUE}[#] whois -h whois.radb.net -- \"-i origin $casn\" | grep route: | cut -d ':' -f 2 | tr -d ' ' | grep -Eo '([0-9.]+){4}/[0-9]+' | anew -q $results/asnip.txt${NC}"
        [ ! -f "$casn" ] && whois -h whois.radb.net -- "-i origin $casn" | grep route: | cut -d ':' -f 2 | tr -d ' ' | grep -Eo "([0-9.]+){4}/[0-9]+" | anew -q "$results/asnip.txt"
        [ -e "$results/asnip.txt" ] && cat $results/asnip.txt
        [ -e "$results/asnip.txt" ] && cat $results/asnip.txt | while IFS= read -r cidr; do hostdiscovery $cidr; done
        if [ -e "$results/asnip.txt" ]; then
          while IFS= read -r cidr; do
            [[ ! -e $results/aliveip.txt || $rerun == true ]] && hostdiscovery $casn
          done < "$results/asnip.txt"
        fi
    fi
}   
