#!/bin/bash
#title: CHOMTE.SH - hostdiscovery.sh
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#This script will do host discovery of CIDR / ASN 
#==============================================================================

# Function to check if the argument is a valid CIDR notation

casn=$1

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

hostdiscovery(){
    echo -e "${bluebg}1. Nmap Ping Scan Only on $1${NC}"
    nmap -sn $1 -oG $results/hostdiscovery1.gnmap 2>&1 &>/dev/null
    cat $results/hostdiscovery1.gnmap | grep Host | cut -d ' ' -f 2 | anew -q $results/aliveip.txt
    
    echo -e "${bluebg}2. Nmap TCP SYN ping scan on $1${NC}"
    nmap -sn -PS -n $1 -oG $results/hostdiscovery2.gnmap 2>&1 &>/dev/null
    cat $results/hostdiscovery2.gnmap | grep Host | cut -d ' ' -f 2 | anew -q $results/aliveip.txt
    
    echo -e "${bluebg}3. Nmap TCP ACK ping scan on $1${NC}"
    nmap -sn -PA -n $1 -oG $results/hostdiscovery3.gnmap 2>&1 &>/dev/null
    cat $results/hostdiscovery3.gnmap | grep Host | cut -d ' ' -f 2 | anew -q $results/aliveip.txt
    
    echo -e "${bluebg}4. Nmap ARP Ping Scan on $1${NC}"
    nmap -sn -PR -n $1 -oG $results/hostdiscovery4.gnmap 2>&1 &>/dev/null
    cat $results/hostdiscovery4.gnmap | grep Host | cut -d ' ' -f 2 | anew -q $results/aliveip.txt
    ##
    rm $results/hostdiscovery*.gnmap
}

nmapdiscovery(){
    # Main script
    if [ $# -ne 1 ]; then
        echo "hostdiscovery.sh: $0 <argument>"
        exit 1
    fi
    # Check if it's a valid CIDR
    if is_cidr "$casn"; then
        echo "CIDR notation: $casn"
        hostdiscovery $casn
    fi
    # Check if it's a valid ASN
    if is_asn "$casn"; then
        echo -e "ASN: $casn >> \n$(asnmap -a $casn -silent)"
        asnip=$(asnmap -a $casn -silent)
        echo "$asnip" | while IFS= read -r cidr; do hostdiscovery $cidr; done
    fi
}   