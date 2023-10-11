#!/bin/bash
#title: crt.sh CHOMTE.SH
#description:   Module of Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#version:       1.0.0
#==============================================================================

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

if ! command_exists pup; then
         echo "${YELLOW}[*] Installing pup ${NC}"
         apt install pup -y > /dev/null 2>/dev/null
fi

if ! command_exists knockknock; then
         echo "${YELLOW}[*] Installing knockknock ${NC}"
         go install github.com/harleo/knockknock@latest > /dev/null 2>/dev/null
fi

if [ $# -ne 2 ]; then
    echo "Help Menu:"
    echo "Usage: $0 project domain"
    echo "Usage: $0 project OrganizationName"
    echo "Description: This script gathers subdomains and root-domains from crt.sh"
    exit 0
fi

project=$1
target=$2

mkdir -p $project
enctarget=$(echo "$target" | tr ' ' '+')

max_retries=3
retry_delay=5

echo "Fetching Records for $enctarget"

echo "${BLLUE}https://crt.sh/?Identity=%25.$enctarget${NC}"

retries=0
while [ $retries -lt $max_retries ]; do
    response=$(curl -fSs -A "Mozilla/5.0" "https://crt.sh/?Identity=%25.$enctarget&output=json" -o $project/$enctarget.json -w "%{http_code}")
    if [ $response -ne 200 ]; then
        echo "${YELLOW}Received Negative Response. ${NC}Retrying..."
        sleep $retry_delay
        retries=$((retries + 1))
    else
        echo "${GREEN}Request successful. Exiting...${NC}"
        break
    fi
done

if [ $retries -eq $max_retries ]; then
    echo "${RED}Maximum retries reached. Exiting...${NC}"
fi

cat $project/$enctarget.json | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | grep -vE ' |@|edgecastcdn.net|cloudflaressl.com' | anew -q $project/crt_alldomains.txt
cat $project/$enctarget.json | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | grep ' ' | anew -q $project/crt_organization.txt
cat $project/crt_alldomains.txt | grep -vE "([0-9]{1,3}\.){3}[0-9]{1,3}" | awk -F '.' '{print $(NF-1)"."$NF}' | sort -u | anew -q $project/crt_apexdomains.txt

[ -e "$project/crt_alldomains.txt" ] && alldcount=$(cat $project/crt_alldomains.txt | wc -l)
[ -e "$project/crt_apexdomains.txt" ] && rdcount=$(cat $project/crt_apexdomains.txt | wc -l)

echo -e "${GREEN} [+] All Collected Domain ${NC} [$alldcount] - $project/crt_alldomains.txt"
echo -e "${GREEN} [+] Apex Root Domain count ${NC} [$rdcount] - $project/crt_apexdomains.txt"
