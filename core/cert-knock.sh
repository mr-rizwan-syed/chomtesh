#!/bin/bash
#title: cert-knock.sh CHOMTE.SH
#description:   Module of Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#version:       2.0.0
#==============================================================================

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
NC=`tput sgr0`

## Put you whoisxmlapi here
API_KEY=""
## https://user.whoisxmlapi.com/products
API_ENDPOINT="https://reverse-whois.whoisxmlapi.com/api/v2"

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

if ! command_exists jq; then
         echo "${YELLOW}[*] Installing jq ${NC}"
         apt install jq -y > /dev/null 2>/dev/null
fi

if ! command_exists anew; then
         echo "${YELLOW}[*] Installing anew ${NC}"
         if command_exists go;then
                 go install -v github.com/tomnomnom/anew@latest > /dev/null 2>/dev/null
         else
                echo -e "${RED}You need to install Go first"
         fi
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

crtdomains(){
echo -e "${BLUE}Gathering Apex/Root/TLDs with crt.sh${NC}"
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

cat $project/$enctarget.json | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | grep -vE ' |@|edgecastcdn.net|cloudflaressl.com' | anew -q $project/crt_collected.txt
cat $project/$enctarget.json | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | grep ' ' | anew -q $project/crt_organization.txt
cat $project/crt_collected.txt | grep -vE "([0-9]{1,3}\.){3}[0-9]{1,3}" | awk -F '.' '{print $(NF-1)"."$NF}' | sort -u | anew -q $project/crt_apexdomains.txt

}

ReverseWhois(){
echo -e "${BLUE}Gathering Apex/Root/TLDs with Reverse Whois${NC}"
REQUEST_JSON=$(cat <<EOF
{
    "apiKey": "$API_KEY",
    "searchType": "current",
    "mode": "purchase",
    "punycode": true,
    "basicSearchTerms": {
        "include": [
            "$target"
        ]
    }
}
EOF
)

if [ -z "$API_KEY" ]; then
    echo "${RED}Error: API key is missing. Please provide a valid WHOISXMLAPI key.${NC}"
else
    ReverseWhois=$(curl -s -X POST -H "Content-Type: application/json" -d "$REQUEST_JSON" "$API_ENDPOINT")
    # Check if API request was successful
    if [ $? -ne 0 ]; then
      echo "Error: API request failed."
      exit 1
    fi

        # Print the API response to the console
    echo "$ReverseWhois" | jq -r '.domainsList[]' | anew -q $project/revese_whois_apexdomains.txt
fi

}

crtdomains
ReverseWhois

[ -e "$project/crt_collected.txt" ] && alldcount=$(cat $project/crt_collected.txt | wc -l)
[ -e "$project/crt_apexdomains.txt" ] && rccount=$(cat $project/crt_apexdomains.txt | wc -l)
[ -e "$project/revese_whois_apexdomains.txt" ] && rwcount=$(cat $project/revese_whois_apexdomains.txt | wc -l)
totalcount=$(cat $project/revese_whois_apexdomains.txt $project/crt_apexdomains.txt | anew $project/total_apexdomains.txt | wc -l)

echo -e "${GREEN} [+] All CRT Collected Domain ${NC} [$alldcount] - $project/crt_collected.txt"
echo -e "${GREEN} [+] CRT Apex Root Domain count ${NC} [$rccount] - $project/crt_apexdomains.txt"
echo -e "${GREEN} [+] Reverse Whois Apex Root Domain count ${NC} [$rwcount] - $project/revese_whois_apexdomains.txt"
echo -e "${GREEN} [+] All Apex Root Domain count ${NC} [$totalcount] -- $project/total_apexdomains.txt"
tree $project -I '*.json'
