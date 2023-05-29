#!/bin/bash

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

max_retries=3
retry_delay=5

mkdir -p $project
enctarget=$(echo "$target" | tr ' ' '+')
echo "Fetching Records for $enctarget"

echo "https://crt.sh/?Identity=%25.$enctarget"

retries=0
while [ $retries -lt $max_retries ]; do
    response=$(curl -fSs -A "Mozilla/5.0" "https://crt.sh/?Identity=%25.$enctarget" -o $project/$enctarget.html -w "%{http_code}")
    if [ $response -ne 200 ]; then
        echo "Received Negative Response. Retrying..."
        sleep $retry_delay
        retries=$((retries + 1))
    else
        echo "Request successful. Exiting..."
        break
    fi
done

if [ $retries -eq $max_retries ]; then
    echo "Maximum retries reached. Exiting..."
fi

cat $project/$enctarget.html | pup 'table tr:nth-child(1) td:nth-child(5) text{}' | grep -v ' ' | anew -q $project/alldomains.txt
cat $project/$enctarget.html | pup 'table tr:nth-child(1) td:nth-child(6) text{}' | grep -vE 'edgecastcdn.net|cloudflaressl.com' | anew -q $project/alldomains.txt
cat $project/alldomains.txt | grep -vE "([0-9]{1,3}\.){3}[0-9]{1,3}" | awk -F '.' '{print $(NF-1)"."$NF}' | sort -u | anew -q $project/rootdomains.txt

alldcount=$(cat $project/alldomains.txt | wc -l)
rdcount=$(cat $project/rootdomains.txt | wc -l)

echo "All Domain count $alldcount"
echo "Root Domain count $rdcount"

knockknock -n $domain -o $results/rootdomains.txt
echo "${GREEN} [+] Root Domain count $rdcount ${NC} - $results/rootdomains.txt"
