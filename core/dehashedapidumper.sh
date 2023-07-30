#!/bin/bash
# mr-rizwan-syed
# Shell script get maximum 10000 dumps of dehashed in one credit request

# Change below parameters
#---------------------------------------------#
email=XXXXXXXXXXXX@gmail.com
apikey=jom44XXXXXXXXXXXXXXXXXXXX
#---------------------------------------------#

domain=$1

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo -e "Domain: $domain"
echo "curl 'https://api.dehashed.com/search?query=domain:'${domain}'&size=10000' -u $email:$apikey -H 'Accept: application/json' > '${domain}_dehashedresults'"
curl 'https://api.dehashed.com/search?query=domain:'${domain}'&size=10000' -u $email:$apikey -H 'Accept: application/json' > ${domain}_dehashedresults

[ -e ${domain}_dehashedresults ] && cat ${domain}_dehashedresults | jq . > ${domain}_dehashedresults.json
echo -e "Results Saved: ${domain}_dehashedresults.json"
[ -e ${domain}_dehashedresults.json ] && emailcount=$(cat ${domain}_dehashedresults.json | grep email | wc -l)
[ -e ${domain}_dehashedresults ] && echo -e "Total Email Breaches of $domain: $emailcount"
