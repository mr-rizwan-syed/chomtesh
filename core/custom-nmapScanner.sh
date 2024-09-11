#Author: mr-rizwan-syed
#Nmap Custom Scanner

GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
CYAN=`tput setaf 6`
NC=`tput sgr0`

# Usage
# ./nmapport.sh ipport.txt Output-Folder "-sV -sC"

ipport=$1
nmapscans=$2
nmapflags=$3

mkdir -p $2
cat $ipport | cut -d : -f 1 > $2/aliveip.txt

scanner(){
        ports=$(cat $ipport| grep $iphost | cut -d ':' -f 2 | xargs | sed -e 's/ /,/g')
            if [ -z "$ports" ]
            then
                echo "No Ports found for $iphost"
            else
                echo ${CYAN}"[$] Running Nmap Scan on"${NC} $iphost ======${CYAN} $ports ${NC}
                if [ -n "$(find $nmapscans -maxdepth 1 -name 'nmapresult-$iphost*' -print -quit)" ]; then
                    echo "${CYAN}Nmap result exists for $iphost, Skipping this host...${NC}"
                else
                    	echo "nmap $iphost -p $ports $nmapflags -oA $2/nmapresult-$iphost"
			nmap $iphost -p $ports $nmapflags -oA $nmapscans/nmapresult-$iphost &>/dev/null
              fi 
            fi
        }

mkdir -p $nmapscans
echo -e ${YELLOW}"[*] Running Nmap Scan"${NC}
counter=0
 while read iphost; do
 	scanner
        counter=$((counter+1))
 done <"$2/aliveip.txt"