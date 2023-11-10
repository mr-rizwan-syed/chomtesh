#!/bin/bash
#title: CHOMTE.SH - nmapscanner
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================
# nmapscanner <ipport-input> <nmapscans-directory>
# nmapscanner ipport.txt nmapscans

scanner(){
  ports=$(cat $ipportin| grep $iphost | cut -d ':' -f 2 | sort -u | xargs | sed -e 's/ /,/g')
    if [ -z "$ports" ]
    then
        echo -e "No Ports found for $iphost"
    else
        echo -e ""
        echo -e ${CYAN}"[$] Running Nmap Scan on"${NC} $iphost ======${CYAN} $ports ${NC}
        if [ -n "$(find $nmapscans -maxdepth 1 -name 'nmapresult-$iphost*' -print -quit)" ]; then
          echo -e "${CYAN}Nmap result exists for $iphost, Skipping this host...${NC}"
        else
          [ ! -e $nmapscans/nmapresult-$iphost.nmap ] && nmap $iphost -p $ports $nmap_flags -oX $nmapscans/nmapresult-$iphost.xml -oN $nmapscans/nmapresult-$iphost.nmap &>/dev/null
        fi
    fi
}

nmapconverter(){
  rm $nmapscans/*.html &>/dev/null
  rm $nmapscans/*.csv &>/dev/null
  # Convert to csv
  ls $nmapscans/*.xml | xargs -I {} python3 $PWD/MISC/xml2csv.py -f {} -csv {}.csv &>/dev/null
  echo -e "${GREEN}[+] All Nmap CSV Generated ${NC}"
  # Merge all csv
  [ ! -e $nmapscans/Nmap_Final_Merged.csv ] && csvstack $nmapscans/*.csv > $nmapscans/Nmap_Final_Merged.csv 2>/dev/null
  echo -e "${GREEN}[+] Merged Nmap CSV Generated ${NC}$nmapscans/Nmap_Final_Merged.csv"
  # Generating HTML Report Format
  ls $nmapscans/*.xml | xargs -I {} xsltproc -o {}_nmap.html ./MISC/nmap-bootstrap.xsl {} 2>$nmapscans/error.log
  echo -e "${GREEN}[+] HTML Report Format Generated ${NC}"
  # Generating RAW Colored HTML Format
  ls $nmapscans/*.nmap | xargs -I {} sh -c 'cat {} | ccze -A | ansi2html > {}_nmap_raw_colored.html' 2>$nmapscans/error.log
  echo -e "${GREEN}[+] HTML RAW Colored Format Generated ${NC}"
}

nmapscanner(){
    # Main Function
    ipportin=$1
    nmapscans=$2
    [ ! -e $aliveip ] && echo -e "cat $ipportin | cut -d : -f 1 | sort -u | grep -v ip | anew -q $aliveip"
    [ ! -e $aliveip ] && cat $ipportin | cut -d : -f 1 | sort -u | grep -v ip | anew -q $aliveip
    cat $ipportin | cut -d : -f 1 | sort -u | while read ip; do echo -n "$ip ";grep "^$ip" $ipportin | cut -d : -f 2 | tr '\n' ' ' | echo -e Total Ports Count [$(wc -w)]; done
    mkdir -p $nmapscans
    echo -e ${YELLOW}"[*] Running Nmap Scan"${NC}
    counter=0
    while read iphost; do
        scanner
        counter=$((counter+1))
        progress=$(($counter * 100 / $(wc -l < "$aliveip")))
        printf "Progress: [%-50s] %d%%\r" $(head -c $(($progress / 2)) < /dev/zero | tr '\0' '#') $progress
    done <"$aliveip"
    [ -e "$nmapscans/Nmap_Final_Merged.csv" ] && echo -e "$nmapscans/Nmap_Final_Merged.csv Exist" || nmapconverter

}
