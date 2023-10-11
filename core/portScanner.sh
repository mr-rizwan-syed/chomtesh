#!/bin/bash
#title: CHOMTE.SH - portscanner
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function portscanner(){
  portscannerin=$1
  naabuout=$2
  
  echo -e "${YELLOW}[*] Port Scanning on DNS Probed Hosts${NC}"

  # This will check if naaabuout file is present than extract aliveip
  if [[ $hostportscan == true ]] && [ -f $portscannerin ]; then
      declared_paths
      [ -e $hostportlist ] && cat $hostportlist | cut -d : -f 1 | anew $aliveip -q &>/dev/null
      
  elif [ -f "$naabuout.csv" ]; then
      [ ! -e $aliveip ] && csvcut -c ip $naabuout.csv | grep -v ip | anew $aliveip -q &>/dev/null
      [ ! -e $ipport ] && csvcut -c ip,port $naabuout.csv 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
  # else run naabu to initiate port scan
  # starts from here
  else
    if [ -f "$portscannerin" ]; then
        echo -e ""
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -list $portscannerin $naabu_flags -j -o $naabuout.json" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -list $portscannerin $naabu_flags -j -o $naabuout.json 2>/dev/null| pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && cat  $naabuout.json | jq -r '"\(.ip)"' | anew $aliveip -q &>/dev/null 2>&1
        [[ ! -e $ipport || $rerun == true ]] && cat  $naabuout.json | jq -r '"\(.ip):\(.port)"' | anew $ipport -q &>/dev/null
	[[ ! -e $naabuout.csv || $rerun == true ]] && python3 ./core/naabu_json2csv.py $naabuout.json $naabuout.csv &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout.csv" ${NC}
    else
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -host $portscannerin $naabu_flags -j -o $naabuout.json" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -host $portscannerin $naabu_flags -j -o $naabuout.json 2>/dev/null| pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && cat  $naabuout.json | jq -r '"\(.ip)"'| anew $aliveip -q &>/dev/null
        [[ ! -e $hostport || $rerun == true ]] && cat  $naabuout.json | jq -r '"\(.host):\(.port)"' | anew $hostport -q &>/dev/null
        [[ ! -e $ipport || $rerun == true ]] && cat  $naabuout.json | jq -r '"\(.ip):\(.port)"' | anew $ipport -q &>/dev/null
	[[ ! -e $naabuout.csv || $rerun == true ]] && python3 ./core/naabu_json2csv.py $naabuout.json $naabuout.csv &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout.csv" ${NC}
    fi
  fi
}
