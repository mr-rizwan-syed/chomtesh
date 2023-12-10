#!/bin/bash
#title: CHOMTE.SH - portscanner
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================
function naabuextract(){
    [[ ! -e $aliveip || $rerun == true ]] && cat  $naabuout.json | jq -r 'select(.cdn == null) | "\(.ip)"' | anew $aliveip -q &>/dev/null
    [[ ! -e $ipport || $rerun == true ]] && cat  $naabuout.json | jq -r 'select(.cdn == null) | "\(.ip):\(.port)"' | anew $ipport -q &>/dev/null
    [[ ! -e $hostport || $rerun == true ]] && cat  $naabuout.json | jq -r '"\(.host):\(.port)"' | grep -v null | anew $hostport -q &>/dev/null
    [[ ! -e $naabuout.csv || $rerun == true ]] && python3 ./core/naabu_json2csv.py $naabuout.json $naabuout.csv &>/dev/null
}

function portscanner(){
  portscannerin=$1
  naabuout=$2

  [[ ! -e $naabuout.json || $rerun == true ]] && echo -e "${YELLOW}[*] Port Scanning on DNS Probed Hosts${NC}"

  # This will check if naaabuout file is present than extract aliveip
  if [[ $hostportscan == true ]] && [ -f $portscannerin ]; then
      declared_paths
      [ -e $hostportlist ] && cat $hostportlist | cut -d : -f 1 | anew $aliveip -q &>/dev/null

  elif [ -f "$naabuout.json" ]; then
    naabuextract
  # else run naabu to initiate port scan
  # starts from here
  else
    if [ -f "$portscannerin" ]; then
        echo -e ""
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout.json || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -list $portscannerin $naabu_flags -j -o $naabuout.json" ${NC}
        [[ ! -e $naabuout.json || $rerun == true ]] && naabu -list $portscannerin $naabu_flags -j -o $naabuout.json
        naabuextract
    else
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -host $portscannerin $naabu_flags -j -o $naabuout.json" ${NC}
        [[ ! -e $naabuout.json || $rerun == true ]] && naabu -host $portscannerin $naabu_flags -j -o $naabuout.json
        naabuextract
    fi
  fi

aliveipcount=$(<$aliveip wc -l)
echo -e "${GREEN}${BOLD}[$] Alive-IP Count ${NC} [$aliveipcount] [$aliveip]"
ipportcount=$(<$ipport wc -l)
echo -e "${GREEN}${BOLD}[$] IP Port Count ${NC} [$ipportcount] [$ipport]"
hostportcount=$(<$hostport wc -l)
echo -e "${GREEN}${BOLD}[$] Host Port Count ${NC} [$hostportcount] [$hostport]"
}
