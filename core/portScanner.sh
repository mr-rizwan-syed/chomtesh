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
      
  elif [ -f "$naabuout" ]; then
      [ ! -e $aliveip ] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q &>/dev/null
      [ ! -e $ipport ] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
  # else run naabu to initiate port scan
  # starts from here
  else
    if [ -f "$portscannerin" ]; then
        echo -e ""
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -list $portscannerin $naabu_flags -o $naabuout -csv" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -list $portscannerin $naabu_flags -o $naabuout -csv 2>/dev/null| pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && csvcut -c ip $naabuout 2>/dev/null| grep -v ip | anew $aliveip -q &>/dev/null 2>&1   
        [[ ! -e $ipport || $rerun == true ]] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout" ${NC}
    else
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -host $portscannerin $naabu_flags -o $naabuout -csv" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -host $portscannerin $naabu_flags -o $naabuout -csv 2>/dev/null| pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && csvcut -c ip $naabuout 2>/dev/null| grep -v ip | anew $aliveip -q &>/dev/null
        [ ! -e $hostport ] && csvcut -c host,port $naabuout 2>/dev/null | tr ',' ':' | anew $hostport -q &>/dev/null         
        [[ ! -e $ipport || $rerun == true ]] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout" ${NC}
	  fi
  fi
}