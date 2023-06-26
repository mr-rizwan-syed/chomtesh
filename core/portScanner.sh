#!/bin/bash
#title: CHOMTE.SH - portscanner
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function portscanner(){
  portscannerin=$1
  naabuout=$2
  
  scanner(){
    ports=$(cat $ipport| grep $iphost | cut -d ':' -f 2 | xargs | sed -e 's/ /,/g')
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
      if [[ $nmap == "true" ]];then
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
      fi
  }

  echo -e "${YELLOW}[*] Port Scanning on DNS Probed Hosts${NC}"

  # This will check if naaabuout file is present than extract aliveip and if nmap=true then run nmap on each ip on respective open ports.
  if [[ $hostportscan == true ]] && [ -f $portscannerin ]; then
      declared_paths
      cat $hostportlist | cut -d : -f 1 | anew $aliveip -q &>/dev/null
      ipport=$hostportlist
      nmapscanner
  elif [ -f "$naabuout" ]; then
      [ ! -e $aliveip ] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q &>/dev/null
      [ ! -e $ipport ] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
      nmapscanner
  # else run naabu to initiate port scan
  # starts from here
  else
    if [ -f "$portscannerin" ]; then
        echo -e ""
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -list $portscannerin $naabu_flags -o $naabuout -csv" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -list $portscannerin $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q &>/dev/null 2>&1   
        [[ ! -e $ipport || $rerun == true ]] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout" ${NC}
        nmapscanner
    else
        echo -e ${YELLOW}"[*] Running Quick Port Scan on $portscannerin" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && echo -e ${BLUE}"[#] naabu -host $portscannerin $naabu_flags -o $naabuout -csv" ${NC}
        [[ ! -e $naabuout || $rerun == true ]] && naabu -host $portscannerin $naabu_flags -o $naabuout -csv | pv -p -t -e -N "Naabu Port Scan is Ongoing" &>/dev/null 2>&1
        [[ ! -e $aliveip || $rerun == true ]] && csvcut -c ip $naabuout | grep -v ip | anew $aliveip -q &>/dev/null
        [ ! -e $hostport ] && csvcut -c host,port $naabuout 2>/dev/null | tr ',' ':' | anew $hostport -q &>/dev/null         
        [[ ! -e $ipport || $rerun == true ]] && csvcut -c ip,port $naabuout 2>/dev/null | tr ',' ':' | anew $ipport -q &>/dev/null
        echo -e ${GREEN}"[+] Quick Port Scan Completed $naabuout" ${NC}
        nmapscanner
	  fi
  fi
}