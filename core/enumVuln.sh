#!/bin/bash
#title: CHOMTE.SH - enumVuln
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaissance Scans
#author:        mr-rizwan-syed
#==============================================================================

'''
nuclei_fuzzer(){
    [[ ! -e $enumscan/URLs/nuclei_fuzzing_results.txt || $rerun == true ]] && echo -e "${YELLOW}[*] Running Nuclei Fuzzer"
    [[ ! -e $enumscan/URLs/nuclei_fuzzing_results.txt || $rerun == true ]] && echo -e "${BLUE}[#] nuclei -silent -t MISC/fuzzing-templates -list $enumscan/URLs/paramurl.txt | anew $enumscan/URLs/nuclei_fuzzing_results.txt ${NC}" 
    [[ ! -e $enumscan/URLs/nuclei_fuzzing_results.txt || $rerun == true ]] && nuclei -silent -t MISC/fuzzing-templates -list $enumscan/URLs/paramurl.txt | anew $enumscan/URLs/nuclei_fuzzing_results.txt
    [ -s $enumscan/URLs/nuclei_fuzzing_results.txt ] && echo -e ${BOLD}${GREEN}"[+] Fuzz Nuclei: [$(cat $enumscan/URLs/nuclei_fuzzing_results.txt | wc -l)] [$enumscan/URLs/nuclei_fuzzing_results.txt]"${NC}
}'''

auto_nuclei(){
    [[ ! -e $enumscan/nuclei_pot_autoscan.txt || $rerun == true ]] && echo -e "${YELLOW}[*] Running Nuclei Automatic-Scan\n${NC}"
    [[ ! -e $enumscan/nuclei_pot_autoscan.txt || $rerun == true ]] && echo "${BLUE}[#] nuclei -l $urlprobed $nuclei_flags -resume -as -silent | anew $enumscan/nuclei_pot_autoscan.txt ${NC}"
    [[ ! -e $enumscan/nuclei_pot_autoscan.txt || $rerun == true ]] && nuclei -l $urlprobed $nuclei_flags -resume -as -silent | anew $enumscan/nuclei_pot_autoscan.txt
    [ -s $enumscan/nuclei_pot_autoscan.txt ] && echo -e ${BOLD}${GREEN}"[+] Auto Nuclei: [$(cat $enumscan/nuclei_pot_autoscan.txt | wc -l)] [$enumscan/nuclei_pot_autoscan.txt]"${NC}
}

full_nuclei(){
    [[ ! -e $enumscan/nuclei_full.txt || $rerun == true ]] && echo -e "${YELLOW}[*] Running Nuclei Full-Scan\n${NC}"
    [[ ! -e $enumscan/nuclei_full.txt || $rerun == true ]] && echo "${BLUE}[#] nuclei -l $urlprobed $nuclei_flags -resume -silent | anew $enumscan/nuclei_full.txt ${NC}"
    [[ ! -e $enumscan/nuclei_full.txt || $rerun == true ]] && nuclei -l $urlprobed $nuclei_flags -resume -silent | anew $enumscan/nuclei_full.txt
    [ -s $enumscan/nuclei_full.txt ] && echo -e ${BOLD}${GREEN}"Full Nuclei: [$(cat $enumscan/nuclei_full.txt | wc -l)] [$enumscan/nuclei_full.txt]"${NC}
}

xsscan(){
    [[ ! -e $enumscan/xss_results.txt || $rerun == true ]] && echo -e ${YELLOW}"[*] Initiating XSS Scan"${NC}
    [[ ! -e $enumscan/xss_results.txt || $rerun == true ]] && echo -e ${BLUE}"[#] cat $enumscan/URLs/paramurl.txt | dalfox pipe -o $enumscan/xss_results.txt"${NC}
    [[ ! -e $enumscan/xss_results.txt || $rerun == true ]] && cat $enumscan/URLs/paramurl.txt | dalfox pipe -o $enumscan/xss_results.txt
    [[ ! -e $enumscan/xss_nuclei_fuzz_results.txt || $rerun == true ]] && echo -e "${BLUE}[#] nuclei -silent -t MISC/fuzzing-templates/xss -list $enumscan/URLs/paramurl.txt"
    [[ ! -e $enumscan/xss_nuclei_fuzz_results.txt || $rerun == true ]] && nuclei -silent -t MISC/fuzzing-templates/xss -list $enumscan/URLs/paramurl.txt 
    [ -s $enumscan/xss_results.txt || $rerun == true ] && echo -e ${BOLD}${GREEN}"XSS Scan Result: [$(cat $enumscan/xss_results.txt | wc -l)] [$enumscan/xss_results.txt]"${NC}
    [ -s $enumscan/xss_nuclei_fuzz_results.txt || $rerun == true ] && echo -e ${BOLD}${GREEN}"XSS Nuclei Fuzz Scan Result: [$(cat $enumscan/xss_nuclei_fuzz_results.txt | wc -l)] [$enumscan/xss_nuclei_fuzz_results.txt]"${NC}
}

function enumVuln(){
    [[ -s $enumscan/URLs/paramurl.txt && "$vuln" == true || $nucleifuzz == true || "$all" == true ]] && nuclei_fuzzer
    [[ "$vuln" == true ]] &&  auto_nuclei  2>/dev/null || echo -e "${BLUE}[*] Nuclei Automatic Scan on $potentialsdurls >> ${NC}$enumscan/nuclei_pot_autoscan.txt"
    [[ "$all" == true ]] && full_nuclei  2>/dev/null|| echo -e "${BLUE}[*] Nuclei Full Scan on $urlprobed >> ${NC}$enumscan/nuclei_full.txt"
    [[ "$vuln" == true ]] && xsscan 2>/dev/null || echo -e "${BLUE}[*] XSS Scan on $enumscan/URLs/paramurl.txt >> ${NC}$enumscan/xss_reults.txt"
}
