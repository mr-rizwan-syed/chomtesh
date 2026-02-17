#!/bin/bash
#title: CHOMTE.SH - nmapscanner
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

# --- Environment Setup (for standalone usage) ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    export CORE_DIR="$SCRIPT_DIR/core"
    export MISC_DIR="$SCRIPT_DIR/MISC"
    
    # Source UI helpers if available
    if [ -f "$CORE_DIR/ui_helpers.sh" ]; then
        source "$CORE_DIR/ui_helpers.sh"
    fi
fi

# Fallback UI helpers if not defined (e.g. if run standalone and ui_helpers missing)
if ! command -v ui_print_header &> /dev/null; then
    ui_print_header() { echo -e "\n${C_BOLD}${C_NEON_BLUE}### $1 - $2 ###${C_RESET}"; }
    ui_print_info() { echo -e "${C_NEON_BLUE}[*]${C_RESET} $1"; }
    ui_print_success() { echo -e "${C_NEON_GREEN}[+]${C_RESET} $1"; }
    ui_print_error() { echo -e "${C_NEON_RED}[!] Error: $1${C_RESET}"; }
    ui_print_progress() { 
        local label=$1 current=$2 total=$3
        local percent=$(( 100 * current / total ))
        printf "\r${C_NEON_BLUE}[*]${C_RESET} %s: [%-40s] %d%%" "$label" $(head -c $((current * 40 / total)) < /dev/zero | tr '\0' '#') "$percent"
        [ "$current" -eq "$total" ] && echo ""
    }
    C_RESET="\e[0m"; C_BOLD="\e[1m"; C_NEON_BLUE="\e[38;5;45m"; C_NEON_GREEN="\e[38;5;46m"; 
    C_NEON_YELLOW="\e[38;5;226m"; C_NEON_RED="\e[38;5;196m"; CYAN="\e[36m"; BLUE="\e[34m"; YELLOW="\e[33m"; GREEN="\e[32m"; NC="\e[0m"
fi

scanner(){
  local ports=$(cat "$ipportin" | grep "$iphost" | cut -d ':' -f 2 | sort -u | xargs | sed -e 's/ /,/g')
  if [ -z "$ports" ]; then
      ui_print_info "No Ports found for $iphost"
  else
      ui_print_info "Running Nmap Scan on $iphost: ${CYAN}$ports${C_RESET}"
      if [ -n "$(find "$nmapscans" -maxdepth 1 -name "nmapresult-$iphost*" -print -quit)" ]; then
          ui_print_info "Nmap result exists for $iphost, Skipping..."
      else
          nmap "$iphost" -p "$ports" $nmap_flags -oX "$nmapscans/nmapresult-$iphost.xml" -oN "$nmapscans/nmapresult-$iphost.nmap" 2>$ERR_LOG >/dev/null
      fi
  fi
}

nmapconverter(){
  ui_print_info "Generating Reports..."
  # Clean old reports to avoid duplicates or errors
  rm "$nmapscans"/*.html "$nmapscans"/*.csv &>/dev/null
  
  # Convert to CSV
  ls "$nmapscans"/*.xml | xargs -I {} python3 "$MISC_DIR/xml2csv.py" -f {} -csv "$nmapscans/scans.csv" 2>$ERR_LOG >/dev/null
  [ -f "$nmapscans/scans.csv" ] && ui_print_success "Nmap CSV Generated: $nmapscans/scans.csv"
  
  # Generating HTML Report Format
  ls "$nmapscans"/*.xml | xargs -I {} xsltproc -o {}_nmap.html "$MISC_DIR/nmap-bootstrap.xsl" {} 2>$ERR_LOG
  ui_print_success "HTML Reports Generated"
  
  # Generating RAW Colored HTML Format
  ls "$nmapscans"/*.nmap | xargs -I {} sh -c "cat {} | ccze -A | ansi2html > {}_nmap_raw_colored.html" 2>$ERR_LOG
  ui_print_success "Colored HTML Reports Generated"
}

nmapscanner(){
    # Main Function
    ipportin=$1
    nmapscans=$2
    nmap_flags=${3:-$nmap_flags}
    ERR_LOG=${ERR_LOG:-/dev/null}
    
    # Check if input file exists
    if [ ! -f "$ipportin" ]; then
        ui_print_error "Input file $ipportin not found!"
        return 1
    fi

    # Use a temporary file for alive IPs to keep results directory clean if needed
    local aliveip="/tmp/aliveip_$$.txt"
    
    ui_print_header "NMAP PORT SCANNER" "Target: $ipportin"
    
    mkdir -p "$nmapscans"
    
    # Extract alive IPs from the ip:port list
    cat "$ipportin" | cut -d : -f 1 | sort -u | grep -v ip | anew -q "$aliveip"
    
    local total_hosts=$(wc -l < "$aliveip")
    local counter=0
    
    while read -r iphost; do
        counter=$((counter+1))
        ui_print_progress "Scanning Hosts" "$counter" "$total_hosts"
        scanner
    done < "$aliveip"
    
    nmapconverter
    
    # Cleanup temp file
    rm -f "$aliveip"
}

# --- Standalone Execution ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ $# -lt 2 ]; then
        echo -e "${C_BOLD}Usage:${C_RESET} $0 <ipport.txt> <output_dir> [nmap_flags]"
        echo -e "Example: $0 ipport.txt nmap_results \"-sV -sC\""
        exit 1
    fi
    nmapscanner "$1" "$2" "$3"
fi
