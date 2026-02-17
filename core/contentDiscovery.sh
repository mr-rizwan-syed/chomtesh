#!/bin/bash
#title: CHOMTE.SH - content_discovery
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

# Fallback UI helpers if not defined
if ! command -v ui_print_header &> /dev/null; then
    ui_print_header() { echo -e "\n${C_BOLD}${C_NEON_BLUE}### $1 - $2 ###${C_RESET}"; }
    ui_print_info() { echo -e "${C_NEON_BLUE}[*]${C_RESET} $1"; }
    ui_print_success() { echo -e "${C_NEON_GREEN}[+]${C_RESET} $1"; }
    ui_print_warning() { echo -e "${C_NEON_YELLOW}[!]${C_RESET} $1"; }
    ui_print_error() { echo -e "${C_NEON_RED}[!] Error: $1${C_RESET}"; }
    ui_print_box_line() { echo -e "│ $1"; }
    ui_print_cmd() { echo -e "│      $1"; }
    ui_step_start() { echo -e "┌──[ ${BH_BLUE}$1${C_RESET} ]"; [ -n "$2" ] && echo -e "│ Command: $2"; }
    ui_step_end() { echo -e "└────────────────"; }
    ui_print_result_item() { echo -e "│ $1\n│     Path: $2 [$3]\n│"; }
    ui_start_spinner() { echo -n "[*] $1... "; }
    ui_stop_spinner() { echo "Done."; }
    C_RESET="\e[0m"; C_BOLD="\e[1m"; C_NEON_BLUE="\e[38;5;45m"; C_NEON_GREEN="\e[38;5;46m"; 
    C_NEON_YELLOW="\e[38;5;226m"; C_NEON_RED="\e[38;5;196m"; C_DIM="\e[2m"; SYM_CMD="[#]"; SYM_INFO="[*]"; NC="\e[0m"
fi

function content_discovery() {
    local target="$1"
    local output_dir="${2:-$enumscan/contentdiscovery}"
    
    # --- Worker Functions ---
    
    merge_results() {
        if [ -d "$output_dir" ]; then
            ui_print_info "Merging Content Discovery Results..."
            
            local merged_csv="$output_dir/all-cd.csv"
            local merged_txt="$output_dir/all-cd.txt"
            
            # Merge CSVs using csvstack for robustness
            if compgen -G "$output_dir/*.csv" > /dev/null; then
                # Exclude the merged file itself if it exists
                [ -f "$merged_csv" ] && rm -f "$merged_csv"
                csvstack "$output_dir"/*.csv 2>$ERR_LOG > "$merged_csv"
            fi

            # Extract 200 OKs
            if [ -s "$merged_csv" ]; then
                # Handle different CSV headers from different tools if necessary
                # csvcut -c url,status_code for ffuf
                # Filter for 200 status code
                csvcut -c url,status_code "$merged_csv" 2>$ERR_LOG | grep ',200' | cut -d , -f 1 | anew -q "$merged_txt"
                if [ -s "$merged_txt" ]; then
                    ui_print_success "Merged Results: $merged_txt"
                fi
            fi
        fi
    }

    run_ffuf_scan() {
        local list_file="$1"
        local wordlist="${WORDLIST:-/usr/share/dirb/wordlists/dicc.txt}"
        
        ui_step_start "Content Discovery (FFUF)" "Mass scan using Interlace & FFUF"
        ui_print_box_line "${C_DIM}Wordlist: $wordlist${C_RESET}"
        
        # Check output directory
        if [ -d "$output_dir" ] && [ "$(ls -A "$output_dir" 2>/dev/null)" ] && [ "$rerun" != true ]; then
            ui_print_warning "Directory $output_dir already exists and is not empty."
            ui_print_info "Skipping FFUF scan to prevent overwrite. Use -rr to force rerun."
        else
            mkdir -p "$output_dir"
            
            ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
            ui_print_cmd "${SYM_INFO} interlace -tL ${list_file} -cL \"$MISC_DIR/contentdiscovery.il\" ..."
            
            ui_start_spinner "Running FFUF on list: $(wc -l < "$list_file") targets"
            
            # Export wordlist for the .il file to consume
            export FFUF_WORDLIST="$wordlist"
            
            # Execute Interlace -> FFUF
            if [ -f "$list_file" ]; then
                interlace -tL "$list_file" -o "$output_dir" -cL "$MISC_DIR/contentdiscovery.il" --silent 2>$ERR_LOG >/dev/null
            fi
            
            ui_stop_spinner
            
            # Count results
            local count=$(ls "$output_dir"/*.csv 2>/dev/null | wc -l)
            ui_print_result_item "Scanned Targets" "$output_dir/" "$count"
        fi
        
        merge_results
        ui_step_end
    }

    run_nuclei_exposure() {
        local input="$1"
        local input_flag=""
        
        ui_step_start "Nuclei Exposure Scan" "Checking for sensitive files & exposures"
        
        mkdir -p "$output_dir"
        local exposure_file="$output_dir/nuclei-exposure.txt"
        
        if [ -f "$input" ]; then
            input_flag="-l $input"
            ui_print_box_line "${C_DIM}Target: List ($input)${C_RESET}"
        else
            input_flag="-u $input"
             ui_print_box_line "${C_DIM}Target: URL ($input)${C_RESET}"
        fi

        ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
        ui_print_cmd "${SYM_INFO} nuclei $input_flag -t ~/nuclei-templates/exposures/ ..."

        if [ ! -s "$exposure_file" ] || [ "$rerun" == true ]; then
            ui_start_spinner "Running Nuclei Exposures"
            nuclei $input_flag -t ~/nuclei-templates/exposures/ -silent 2>$ERR_LOG | anew "$exposure_file" >/dev/null
            ui_stop_spinner
        else
             ui_print_info "Nuclei exposure results already exist, skipping."
        fi
        
        local count=$(wc -l < "$exposure_file" 2>/dev/null || echo 0)
        ui_print_result_item "Exposures Found" "$exposure_file" "$count"
        
        ui_step_end
    }

    run_dirsearch_single() {
        local url="$1"
        
        ui_step_start "Content Discovery (Dirsearch)" "Single Target Scan"
        ui_print_box_line "${C_DIM}Target: $url${C_RESET}"
        
        mkdir -p "$output_dir"
        local output_file="$output_dir/dirsearch_result.csv"
        
        ui_print_box_line "${C_NEON_YELLOW}${SYM_CMD} ${C_WHITE}Command:${C_RESET}"
        ui_print_cmd "${SYM_INFO} dirsearch $dirsearch_flags -u $url ..."
        
        if [ ! -f "$output_file" ] || [ "$rerun" == true ]; then
             ui_start_spinner "Running Dirsearch"
             [ "$rerun" == true ] && rm -f "$output_file"
             dirsearch $dirsearch_flags -u "$url" --format csv -o "$output_file" 2>$ERR_LOG >/dev/null
             ui_stop_spinner
        else
             ui_print_info "Dirsearch results already exist, skipping."
        fi
        
        local count=$(grep -c "^" "$output_file" 2>/dev/null || echo 0)
        ui_print_result_item "Dirsearch Results" "$output_file" "$count"
        
        ui_step_end
    }

    # --- Main Execution Logic ---
    
    ui_print_header "Content Discovery" "Directory Fuzzing & Exposure Checks"
    trap 'ui_handle_sigint' SIGINT 2>/dev/null

    if [ -f "$target" ]; then
        # Target is a list of URLs/Domains
        run_ffuf_scan "$target"
        run_nuclei_exposure "$target"
    else
        # Target is a single URL
        run_dirsearch_single "$target"
        run_nuclei_exposure "$target"
    fi
}

# Standalone Execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ $# -lt 1 ]; then
        echo -e "${C_BOLD}Usage:${C_RESET} $0 <target_list_or_url> [output_dir]"
        echo -e "Example: $0 urls.txt ./results"
        exit 1
    fi
    # Set default ERR_LOG if not set
    export ERR_LOG=${ERR_LOG:-/dev/null}
    content_discovery "$1" "$2"
fi
