#!/bin/bash
# UI Helpers for CHOMTE.SH
# Implements Bashtop-like Vibrant Header + Boxed Command Style

# --- Vibrant Color Palette (256-color / TrueColor approximation) ---
# Backgrounds
BG_DARK="\e[48;5;232m"      # Very dark gray/black
BG_PANEL="\e[48;5;234m"     # Slightly lighter dark gray

# Foreground Colors
C_RESET="\e[0m"
C_BOLD="\e[1m"
C_DIM="\e[2m"

# Vibrant Neons
C_NEON_BLUE="\e[38;5;45m"    # Bright Cyan/Blue
C_NEON_GREEN="\e[38;5;46m"   # Bright Green
C_NEON_PINK="\e[38;5;198m"   # Hot Pink
C_NEON_PURPLE="\e[38;5;171m" # Light Purple
C_NEON_YELLOW="\e[38;5;226m" # Bright Yellow
C_NEON_RED="\e[38;5;196m"    # Bright Red
C_WHITE="\e[38;5;255m"       # White
C_GRAY="\e[38;5;240m"        # Dark Gray for borders

# Icons / Symbols
SYM_CHECK="[+]"
SYM_CROSS="[-]"
SYM_INFO="[*]"
SYM_CMD="[#]"
SYM_WARN="[!]"

# --- Components ---

ui_print_banner() {
    clear
    echo -e "${C_BOLD}${C_NEON_BLUE}"
    cat << "EOF"
   ██████╗██╗  ██╗ ██████╗ ███╗   ███╗████████╗███████╗   ███████╗██╗  ██╗
  ██╔════╝██║  ██║██╔═══██╗████╗ ████║╚══██╔══╝██╔════╝   ██╔════╝██║  ██║
  ██║     ███████║██║   ██║██╔████╔██║   ██║   █████╗     ███████╗███████║
  ██║     ██╔══██║██║   ██║██║╚██╔╝██║   ██║   ██╔══╝     ╚════██║██╔══██║
  ╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║   ██║   ███████╗██╗███████║██║  ██║
   ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
EOF
    echo -e "${C_RESET}"
    echo -e "  ${C_DIM}Automated Security Reconnaissance Framework${C_RESET}"
    echo -e "  ${C_NEON_PURPLE}Author: mr-rizwan-syed${C_RESET}"
    echo ""
}

ui_print_header() {
    local title="$1"
    local subtitle="$2"
    local b_col="${C_GRAY}"
    local t_col="${C_NEON_BLUE}${C_BOLD}"
    
    echo -e ""
    echo -e "${b_col}┌──[ ${t_col}${title}${C_RESET}${b_col} ]───────────────────────────────────────────────────────────┐${C_RESET}"
    if [ -n "$subtitle" ]; then
        echo -e "${b_col}│${C_RESET} ${C_DIM}${subtitle}${C_RESET}"
    fi
    echo -e "${b_col}└───────────────────────────────────────────────────────────────────────────┘${C_RESET}"
}

ui_print_info() { echo -e "${C_BOLD}${C_NEON_BLUE}${SYM_INFO} ${C_WHITE}${1}${C_RESET}"; }
ui_print_success() { echo -e "${C_BOLD}${C_NEON_GREEN}${SYM_CHECK} ${C_WHITE}${1}${C_RESET}"; }
ui_print_warning() { echo -e "${C_BOLD}${C_NEON_YELLOW}${SYM_WARN} ${C_WHITE}${1}${C_RESET}"; }
ui_print_error() { echo -e "${C_BOLD}${C_NEON_RED}${SYM_CROSS} Error: ${1}${C_RESET}"; }

# --- Unified Box System ---

# Start a unified step box with the command
# Usage: ui_step_start "Tool Name" "Command String"
ui_step_start() {
    local title="$1"
    local cmd="$2"
    local b_col="${C_GRAY}"
    local t_col="${C_NEON_BLUE}${C_BOLD}"
    local cmd_icon="${C_NEON_YELLOW}${SYM_CMD}${C_RESET}"

    echo -e "${b_col}┌──[ ${t_col}${title}${C_RESET}${b_col} ]───────────────────────────────────────────────────────────┐${C_RESET}"
    if [ -n "$cmd" ]; then
        echo -e "${b_col}│${C_RESET} ${cmd_icon} ${C_WHITE}Command:${C_RESET} ${C_DIM}${cmd}${C_RESET}"
    fi
}

# Add results to the currently open step box
# Usage: ui_step_results "Line 1" "Line 2" ...
ui_step_results() {
    local b_col="${C_GRAY}"
    local res_icon="${C_NEON_GREEN}${SYM_CHECK}${C_RESET}"
    
    # Separator
    echo -e "${b_col}│${C_RESET}"
    echo -e "${b_col}│${C_RESET} ${res_icon} ${C_WHITE}Results:${C_RESET}"
    
    for line in "$@"; do
        echo -e "${b_col}│${C_RESET}     ${line}"
    done
}

# End the step box
ui_step_end() {
    local b_col="${C_GRAY}"
    echo -e "${b_col}└───────────────────────────────────────────────────────────────────────────┘${C_RESET}"
}

# Print a detailed result item with path
# Usage: ui_print_result_item "Label" "Path/To/File" "Count"
ui_print_result_item() {
    local label="$1"
    local path="$2"
    local count="$3"
    local b_col="${C_GRAY}"
    
    # If count is 0 or empty, handle gracefully (optional)
    [ -z "$count" ] && count="0"
    
    echo -e "${b_col}│${C_RESET} ${C_NEON_BLUE}${label}${C_RESET}"
    echo -e "${b_col}│${C_RESET}     ${C_DIM}Path:${C_RESET} ${C_WHITE}${path}${C_RESET} ${C_NEON_GREEN}[${count}]${C_RESET}"
    echo -e "${b_col}│${C_RESET}"
}

# --- Legacy Compatibility Components (Refreshed Style) ---

# Print a generic line inside the box
# Usage: ui_print_box_line "Text"
ui_print_box_line() {
    local text="$1"
    local b_col="${C_GRAY}"
    echo -e "${b_col}│${C_RESET} ${text}"
}

# Print an indented command line
# Usage: ui_print_cmd "command string"
ui_print_cmd() {
    local cmd="$1"
    local b_col="${C_GRAY}"
    echo -e "${b_col}│${C_RESET}      ${C_DIM}${cmd}${C_RESET}"
}

# --- Legacy Compatibility Components (Refreshed Style) ---

ui_box_command() {
    local title="$1"
    local cmd="$2"
    ui_step_start "$title" "$cmd"
    ui_step_end
}

ui_box_results() {
    local title="$1"
    shift
    local b_col="${C_GRAY}"
    local t_col="${C_NEON_GREEN}${C_BOLD}"
    
    echo -e "${b_col}┌──[ ${t_col}${title}${C_RESET}${b_col} ]───────────────────────────────────────────────────────────┐${C_RESET}"
    for line in "$@"; do
        echo -e "${b_col}│${C_RESET}  ${line}"
    done
    echo -e "${b_col}└───────────────────────────────────────────────────────────────────────────┘${C_RESET}"
}

# Progress Bar
ui_print_progress() {
    local label="$1"
    local current="$2"
    local total="$3"
    local percent=$(( 100 * current / total ))
    local bar_len=40
    local filled=$(( bar_len * current / total ))
    local empty=$(( bar_len - filled ))
    
    local bar=$(printf "%0.s█" $(seq 1 $filled))
    local space=$(printf "%0.s░" $(seq 1 $empty))
    
    echo -ne "\r${C_NEON_BLUE}${SYM_INFO} ${label} [${C_NEON_GREEN}${bar}${C_DIM}${space}${C_RESET}] ${percent}% "
    if [ "$current" -eq "$total" ]; then
        echo ""
    fi
}

ui_start_spinner() {
    local msg="$1"
    # Hide cursor
    tput civis
    # Run spinner in background
    (
        while :; do
            for c in "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏"; do
                echo -ne "\r${C_NEON_BLUE}${SYM_INFO} ${C_WHITE}${msg}... ${C_NEON_PINK}$c${C_RESET} "
                sleep 0.1
            done
        done
    ) &
    SPINNER_PID=$!
}

ui_stop_spinner() {
    if [ -n "$SPINNER_PID" ]; then
        kill $SPINNER_PID 2>/dev/null
        wait $SPINNER_PID 2>/dev/null
        unset SPINNER_PID
    fi
    # Restore cursor
    tput cnorm
    echo -ne "\r\033[K" # Clear line
}

# Ensure spinner is stopped on exit or interrupt

# Interactive Interrupt Handler
# usage: trap ui_handle_sigint SIGINT
ui_handle_sigint() {
    # Stop any running spinner first so it doesn't mess up the prompt
    ui_stop_spinner
    
    echo -e "\n${C_BOLD}${C_NEON_RED} [!] Ctrl+C Detected! ${RED}Thats what she said...${C_RESET}"
    echo -e "${C_WHITE} Do you want to [s]kip the current step or [q]uit the script? ${C_RESET}"
    
    while true; do
        read -p " (s/q) > " choice
        case "$choice" in 
            s|S) 
                echo -e "${C_NEON_YELLOW} [*] Skipping current step...${C_RESET}"
                return 0 # Returning 0 allows script to continue to next command
                ;;
            q|Q)
                echo -e "${C_NEON_RED} [!] Exiting script.${C_RESET}"
                exit 1
                ;;
            *)
                echo -e " Please enter 's' or 'q'."
                ;;
        esac
    done
}

trap ui_stop_spinner EXIT
