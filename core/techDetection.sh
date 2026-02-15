#!/bin/bash
# Tech Detection Module for CHOMTE.SH

# Function: identify_technologies
# Description: Aggregates detected technologies from various sources and identifies unique techs.
# Usage: identify_technologies
# Sets global: detected_techs
identify_technologies() {
    # Pre-process all found technologies and URLs into a single file for efficiency
    # Format: url,tech
    local all_tech_urls="$results/all_tech_urls.txt"
    : > "$all_tech_urls"

    # Extract from httpxmerge.csv (Column 2 is tech)
    if [ -e "$results/httpxmerge.csv" ]; then
        csvcut -c url,tech "$results/httpxmerge.csv" 2>/dev/null | tail -n +2 >> "$all_tech_urls"
    fi

    # Extract from httpxout.json
    if [ -e "$httpxout.json" ]; then
         cat "$httpxout.json" | jq -r 'select(.tech // [] | length > 0) | [.url, .tech[]] | @csv' | tr -d '"' >> "$all_tech_urls" 2>/dev/null
    fi

    # Extract from webtech.json
    if [ -e "$webtech" ]; then
        cat "$webtech" | jq -r '. | [.hostname, .matches[].app_name] | @csv' | tr -d '"' >> "$all_tech_urls" 2>/dev/null
    fi

    # Normalize invalid characters and ensure format
    # Remove quotes, brackets, and clean up common JSON artifacts
    sed -i 's/"//g; s/\[//g; s/\]//g; s/ //g' "$all_tech_urls"

    # Get unique list of detected technologies (lowercase for comparison)
    # We use awk to lowercase the tech name (field 2)
    # extract all fields after the first comma (url), replace commas with newlines, strip version numbers
    detected_techs=$(cat "$all_tech_urls" | tr ',' '\n' | grep -v '://' | sed -E 's/:[0-9.]+//g' | sort -u | grep -v "^$" | awk '{print tolower($0)}')
    
    # Export explicitly if needed, though in bash functions sharing scope it's automatic
    export detected_techs
}

# Function: techdetect
# Description: Extracts URLs matching a specific technology pattern.
# Usage: techdetect <tech_pattern>
techdetect(){
    local tech_pattern="$1"
    local all_tech_urls="$results/all_tech_urls.txt"
    # We search specifically in the generated all_tech_urls file
    # Grep with fixed string if possible, or ensure pattern is safe
    # If tech_pattern contains regex metacharacters, it might break.
    # Since we cleaned detected_techs, it should be mostly alphanum/underscore.
    # We use -F for fixed string matching on the tech pattern part effectively if we could, 
    # but we need the comma context. 
    # Let's escape special chars in pattern just in case.
    local safe_pattern=$(echo "$tech_pattern" | sed 's/[]\/$*.^[]/\\&/g')
    
    grep -i ",.*$safe_pattern" "$all_tech_urls" | cut -d ',' -f 1 | grep -oE "^https?://[^/]*(:[0-9]+)?" | sort -u
}

# Function: show_tech_summary
# Description: Logs a summary of detected technologies were found to a file.
show_tech_summary() {
    local all_tech_urls="$results/all_tech_urls.txt"
    local summary_file="$results/tech_summary.txt"
    
    if [ ! -s "$all_tech_urls" ]; then
        return
    fi
    
    # Ensure detected_techs is populated
    if [ -z "$detected_techs" ]; then
        identify_technologies
    fi

    # Log to file instead of stdout
    {
        echo "TECH DETECTION SUMMARY"
        echo "======================"
        
        for tech in $detected_techs; do
            local count=$(techdetect "$tech" | wc -l)
            
            if [ "$count" -gt 0 ]; then
                 printf "   %-20s : %s URLs\n" "$tech" "$count"
            fi
        done
        echo ""
    } > "$summary_file"
    
    ui_print_info "Tech Detection Summary Check: $summary_file"
}
