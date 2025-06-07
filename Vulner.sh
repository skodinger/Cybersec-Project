#!/bin/bash

#==============================================================================
#
#          FILE: netvuln_scanner.sh
#
#         USAGE: ./netvuln_scanner.sh
#
#   DESCRIPTION: A comprehensive network scanning and vulnerability
#                assessment tool. It maps devices, identifies services,
#                and probes for vulnerabilities like weak credentials.
#
#       OPTIONS: ---
#  REQUIREMENTS: nmap, masscan, hydra, searchsploit, zip
#          BUGS: ---
#         NOTES: Run with sudo for best results (e.g., nmap SYN scans).
#        AUTHOR: skodinger
#  ORGANIZATION:
#       CREATED: 2025-06-05
#      REVISION: 1.0
#
#==============================================================================

# --- Color Definitions ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_WHITE='\033[1;37m'

# --- Global Variables ---
OUTPUT_DIR=""
NETWORK_RANGE=""
SCAN_TYPE=""
PASSWORD_LIST=""
DEFAULT_USER_LIST="users.lst"
DEFAULT_PASS_LIST="passwords.lst"

#==============================================================================
# HELPER FUNCTIONS
#==============================================================================

# --- Print headers for different stages ---
print_header() {
    echo -e "\n${C_CYAN}=======================================================================${C_RESET}"
    echo -e "${C_WHITE}>> $1 ${C_RESET}"
    echo -e "${C_CYAN}=======================================================================${C_RESET}"
}

# --- Check if required tools are installed ---
check_dependencies() {
    print_header "Checking for required tools..."
    local missing_tools=0
    local tools=("nmap" "masscan" "hydra" "searchsploit" "zip")

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${C_RED}[ERROR] '$tool' is not installed. Please install it to continue.${C_RESET}"
            missing_tools=1
        else
            echo -e "${C_GREEN}[OK] $tool is installed.${C_RESET}"
        fi
    done

    if [[ $missing_tools -eq 1 ]]; then
        exit 1
    fi

    # Check for root privileges, as they are needed for optimal nmap performance
    if [[ $EUID -ne 0 ]]; then
       echo -e "\n${C_YELLOW}[WARNING] This script works best when run with root privileges (sudo).${C_RESET}"
       echo -e "${C_YELLOW}          Some scans (like nmap -sS) may not work as expected without it.${C_RESET}"
    fi
}

# --- Display a cool banner ---
display_banner() {
    echo -e "${C_BLUE}"
    cat << "EOF"
 _   _      _   _     _   _            _    _                 
| \ | | ___| \ | | __| | | |   _   _  / \  | | __ _  ___ _ __ 
|  \| |/ _ \  \| |/ _` | | |  | | | |/ _ \ | |/ _` |/ _ \ '__|
| |\  |  __/ |\  | (_| | | |__| |_| / ___ \| | (_| |  __/ |   
|_| \_|\___|_| \_|\__,_| |_____\__, /_/   \_\_|\__,_|\___|_|   
                               |___/                          
    Network Vulnerability & Enumeration Reconnaissance Tool
EOF
    echo -e "${C_RESET}"
}

#==============================================================================
# CORE LOGIC FUNCTIONS
#==============================================================================

# --- 1. Get User Input ---
get_user_input() {
    print_header "Configuration"

    # 1.1 Get Network Range
    while true; do
        read -p "Enter the network range to scan (e.g., 192.168.1.0/24): " NETWORK_RANGE
        # Simple CIDR validation regex
        if [[ $NETWORK_RANGE =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            break
        else
            echo -e "${C_RED}Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24).${C_RESET}"
        fi
    done

    # 1.2 Get Output Directory
    read -p "Enter a name for the output directory: " OUTPUT_DIR
    OUTPUT_DIR=${OUTPUT_DIR:-"netscan_results_$(date +%Y%m%d_%H%M%S)"}
    mkdir -p "$OUTPUT_DIR"
    cd "$OUTPUT_DIR" || exit
    echo -e "${C_GREEN}Results will be saved in '$(pwd)'${C_RESET}"


    # 1.3 Get Scan Type
    while true; do
        read -p "Choose scan type [B]asic or [F]ull: " scan_choice
        case ${scan_choice^^} in
            B|BASIC)
                SCAN_TYPE="Basic"
                break
                ;;
            F|FULL)
                SCAN_TYPE="Full"
                break
                ;;
            *)
                echo -e "${C_RED}Invalid choice. Please enter 'B' for Basic or 'F' for Full.${C_RESET}"
                ;;
        esac
    done

    # 2.1.2 Get custom password list
    read -p "Enter path to a custom password list (or press Enter to use a default list): " custom_pass_list
    if [[ -f "$custom_pass_list" ]]; then
        PASSWORD_LIST="$custom_pass_list"
        echo -e "${C_GREEN}Using custom password list: $PASSWORD_LIST${C_RESET}"
    else
        echo -e "${C_YELLOW}Custom list not found or not provided. Creating a default password list.${C_RESET}"
        PASSWORD_LIST="$DEFAULT_PASS_LIST"
        # 2.1.1 Create default password list
        cat << EOF > "$PASSWORD_LIST"
password
123456
123456789
admin
root
qwerty
1234
password123
p@ssword
EOF
        # Create default user list for brute-forcing
        cat << EOF > "$DEFAULT_USER_LIST"
root
admin
user
test
guest
administrator
ftp
ssh
telnet
EOF
    fi
}

# --- Perform Host Discovery ---
run_discovery() {
    print_header "Phase 1: Host Discovery"
    echo "Using masscan to quickly find live hosts..."
    # Using masscan for speed to find any host with common ports open
    masscan "$NETWORK_RANGE" -p21,22,23,80,443,3389 --rate=1000 -oL masscan_hosts.txt
    
    if [[ ! -s masscan_hosts.txt || $(grep -c "host" masscan_hosts.txt) -eq 0 ]]; then
        echo -e "${C_YELLOW}Masscan found no hosts. Trying nmap ping scan as a fallback...${C_RESET}"
        nmap -sn "$NETWORK_RANGE" -oG - | awk '/Up$/{print $2}' > live_hosts.txt
    else
        # Extract IPs from masscan output
        awk '/host/{print $4}' masscan_hosts.txt | sort -u > live_hosts.txt
    fi

    if [[ ! -s live_hosts.txt ]]; then
        echo -e "${C_RED}No live hosts found in the network range. Exiting.${C_RESET}"
        exit 1
    fi
    
    echo -e "${C_GREEN}Discovery complete. Found $(wc -l < live_hosts.txt) live host(s). List saved to 'live_hosts.txt'.${C_RESET}"
}

# --- Run Nmap Scans based on chosen type ---
run_nmap_scan() {
    local nmap_args
    local output_file

    if [[ "$SCAN_TYPE" == "Full" ]]; then
        print_header "Phase 2: Full Scan (Nmap NSE & Vulnerability Analysis)"
        echo "Running an in-depth Nmap scan with service enumeration and vulnerability scripts..."
        # 1.3.2 Full scan with service versions, OS detection, and NSE vuln scripts
        nmap_args="-sV -sC -A --script=vuln"
        output_file="nmap_full_scan"
    else
        print_header "Phase 2: Basic Scan (Port & Service Enumeration)"
        echo "Running a basic Nmap scan for TCP ports and service versions..."
        # 1.3.1 Basic scan for all TCP ports and service versions
        nmap_args="-sV -p-"
        output_file="nmap_basic_scan"
    fi

    echo -e "${C_YELLOW}This may take a significant amount of time depending on the network size...${C_RESET}"
    nmap -T4 -iL live_hosts.txt $nmap_args -oN "$output_file.txt" -oX "$output_file.xml" > /dev/null
    echo -e "${C_GREEN}Nmap scan complete. Results saved to '$output_file.txt' and '$output_file.xml'.${C_RESET}"
}

# --- 3. Mapping Vulnerabilities ---
map_vulnerabilities() {
    if [[ "$SCAN_TYPE" == "Full" ]]; then
        print_header "Phase 3: Vulnerability Mapping with SearchSploit"
        echo "Updating SearchSploit database..."
        searchsploit -u > /dev/null 2>&1
        echo "Cross-referencing Nmap results with known exploits..."
        searchsploit --nmap nmap_full_scan.xml > searchsploit_results.txt
        if [[ -s searchsploit_results.txt && $(wc -l < searchsploit_results.txt) -gt 4 ]]; then
             echo -e "${C_GREEN}SearchSploit found potential exploits! Results saved to 'searchsploit_results.txt'.${C_RESET}"
        else
             echo -e "${C_YELLOW}SearchSploit did not find any matching public exploits.${C_RESET}"
        fi
    else
        echo -e "${C_YELLOW}Skipping vulnerability mapping (only available in Full scan mode).${C_RESET}"
    fi
}

# --- 2. Weak Credentials Check ---
check_weak_credentials() {
    print_header "Phase 4: Weak Credential Check"
    local scan_file
    [[ -f "nmap_full_scan.txt" ]] && scan_file="nmap_full_scan.txt" || scan_file="nmap_basic_scan.txt"

    # Define services and their corresponding ports
    declare -A services=( ["ssh"]="22" ["ftp"]="21" ["telnet"]="23" ["rdp"]="3389" )
    
    echo "Scanning for open login services to test for weak passwords..."

    for service in "${!services[@]}"; do
        local port=${services[$service]}
        # Grep for hosts with the specific port open
        local targets=$(grep " ${port}/tcp " "$scan_file" | awk '{print $1}' | sort -u)

        if [[ -n "$targets" ]]; then
            echo -e "\n${C_YELLOW}Targets found for $service on port $port:${C_RESET}"
            echo "$targets"
            
            # Create a target list file for Hydra
            echo "$targets" > "${service}_targets.txt"
            
            echo "Running Hydra against $service targets..."
            # Using -t 4 for 4 parallel tasks per host
            hydra -L "$DEFAULT_USER_LIST" -P "$PASSWORD_LIST" -M "${service}_targets.txt" -t 4 "$service" -o "hydra_${service}_results.txt" > /dev/null

            if grep -q "host:" "hydra_${service}_results.txt"; then
                echo -e "${C_RED}[VULNERABLE] Weak credentials found for $service! See 'hydra_${service}_results.txt'.${C_RESET}"
            else
                echo -e "${C_GREEN}[SECURE] No weak credentials found for $service with the provided list.${C_RESET}"
            fi
        else
            echo -e "\n${C_GREEN}No open ports found for $service.${C_RESET}"
        fi
    done
}


# --- 4. Log and Present Results ---
present_results() {
    print_header "Scan Summary & Final Report"

    echo -e "${C_WHITE}--- Live Hosts ---${C_RESET}"
    cat live_hosts.txt
    
    echo -e "\n${C_WHITE}--- Open Ports & Services ---${C_RESET}"
    local scan_file
    [[ -f "nmap_full_scan.txt" ]] && scan_file="nmap_full_scan.txt" || scan_file="nmap_basic_scan.txt"
    grep "/tcp.*open" "$scan_file"
    
    echo -e "\n${C_WHITE}--- Weak Credentials Found ---${C_RESET}"
    if compgen -G "hydra_*_results.txt" > /dev/null; then
        grep "host:" hydra_*_results.txt || echo "None found."
    else
        echo "None found."
    fi

    if [[ "$SCAN_TYPE" == "Full" ]]; then
        echo -e "\n${C_WHITE}--- Potential Exploits (SearchSploit) ---${C_RESET}"
        if [[ -s searchsploit_results.txt && $(wc -l < searchsploit_results.txt) -gt 4 ]]; then
            cat searchsploit_results.txt
        else
            echo "None found."
        fi
    fi

    # 4.3 & 4.4 Final user options
    while true; do
        read -p $'\n'"Enter a term to [S]earch results, [Z]ip results, or [Q]uit: " final_choice
        case ${final_choice^^} in
            S|SEARCH)
                read -p "Enter search term: " search_term
                echo -e "${C_YELLOW}--- Searching for '$search_term' in all result files ---${C_RESET}"
                grep -rli --color=always "$search_term" .
                ;;
            Z|ZIP)
                local zip_filename="../${OUTPUT_DIR}.zip"
                echo "Compressing all results into '$zip_filename'..."
                zip -r "$zip_filename" . > /dev/null
                echo -e "${C_GREEN}Results compressed.${C_RESET}"
                ;;
            Q|QUIT)
                echo -e "${C_CYAN}Scan complete. All results are in the '$(pwd)' directory.${C_RESET}"
                exit 0
                ;;
            *)
                echo -e "${C_RED}Invalid choice.${C_RESET}"
                ;;
        esac
    done
}


#==============================================================================
# MAIN EXECUTION
#==============================================================================
main() {
    clear
    display_banner
    check_dependencies
    
    # The 'trap' command ensures that if the user exits the script (e.g., with Ctrl+C),
    # a clean exit message is shown.
    trap "echo -e '\n\n${C_RED}Script interrupted. Exiting.${C_RESET}'; exit 1" INT

    get_user_input
    
    # 4.1 Display stage in terminal (done via print_header in each function)
    run_discovery
    run_nmap_scan
    map_vulnerabilities
    check_weak_credentials
    
    present_results
}

# --- Start the script ---
main

