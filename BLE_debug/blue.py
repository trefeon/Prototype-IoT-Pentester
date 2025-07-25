import asyncio
from bleak import BleakScanner, BleakClient, BleakError

# Optional: warna output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Dummy:
        def __getattr__(self, name): return ''
    Fore = Style = Dummy()

async def scan_devices():
    print(f"{Fore.YELLOW}[*] Scanning for BLE devices (5 seconds)...{Style.RESET_ALL}")
    def detection_callback(device, adv_data):
        print(f"{Fore.GREEN}{device.address} | RSSI: {adv_data.rssi} | Name: {device.name or 'Unknown'}{Style.RESET_ALL}")
    try:
        scanner = BleakScanner(detection_callback)
        await scanner.start()
        await asyncio.sleep(5.0)
        await scanner.stop()
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")

async def enumerate_characteristics(mac_address, retries=3, timeout=10):
    print(f"{Fore.YELLOW}[*] Scanning for {mac_address} to make sure it's reachable...{Style.RESET_ALL}")
    try:
        devices = await BleakScanner.discover(timeout=5.0)
        target = next((d for d in devices if d.address.upper() == mac_address.upper()), None)

        if not target:
            print(f"{Fore.RED}[!] Device {mac_address} not found during scan.{Style.RESET_ALL}")
            return

        for attempt in range(1, retries + 1):
            try:
                print(f"{Fore.YELLOW}[*] Attempting to connect (Attempt {attempt})...{Style.RESET_ALL}")
                async with BleakClient(mac_address, timeout=timeout) as client:
                    if not client.is_connected:
                        print(f"{Fore.RED}[!] Could not connect to {mac_address}{Style.RESET_ALL}")
                        return

                    print(f"{Fore.GREEN}[*] Connected to {mac_address}{Style.RESET_ALL}")
                    services = await client.get_services()
                    for service in services:
                        print(f"{Fore.CYAN}[+] Service: {service.uuid}{Style.RESET_ALL}")
                        for char in service.characteristics:
                            props = ', '.join(char.properties)
                            print(f"    - Char: {char.uuid} | Props: {props}")
                    return
            except asyncio.TimeoutError:
                print(f"{Fore.RED}[!] Timeout on attempt {attempt}. Retrying...{Style.RESET_ALL}")
                await asyncio.sleep(2)
            except BleakError as e:
                print(f"{Fore.RED}[!] BLE Error: {e}{Style.RESET_ALL}")
                return
            except Exception as e:
                print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
                return
        print(f"{Fore.RED}[!] Failed to connect after {retries} attempts.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")

async def write_to_characteristic(mac_address, uuid, hex_data):
    try:
        data = bytes.fromhex(hex_data)
    except ValueError:
        print(f"{Fore.RED}[!] Invalid hex data: '{hex_data}'{Style.RESET_ALL}")
        return

    try:
        async with BleakClient(mac_address) as client:
            if not client.is_connected:
                print(f"{Fore.RED}[!] Could not connect to {mac_address}{Style.RESET_ALL}")
                return

            print(f"{Fore.GREEN}[*] Connected to {mac_address}{Style.RESET_ALL}")
            await client.write_gatt_char(uuid, data)
            print(f"{Fore.GREEN}[+] Wrote data to {uuid}: {hex_data}{Style.RESET_ALL}")
    except BleakError as e:
        print(f"{Fore.RED}[!] BLE Error: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")

async def main_menu():
    while True:
        print("\n=== BLE Tool Menu ===")
        print("1. Scan BLE devices")
        print("2. Enumerate characteristics")
        print("3. Write to characteristic")
        print("4. Exit")

        choice = input("Select an option (1-4): ").strip()

        if choice == '1':
            await scan_devices()
        elif choice == '2':
            mac = input("Enter MAC address of the device: ").strip()
            await enumerate_characteristics(mac)
        elif choice == '3':
            mac = input("Enter MAC address of the device: ").strip()
            uuid = input("Enter characteristic UUID: ").strip()
            hexdata = input("Enter hex data to write (e.g., 0A0B0C): ").strip()
            await write_to_characteristic(mac, uuid, hexdata)
        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 4.")

if __name__ == "__main__":
    try:
        asyncio.run(main_menu())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Unhandled exception: {e}{Style.RESET_ALL}")
