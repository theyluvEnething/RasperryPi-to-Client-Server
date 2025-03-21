import socket
import ssl

def send_command(server_address, server_port, command_str):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sslsock = context.wrap_socket(sock, server_hostname=server_address)
        sslsock.connect((server_address, server_port))

        print(f"Sending command: {command_str}")
        sslsock.sendall(command_str.encode())

        response = sslsock.recv(4096)
        print(f"Received response: {response.decode()}")

        sslsock.close()
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def print_menu():
    print("Please choose a command:")
    print("[1] Dump I2C: example command -> dump 0x50")
    print("[2] Read Register: example command -> read 0x50 0x00 4")
    print("[3] Write Register: example command -> write 0x50 0x00 0xAA 0xBB")
    print("[4] Scan I2C devices: example command -> scan")
    print("[5] LED On: example command -> led on")
    print("[6] LED Off: example command -> led off")
    print("[0] Exit")

if __name__ == "__main__":
    server_address = "127.0.0.1"
    server_port = 12345

    while True:
        print_menu()
        choice = input("Enter your choice: ").strip()
        if choice == "0":
            print("Exiting.")
            break
        elif choice == "1":
            # Dump I2C command example:
            command = "dump 0x50"
        elif choice == "2":
            # Read register example:
            command = "read 0x50 0x00 4"
        elif choice == "3":
            # Write register example:
            command = "write 0x50 0x00 0xAA 0xBB"
        elif choice == "4":
            # Scan I2C devices:
            command = "scan"
        elif choice == "5":
            # LED On command:
            command = "led on"
        elif choice == "6":
            # LED Off command:
            command = "led off"
        else:
            print("Invalid choice. Please try again.\n")
            continue

        send_command(server_address, server_port, command)
        print()  # Print a newline for better separation between commands
