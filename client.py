import socket
import ssl
import sys
import traceback

# --- Configuration ---
# !! Important: Replace with the actual IP address of your Raspberry Pi !!
DEFAULT_SERVER_ADDRESS = "172.20.10.3" # Replace with your Pi's IP
DEFAULT_SERVER_PORT = 12345
CONNECTION_TIMEOUT = 5.0 # Seconds to wait for connection
RECEIVE_TIMEOUT = 10.0   # Seconds to wait for response

def send_command(server_address, server_port, command_str):
    """
    Connects to the TLS server, sends a command, and returns the response.

    Args:
        server_address (str): The IP address or hostname of the server.
        server_port (int): The port number of the server.
        command_str (str): The command string to send.

    Returns:
        str: The decoded response from the server, or None if an error occurred.
    """
    sock = None
    sslsock = None
    try:
        # 1. Create SSL Context (INSECURE - Disables Verification)
        #    For production, use:
        #    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='path/to/server/ca.crt')
        #    context.check_hostname = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) # Specify TLS client protocol
        context.check_hostname = False                    # Disable hostname verification (Insecure)
        context.verify_mode = ssl.CERT_NONE               # Disable certificate verification (Insecure)

        # 2. Create and Connect Socket
        sock = socket.create_connection((server_address, server_port), timeout=CONNECTION_TIMEOUT)

        # 3. Wrap Socket with SSL/TLS
        #    server_hostname is important for SNI (Server Name Indication) even if check_hostname is False
        sslsock = context.wrap_socket(sock, server_hostname=server_address)
        print(f"Connected to {server_address}:{server_port} using {sslsock.version()}")

        # 4. Send Command
        print(f"Sending: {command_str}")
        sslsock.sendall(command_str.encode('utf-8')) # Use utf-8 explicitly

        # 5. Receive Response
        sslsock.settimeout(RECEIVE_TIMEOUT)
        response_bytes = sslsock.recv(4096)
        if not response_bytes:
            print("Server closed connection unexpectedly.")
            return None
        response_str = response_bytes.decode('utf-8') # Use utf-8 explicitly
        print(f"Received: {response_str}")
        return response_str

    except ssl.SSLCertVerificationError as e:
        print(f"SSL CERTIFICATE VERIFICATION ERROR: {e}", file=sys.stderr)
        print(" -> If using self-signed certs, ensure verify_mode=ssl.CERT_NONE (INSECURE) or", file=sys.stderr)
        print(" -> provide the correct CA certificate using context.load_verify_locations()", file=sys.stderr)
        return None
    except ssl.SSLError as e:
        print(f"SSL ERROR: {e}", file=sys.stderr)
        print(f" -> Check TLS/SSL protocol compatibility and certificate validity on server.", file=sys.stderr)
        # traceback.print_exc() # Uncomment for detailed SSL traceback
        return None
    except socket.timeout:
        print(f"ERROR: Connection or receive timed out ({CONNECTION_TIMEOUT}/{RECEIVE_TIMEOUT}s)", file=sys.stderr)
        return None
    except socket.error as e:
        print(f"SOCKET ERROR: {e}", file=sys.stderr)
        print(f" -> Is the server running at {server_address}:{server_port}?", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        traceback.print_exc()
        return None
    finally:
        # 6. Close Connection
        if sslsock:
            try:
                sslsock.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass # Ignore errors if already closed
            finally:
                sslsock.close()
            # print("Connection closed.") # Optional: uncomment for verbose closing message
        elif sock:
            sock.close() # Close underlying socket if SSL wrap failed

def print_menu():
    """Prints the command format menu."""
    print("\n--- TLS I2C Client ---")
    print("Enter command (case-insensitive) or 'exit'. Examples:")
    print("  scan")
    print("  read <addr_hex> <reg_hex> [length_dec=1]")
    print("     e.g., read 0x50 0x00 4")
    print("  write <addr_hex> <reg_hex> <byte1_hex> [byte2_hex ...]")
    print("     e.g., write 0x50 0x10 AA BB CC")
    print("  rawread <addr_hex> <length_dec>")
    print("     e.g., rawread 0x50 16")
    print("  rawwrite <addr_hex> <byte1_hex> [byte2_hex ...]")
    print("     e.g., rawwrite 0x20 DE AD")
    print("  dump <addr_hex> [length_dec=16]  (Alias for rawread)")
    print("     e.g., dump 0x50")
    print("-----------------------")

if __name__ == "__main__":
    server_address = input(f"Enter Server IP Address [{DEFAULT_SERVER_ADDRESS}]: ").strip()
    if not server_address:
        server_address = DEFAULT_SERVER_ADDRESS

    port_str = input(f"Enter Server Port [{DEFAULT_SERVER_PORT}]: ").strip()
    try:
        server_port = int(port_str) if port_str else DEFAULT_SERVER_PORT
    except ValueError:
        print(f"Invalid port '{port_str}', using default {DEFAULT_SERVER_PORT}.")
        server_port = DEFAULT_SERVER_PORT

    print("\n" + "*"*40)
    print(" WARNING: SSL certificate verification is DISABLED.")
    print("          Connection is encrypted but not authenticated.")
    print("          DO NOT use in production without proper cert validation.")
    print("*"*40 + "\n")

    while True:
        print_menu()
        try:
            command = input("Enter command> ").strip()
        except EOFError: # Handle Ctrl+D
             print("\nExiting.")
             break

        if not command:
            continue

        if command.lower() == "exit":
            print("Exiting.")
            break

        # Send the raw command entered by the user
        send_command(server_address, server_port, command)
        # The send_command function now prints the response directly