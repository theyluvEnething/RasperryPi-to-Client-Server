import socket
import ssl
import sys
import traceback
import time
import struct # Needed for converting bytes to integer
import signal # Needed for graceful exit on Ctrl+C

# --- Configuration ---
# !! Important: Ensure this is the actual IP address of your Raspberry Pi !!
DEFAULT_SERVER_ADDRESS = "172.20.10.3" # Set to your Pi's IP
DEFAULT_SERVER_PORT = 12345
CONNECTION_TIMEOUT = 5.0 # Seconds to wait for connection
RECEIVE_TIMEOUT = 10.0   # Seconds to wait for response

# --- I2C Target Configuration ---
I2C_DEVICE_ADDRESS = 0x6a
Z_AXIS_REGISTER_LSB = 0x2c # Assuming LSB register for Z-axis
READ_LENGTH = 2            # Reading 2 bytes for a 16-bit value
READ_INTERVAL_SECONDS = 0.1 # How often to read (e.g., 0.1 = 10 Hz)

# --- Global flag for loop control ---
running = True

def signal_handler(sig, frame):
    """Handles Ctrl+C signal for graceful shutdown."""
    global running
    print("\nCtrl+C detected. Stopping reads and disconnecting...")
    running = False

def connect_and_read_continuously(server_address, server_port):
    """
    Connects to the TLS server and continuously reads Z-axis acceleration.
    """
    global running
    sslsock = None
    sock = None

    # Construct the command string once
    # Format: read <addr_hex> <reg_hex> <length_dec>
    command_str = f"read {I2C_DEVICE_ADDRESS:#04x} {Z_AXIS_REGISTER_LSB:#04x} {READ_LENGTH}"
    # {:#04x} formats as "0xNN"

    try:
        # 1. Create SSL Context (INSECURE - Disables Verification)
        print("Creating SSL context (WARNING: Certificate verification disabled)")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # 2. Create and Connect Socket
        print(f"Attempting to connect to {server_address}:{server_port}...")
        sock = socket.create_connection((server_address, server_port), timeout=CONNECTION_TIMEOUT)

        # 3. Wrap Socket with SSL/TLS
        sslsock = context.wrap_socket(sock, server_hostname=server_address)
        print(f"Connected successfully using {sslsock.version()}")
        sslsock.settimeout(RECEIVE_TIMEOUT) # Set timeout for subsequent operations

        # 4. Continuous Reading Loop
        print(f"Starting continuous read from Dev:{I2C_DEVICE_ADDRESS:#04x} Reg:{Z_AXIS_REGISTER_LSB:#04x}...")
        while running:
            try:
                # --- Send Read Command ---
                # print(f"Sending: {command_str}") # Uncomment for verbose debug
                sslsock.sendall(command_str.encode('utf-8'))

                # --- Receive Response ---
                response_bytes = sslsock.recv(4096)
                if not response_bytes:
                    print("Server closed connection unexpectedly.")
                    running = False # Stop the loop
                    break
                response_str = response_bytes.decode('utf-8').strip()
                # print(f"Received: {response_str}") # Uncomment for verbose debug

                # --- Parse and Process Response ---
                if response_str.startswith("OK "):
                    hex_values = response_str[3:].split() # Get space-separated hex strings
                    if len(hex_values) == READ_LENGTH:
                        try:
                            byte_list = [int(h, 16) for h in hex_values]
                            # Assuming Little-Endian ('<') signed short ('h')
                            # bytes() constructor expects an iterable of ints 0-255
                            z_accel_raw = struct.unpack('<h', bytes(byte_list))[0]
                            # --- Print the result ---
                            # Use \r for carriage return to overwrite the line
                            print(f"Z Acceleration: {z_accel_raw}    \r", end='')

                        except (ValueError, struct.error) as parse_err:
                            print(f"\nError parsing/unpacking response data '{response_str[3:]}': {parse_err}")
                        except Exception as proc_err:
                             print(f"\nError processing data: {proc_err}")
                    else:
                        print(f"\nError: Received unexpected number of bytes. Expected {READ_LENGTH}, Got {len(hex_values)}: {response_str}")
                elif response_str.startswith("ERROR"):
                    print(f"\nServer returned error: {response_str}")
                    # Decide if error is fatal or if we should retry
                    # For now, we'll keep trying after a delay
                else:
                     print(f"\nReceived unexpected response format: {response_str}")

                # --- Wait before next read ---
                if running: # Check again in case Ctrl+C was pressed during processing
                    time.sleep(READ_INTERVAL_SECONDS)

            except socket.timeout:
                print("\nERROR: Receive timed out. Retrying...")
                # Optional: Add logic to reconnect if timeout persists
                time.sleep(1) # Wait a bit before retrying
                continue # Retry sending command
            except (socket.error, ssl.SSLError) as loop_err:
                print(f"\nSOCKET/SSL ERROR during loop: {loop_err}. Disconnecting.")
                running = False # Stop the loop
                break
            except Exception as loop_exc:
                print(f"\nUnexpected error during loop: {loop_exc}")
                traceback.print_exc()
                running = False # Stop the loop on unexpected errors
                break

    # --- Handle Connection Errors ---
    except ssl.SSLCertVerificationError as e:
        print(f"SSL CERTIFICATE VERIFICATION ERROR: {e}", file=sys.stderr)
    except ssl.SSLError as e:
        print(f"SSL ERROR: {e}", file=sys.stderr)
    except socket.timeout:
        print(f"ERROR: Connection timed out ({CONNECTION_TIMEOUT}s)", file=sys.stderr)
    except socket.error as e:
        print(f"SOCKET ERROR during connection: {e}", file=sys.stderr)
        print(f" -> Is the server running at {server_address}:{server_port}?", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred during setup: {e}", file=sys.stderr)
        traceback.print_exc()

    # --- Cleanup ---
    finally:
        if sslsock:
            print("\nClosing connection...")
            try:
                sslsock.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass # Ignore errors if already closed
            finally:
                sslsock.close()
            print("Connection closed.")
        elif sock:
            sock.close() # Close underlying socket if SSL wrap failed


if __name__ == "__main__":
    # Register the signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

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

    connect_and_read_continuously(server_address, server_port)

    print("Client finished.")