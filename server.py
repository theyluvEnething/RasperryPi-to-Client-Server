import socket
import ssl
import threading
import traceback
import os
import fcntl
import logging
import argparse
import time # Added for potential delays if needed, and scanning robustness

# I2C constants - Standard Linux ioctl numbers
I2C_SLAVE = 0x0703       # Use this slave address
I2C_SLAVE_FORCE = 0x0706 # Use this slave address, even if it is already in use by a driver
I2C_RDWR = 0x0707       # Combined R/W transfer (not used in this simplified handler)
I2C_M_RD = 0x0001       # Read data, from slave to master

# Setup basic logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

class I2CError(IOError):
    """Custom exception for I2C specific errors."""
    pass

class I2CHandler:
    def __init__(self, bus_number=1):
        self.bus_number = bus_number
        self.device_path = f"/dev/i2c-{self.bus_number}"
        self.fd = None
        self._lock = threading.Lock() # Lock for thread safety
        self.open()

    def open(self):
        # Ensure close is called before reopening if fd exists
        self.close()
        logging.info(f"Opening I2C bus: {self.device_path}")
        try:
            # Using os.O_RDWR | os.O_CLOEXEC to prevent fd leakage on exec
            self.fd = os.open(self.device_path, os.O_RDWR | os.O_CLOEXEC)
        except OSError as e:
            logging.error(f"Could not open I2C bus {self.device_path}: {e}")
            raise I2CError(f"Could not open I2C bus {self.device_path}: {e}") from e
        except Exception as e: # Catch any other potential non-OS errors
             logging.error(f"Unexpected error opening I2C bus {self.device_path}: {e}")
             raise I2CError(f"Unexpected error opening I2C bus {self.device_path}: {e}") from e


    def close(self):
        # Acquire lock before closing to prevent race condition with ongoing operation
        with self._lock:
            if self.fd is not None:
                logging.info(f"Closing I2C bus: {self.device_path}")
                try:
                    os.close(self.fd)
                except OSError as e:
                    # Log error but don't prevent further cleanup
                    logging.error(f"Error closing I2C file descriptor {self.fd}: {e}")
                finally:
                     self.fd = None # Ensure fd is marked as closed

    def _set_address(self, address):
        """Internal method to set slave address. MUST be called with lock held."""
        if self.fd is None:
            raise I2CError("I2C bus not open")
        try:
            fcntl.ioctl(self.fd, I2C_SLAVE, address)
        except OSError as e:
            # Try forcing the address if the initial attempt fails (e.g., device busy)
            logging.warning(f"ioctl(I2C_SLAVE, 0x{address:02X}) failed: {e}. Trying I2C_SLAVE_FORCE.")
            try:
                fcntl.ioctl(self.fd, I2C_SLAVE_FORCE, address)
            except OSError as e_force:
                logging.error(f"ioctl(I2C_SLAVE_FORCE, 0x{address:02X}) failed: {e_force}")
                raise I2CError(f"Failed to set I2C slave address to 0x{address:02X}: {e_force}") from e_force

    def read_bytes(self, address, length):
        """Reads a sequence of bytes directly from the specified device address."""
        if length <= 0:
            return b''
        with self._lock:
            self._set_address(address)
            try:
                read_data = os.read(self.fd, length)
                return read_data
            except OSError as e:
                logging.error(f"Failed to read {length} bytes from 0x{address:02X}: {e}")
                raise I2CError(f"Failed to read from 0x{address:02X}: {e}") from e

    def write_bytes(self, address, data):
        """Writes a sequence of bytes directly to the specified device address."""
        if not data:
            return
        with self._lock:
            self._set_address(address)
            try:
                # Ensure data is bytes
                write_data = bytes(data)
                bytes_written = os.write(self.fd, write_data)
                if bytes_written != len(write_data):
                     # This shouldn't typically happen with I2C writes unless interrupted
                     raise I2CError(f"Partial write to 0x{address:02X}: wrote {bytes_written}/{len(write_data)} bytes")
            except OSError as e:
                logging.error(f"Failed to write {len(data)} bytes to 0x{address:02X}: {e}")
                raise I2CError(f"Failed to write to 0x{address:02X}: {e}") from e

    def read_register(self, address, register, length=1):
        """Reads data from a specific register of an I2C device."""
        if length <= 0:
            return b''
        with self._lock:
            self._set_address(address)
            try:
                # Write the register address we want to read from
                reg_bytes = bytes([register])
                bytes_written = os.write(self.fd, reg_bytes)
                if bytes_written != 1:
                     raise I2CError(f"Partial write for register address 0x{register:02X} on device 0x{address:02X}")

                # Some devices might need a small delay between write and read
                # time.sleep(0.001) # Uncomment if needed

                # Read the data
                read_data = os.read(self.fd, length)
                if len(read_data) != length:
                     # This might indicate a problem on the bus or device not responding as expected
                     logging.warning(f"Short read from 0x{address:02X}, register 0x{register:02X}. Expected {length}, got {len(read_data)}")
                     # Decide if short read is an error or just return what was read
                     # For now, return what we got, but log warning.
                     # If strict length is required, raise I2CError here.

                return read_data
            except OSError as e:
                logging.error(f"Failed read from 0x{address:02X}, register 0x{register:02X}: {e}")
                raise I2CError(f"Failed read from 0x{address:02X}, register 0x{register:02X}: {e}") from e

    def write_register(self, address, register, data):
        """Writes data to a specific register of an I2C device."""
        with self._lock:
            self._set_address(address)
            try:
                # Data to write: register address followed by actual data bytes
                write_data = bytes([register] + data)
                bytes_written = os.write(self.fd, write_data)
                if bytes_written != len(write_data):
                    raise I2CError(f"Partial write to 0x{address:02X}, register 0x{register:02X}: wrote {bytes_written}/{len(write_data)} bytes")
            except OSError as e:
                logging.error(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}")
                raise I2CError(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}") from e

    def scan_devices(self):
        """Scans the I2C bus for available devices."""
        devices = []
        # Addresses 0x00-0x02 and 0x78-0x7F are reserved.
        for addr in range(0x03, 0x78):
            with self._lock: # Need lock for set_address and read
                if self.fd is None:
                     raise I2CError("I2C bus not open for scanning")
                try:
                    # Try setting the address. If it fails, device not present or busy.
                    fcntl.ioctl(self.fd, I2C_SLAVE, addr)

                    # Try reading one byte. Some devices require a write first,
                    # others might NACK a read if they don't have data ready.
                    # A successful read or even a specific OSError (like Remote I/O error
                    # after setting address) often indicates presence. A timeout or
                    # ENXIO (No such device or address) usually indicates absence.
                    # We'll attempt a minimal read. If ioctl succeeds, we assume presence.
                    # A more robust scan might try writing 0x00 then reading.
                    try:
                        # A simple read attempt after setting address
                        os.read(self.fd, 1)
                        devices.append(f"0x{addr:02x}")
                    except OSError as read_err:
                        # A "Remote I/O error" (errno 121) often means the device ACKed the address
                        # but failed the read command. This still indicates presence.
                        # Other errors might not. Be slightly more lenient here.
                        if read_err.errno == 121:
                             devices.append(f"0x{addr:02x}")
                             logging.debug(f"Device 0x{addr:02x} ACKed address but NACKed read (errno {read_err.errno}).")
                        else:
                             logging.debug(f"Read attempt failed for 0x{addr:02x} after setting address: {read_err}")
                             # Don't add if read fails significantly, re-evaluate if needed
                             pass

                except OSError as e:
                    # Common errors indicating absence: ENXIO (6), ETIMEDOUT (110)
                    # EBUSY (16) means a kernel driver might be using it.
                    logging.debug(f"No device found at 0x{addr:02x}: {e}")
                    pass # Device not found at this address
                # A small delay might prevent overwhelming the bus during scan
                # time.sleep(0.01)
        return devices

def handle_client(sslsock, client_address, i2c_handler):
    """Handles communication with a single TLS client."""
    client_ip, client_port = client_address
    logging.info(f"Client connected: {client_ip}:{client_port}")
    try:
        while True:
            # Set a timeout for recv to prevent hanging indefinitely if client stalls
            sslsock.settimeout(300.0) # 5 minutes, adjust as needed
            try:
                data_raw = sslsock.recv(4096)
                if not data_raw:
                    logging.info(f"Client {client_ip}:{client_port} disconnected gracefully.")
                    break
                data = data_raw.decode().strip()
            except socket.timeout:
                 logging.warning(f"Client {client_ip}:{client_port} timed out.")
                 break
            except UnicodeDecodeError:
                 logging.warning(f"Client {client_ip}:{client_port} sent non-UTF8 data.")
                 sslsock.sendall(b"ERROR: Invalid encoding. Use UTF-8.")
                 continue # Or break, depending on desired behavior


            logging.debug(f"Received command from {client_ip}:{client_port}: {data}")
            parts = data.split()
            if not parts:
                continue # Ignore empty lines

            command = parts[0].lower()
            response = "ERROR: Invalid command format" # Default error

            try:
                # --- SCAN command ---
                if command == "scan" and len(parts) == 1:
                    devices = i2c_handler.scan_devices()
                    response = f"OK {' '.join(devices)}"

                # --- READ REGISTER command ---
                # read <addr_hex> <reg_hex> [length_dec]
                elif command == "read" and len(parts) >= 3:
                    addr = int(parts[1], 16)
                    reg = int(parts[2], 16)
                    length = 1
                    if len(parts) > 3:
                        length = int(parts[3]) # decimal length
                    if length <= 0 or length > 255: # Practical limit for many I2C reads
                         raise ValueError("Length must be between 1 and 255")

                    result_bytes = i2c_handler.read_register(addr, reg, length)
                    # Format bytes as space-separated hex string
                    response = f"OK {result_bytes.hex(' ')}"

                # --- WRITE REGISTER command ---
                # write <addr_hex> <reg_hex> <byte1_hex> [byte2_hex ...]
                elif command == "write" and len(parts) >= 4:
                    addr = int(parts[1], 16)
                    reg = int(parts[2], 16)
                    # Parse data bytes from hex strings
                    data_to_write = [int(x, 16) for x in parts[3:]]
                    if not data_to_write:
                         raise ValueError("No data bytes provided for write")

                    i2c_handler.write_register(addr, reg, data_to_write)
                    response = "OK"

                # --- RAW READ BYTES command ---
                # rawread <addr_hex> <length_dec>
                elif command == "rawread" and len(parts) == 3:
                    addr = int(parts[1], 16)
                    length = int(parts[2]) # decimal length
                    if length <= 0 or length > 255:
                         raise ValueError("Length must be between 1 and 255")

                    result_bytes = i2c_handler.read_bytes(addr, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- RAW WRITE BYTES command ---
                # rawwrite <addr_hex> <byte1_hex> [byte2_hex ...]
                elif command == "rawwrite" and len(parts) >= 3:
                    addr = int(parts[1], 16)
                    data_to_write = [int(x, 16) for x in parts[2:]]
                    if not data_to_write:
                         raise ValueError("No data bytes provided for raw write")

                    i2c_handler.write_bytes(addr, data_to_write)
                    response = "OK"

                # --- DUMP command (kept for compatibility, acts like rawread) ---
                # dump <addr_hex> [length_dec] - Reads fixed 16 bytes if length omitted
                elif command == "dump" and len(parts) >= 2:
                    addr = int(parts[1], 16)
                    length = 16 # Default dump length
                    if len(parts) > 2:
                        length = int(parts[2])
                    if length <= 0 or length > 255:
                         raise ValueError("Length must be between 1 and 255")
                    # Use raw read for dump
                    result_bytes = i2c_handler.read_bytes(addr, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- UNKNOWN command ---
                else:
                    response = f"ERROR: Unknown command or incorrect parameters: '{data}'"

            # --- Error Handling for Command Execution ---
            except (ValueError, IndexError) as e:
                response = f"ERROR: Invalid parameters - {e}"
                logging.warning(f"Invalid parameters from {client_ip}:{client_port} for command '{data}': {e}")
            except I2CError as e:
                response = f"ERROR: I2C operation failed - {e}"
                logging.error(f"I2C Error handling command '{data}' from {client_ip}:{client_port}: {e}")
            except Exception as e:
                response = f"ERROR: Unexpected server error - {e}"
                logging.error(f"Unexpected error handling command '{data}' from {client_ip}:{client_port}: {traceback.format_exc()}")

            # --- Send Response ---
            try:
                logging.debug(f"Sending response to {client_ip}:{client_port}: {response}")
                sslsock.sendall(response.encode())
            except (socket.error, ssl.SSLError) as e:
                 logging.error(f"Failed to send response to {client_ip}:{client_port}: {e}")
                 break # Assume client connection is broken

    # --- Error Handling for Connection ---
    except (ssl.SSLError, socket.error) as e:
        # Log specific SSL/socket errors that might occur during recv/send loop
        if isinstance(e, ssl.SSLError) and e.reason == 'SSLV3_ALERT_CERTIFICATE_UNKNOWN':
             logging.warning(f"Client {client_ip}:{client_port} disconnected possibly due to certificate issue: {e}")
        elif isinstance(e, socket.error) and e.errno == 104: # Connection reset by peer
             logging.info(f"Client {client_ip}:{client_port} reset the connection.")
        else:
             logging.error(f"Connection error with {client_ip}:{client_port}: {e}")
    except Exception as e:
        # Catch any unexpected errors in the handler function itself
        logging.error(f"Unexpected error in client handler for {client_ip}:{client_port}: {traceback.format_exc()}")
    finally:
        logging.info(f"Closing connection for {client_ip}:{client_port}")
        try:
            sslsock.shutdown(socket.SHUT_RDWR) # Attempt graceful shutdown
        except (socket.error, OSError):
            pass # Ignore errors if socket already closed or invalid
        finally:
             sslsock.close()

def tls_i2c_server(server_address, server_port, certfile, keyfile, bus_number=1):
    """Starts the TLS secured I2C server."""
    server_sock = None
    i2c_handler = None

    # --- Validate Cert/Key Files ---
    if not os.path.exists(certfile):
        logging.error(f"Certificate file not found: {certfile}")
        return
    if not os.path.exists(keyfile):
        logging.error(f"Key file not found: {keyfile}")
        return

    try:
        # --- Setup I2C Handler ---
        # Do this first to fail early if I2C isn't available
        i2c_handler = I2CHandler(bus_number)

        # --- Setup SSL Context ---
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # Use modern TLS
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        # Optional: Add client certificate verification if needed
        # context.verify_mode = ssl.CERT_REQUIRED
        # context.load_verify_locations(cafile='path/to/client/ca.crt')

        # --- Setup Server Socket ---
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow address reuse immediately after server restart
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((server_address, server_port))
        server_sock.listen(5) # Listen for up to 5 queued connections
        logging.info(f"TLS I2C Server listening on {server_address}:{server_port} for I2C bus {bus_number}")
        logging.info(f"Using cert: {certfile}, key: {keyfile}")

        # --- Accept Connections Loop ---
        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                # Wrap socket immediately in try block to handle SSL handshake errors
                try:
                    sslsock = context.wrap_socket(client_sock, server_side=True)
                    # Create and start thread for the connected client
                    client_thread = threading.Thread(
                        target=handle_client,
                        args=(sslsock, client_addr, i2c_handler),
                        name=f"Client-{client_addr[0]}:{client_addr[1]}"
                    )
                    client_thread.daemon = True # Allows main thread to exit even if clients are connected
                    client_thread.start()
                except ssl.SSLError as e:
                    logging.error(f"SSL Handshake failed with {client_addr}: {e}")
                    client_sock.close() # Close the underlying socket
                except Exception as e:
                     logging.error(f"Failed to start handler thread for {client_addr}: {e}")
                     client_sock.close()

            except KeyboardInterrupt:
                 logging.info("Shutdown signal received (KeyboardInterrupt).")
                 break # Exit the accept loop
            except Exception as e:
                 # Catch errors during accept() itself
                 logging.error(f"Error accepting connection: {e}")
                 # Optional: Add a small delay before retrying accept
                 time.sleep(0.1)


    except I2CError as e:
         # Handle errors during I2CHandler initialization
         logging.critical(f"Failed to initialize I2C Handler: {e} - Server cannot start.")
    except ssl.SSLError as e:
         logging.critical(f"SSL configuration error: {e} - Server cannot start.")
    except socket.error as e:
         logging.critical(f"Socket error during setup: {e} - Server cannot start.")
    except Exception as e:
        # Catch-all for any other unexpected server errors during setup or runtime
        logging.critical(f"Fatal server error: {traceback.format_exc()}")
    finally:
        # --- Cleanup ---
        logging.info("Shutting down server...")
        if server_sock:
            try:
                 server_sock.close()
                 logging.info("Server socket closed.")
            except Exception as e:
                 logging.error(f"Error closing server socket: {e}")
        if i2c_handler:
            try:
                 i2c_handler.close()
                 logging.info("I2C handler closed.")
            except Exception as e:
                 logging.error(f"Error closing I2C handler: {e}")
        logging.info("Server shut down complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS-secured I2C Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=12345, help="Port to listen on (default: 12345)")
    parser.add_argument("--cert", default="keys/server.crt", help="Path to SSL certificate file (PEM format)")
    parser.add_argument("--key", default="keys/server.key", help="Path to SSL private key file (PEM format)")
    parser.add_argument("--bus", type=int, default=1, help="I2C bus number (default: 1 for RPi)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create keys directory if it doesn't exist (useful for first run)
    key_dir = os.path.dirname(args.cert)
    if key_dir and not os.path.exists(key_dir):
        try:
            os.makedirs(key_dir)
            logging.info(f"Created directory: {key_dir}")
            print(f"NOTE: Certificate ({args.cert}) and key ({args.key}) not found.")
            print("You need to generate them, e.g., using openssl:")
            print(f"  openssl req -x509 -newkey rsa:4096 -keyout {args.key} -out {args.cert} -sha256 -days 365 -nodes -subj '/CN=MyI2CServer'")
            # Exit if certs are missing after creating dir
            if not (os.path.exists(args.cert) and os.path.exists(args.key)):
                 exit(1)
        except OSError as e:
            logging.error(f"Failed to create directory {key_dir}: {e}")
            # Attempt to continue, server start will fail if files are truly missing

    tls_i2c_server(args.host, args.port, args.cert, args.key, args.bus)