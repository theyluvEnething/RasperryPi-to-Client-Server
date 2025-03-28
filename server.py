import socket
import ssl
import threading
import traceback
import os
import fcntl
import logging
import argparse
import time

# Attempt to import RPi.GPIO and handle potential import errors
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    logging.warning("RPi.GPIO library not found. LED control commands will be disabled.")
except RuntimeError as e:
    GPIO_AVAILABLE = False
    logging.error(f"Error initializing RPi.GPIO (maybe not running on RPi or insufficient permissions?): {e}")
    logging.warning("LED control commands will be disabled.")


# I2C constants - Standard Linux ioctl numbers
I2C_SLAVE = 0x0703       # Use this slave address
I2C_SLAVE_FORCE = 0x0706 # Use this slave address, even if it is already in use by a driver
I2C_RDWR = 0x0707       # Combined R/W transfer (not used in this simplified handler)
I2C_M_RD = 0x0001       # Read data, from slave to master

# --- GPIO Configuration ---
LED_GPIO_PIN = 5 # Using GPIO5 as requested

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
        try:
            self.open()
        except I2CError as e:
            # Log the error during init but allow server to potentially start
            # depending on whether I2C is critical for all functions.
            logging.error(f"I2C Initialization Error: {e}")
            # Raise it again if I2C must be available for the server to be useful
            raise

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
        if self.fd is None: # Check if bus was successfully opened initially
             raise I2CError("I2C bus is not available.")
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
        if self.fd is None:
             raise I2CError("I2C bus is not available.")
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
        if self.fd is None:
             raise I2CError("I2C bus is not available.")
        with self._lock:
            self._set_address(address)
            try:
                # Write the register address we want to read from
                reg_bytes = bytes([register])
                bytes_written = os.write(self.fd, reg_bytes)
                if bytes_written != 1:
                     raise I2CError(f"Partial write for register address 0x{register:02X} on device 0x{address:02X}")

                # Read the data
                read_data = os.read(self.fd, length)
                if len(read_data) != length:
                     logging.warning(f"Short read from 0x{address:02X}, register 0x{register:02X}. Expected {length}, got {len(read_data)}")

                return read_data
            except OSError as e:
                logging.error(f"Failed read from 0x{address:02X}, register 0x{register:02X}: {e}")
                raise I2CError(f"Failed read from 0x{address:02X}, register 0x{register:02X}: {e}") from e

    def write_register(self, address, register, data):
        """Writes data to a specific register of an I2C device."""
        if self.fd is None:
            raise I2CError("I2C bus is not available.")
        with self._lock:
            self._set_address(address)
            try:
                # Data to write: register address followed by actual data bytes
                write_data = bytes([register] + list(data)) # Ensure data is list/iterable
                bytes_written = os.write(self.fd, write_data)
                if bytes_written != len(write_data):
                    raise I2CError(f"Partial write to 0x{address:02X}, register 0x{register:02X}: wrote {bytes_written}/{len(write_data)} bytes")
            except OSError as e:
                logging.error(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}")
                raise I2CError(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}") from e
            except TypeError: # Catch if data is not suitable for list() or bytes()
                 raise ValueError("Data for write_register must be an iterable of integers")


    def scan_devices(self):
        """Scans the I2C bus for available devices."""
        if self.fd is None:
            raise I2CError("I2C bus not open for scanning")

        devices = []
        # Addresses 0x00-0x02 and 0x78-0x7F are reserved.
        for addr in range(0x03, 0x78):
            with self._lock: # Need lock for set_address and read
                try:
                    fcntl.ioctl(self.fd, I2C_SLAVE, addr)
                    try:
                        # A simple read attempt after setting address
                        os.read(self.fd, 1)
                        devices.append(f"0x{addr:02x}")
                        logging.debug(f"Device 0x{addr:02x} responded to read.")
                    except OSError as read_err:
                        # errno 121 (Remote I/O error) often means ACK Address, NACK read -> device present
                        if read_err.errno == 121:
                             devices.append(f"0x{addr:02x}")
                             logging.debug(f"Device 0x{addr:02x} ACKed address but NACKed read (errno {read_err.errno}).")
                        # errno 6 (No such device or address) can sometimes happen *after* successful ioctl
                        # if the device is weird, but usually means no device. We'll treat it as absent here.
                        # errno 110 (Connection timed out) usually means absent.
                        elif read_err.errno not in [6, 110]:
                             # Log other unexpected read errors
                             logging.warning(f"Unexpected OSError during read scan at 0x{addr:02x}: {read_err}")
                        # else: # Device likely absent if read fails with common errors
                             # logging.debug(f"Read attempt failed for 0x{addr:02x} after setting address: {read_err}")

                except OSError as e:
                    # Common errors indicating absence during ioctl: ENXIO (6), ETIMEDOUT (110)
                    # EBUSY (16) means a kernel driver might be using it. Treat as present? Debatable.
                    # For scan, we'll treat EBUSY as not available *for us*, so don't list.
                     if e.errno == 16:
                         logging.warning(f"Address 0x{addr:02x} is busy (likely used by kernel driver).")
                     else:
                         logging.debug(f"No device found at 0x{addr:02x}: {e}")
                    # pass # Device not found or busy
                # time.sleep(0.01) # Optional small delay
        return devices

def handle_client(sslsock, client_address, i2c_handler):
    """Handles communication with a single TLS client."""
    client_ip, client_port = client_address
    logging.info(f"Client connected: {client_ip}:{client_port}")
    try:
        while True:
            sslsock.settimeout(300.0) # 5 minutes timeout
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
                 continue

            logging.debug(f"Received command from {client_ip}:{client_port}: {data}")
            parts = data.split()
            if not parts:
                continue

            command = parts[0].lower()
            response = "ERROR: Invalid command format"

            try:
                # --- SCAN command ---
                if command == "scan" and len(parts) == 1:
                    # Check if I2C handler is available
                    if i2c_handler.fd is None:
                        raise I2CError("I2C bus is not available for scanning.")
                    devices = i2c_handler.scan_devices()
                    response = f"OK {' '.join(devices)}"

                # --- READ REGISTER command ---
                elif command == "read" and len(parts) >= 3:
                    if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                    addr = int(parts[1], 16)
                    reg = int(parts[2], 16)
                    length = 1
                    if len(parts) > 3:
                        length = int(parts[3])
                    if length <= 0 or length > 255: raise ValueError("Length must be between 1 and 255")
                    result_bytes = i2c_handler.read_register(addr, reg, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- WRITE REGISTER command ---
                elif command == "write" and len(parts) >= 4:
                    if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                    addr = int(parts[1], 16)
                    reg = int(parts[2], 16)
                    data_to_write = [int(x, 16) for x in parts[3:]]
                    if not data_to_write: raise ValueError("No data bytes provided for write")
                    i2c_handler.write_register(addr, reg, data_to_write)
                    response = "OK"

                # --- RAW READ BYTES command ---
                elif command == "rawread" and len(parts) == 3:
                    if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                    addr = int(parts[1], 16)
                    length = int(parts[2])
                    if length <= 0 or length > 255: raise ValueError("Length must be between 1 and 255")
                    result_bytes = i2c_handler.read_bytes(addr, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- RAW WRITE BYTES command ---
                elif command == "rawwrite" and len(parts) >= 3:
                    if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                    addr = int(parts[1], 16)
                    data_to_write = [int(x, 16) for x in parts[2:]]
                    if not data_to_write: raise ValueError("No data bytes provided for raw write")
                    i2c_handler.write_bytes(addr, data_to_write)
                    response = "OK"

                # --- DUMP command ---
                elif command == "dump" and len(parts) >= 2:
                    if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                    addr = int(parts[1], 16)
                    length = 16
                    if len(parts) > 2:
                        length = int(parts[2])
                    if length <= 0 or length > 255: raise ValueError("Length must be between 1 and 255")
                    result_bytes = i2c_handler.read_bytes(addr, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- **NEW** TURN ON LED command ---
                elif command == "turnonled" and len(parts) == 1:
                    if GPIO_AVAILABLE:
                        GPIO.output(LED_GPIO_PIN, GPIO.HIGH)
                        response = "OK LED ON"
                        logging.info(f"Turned LED ON (GPIO{LED_GPIO_PIN}) for {client_ip}:{client_port}")
                    else:
                        response = "ERROR: GPIO control not available on server"
                        logging.warning(f"LED ON command failed: GPIO unavailable.")

                # --- **NEW** TURN OFF LED command ---
                elif command == "turnoffled" and len(parts) == 1:
                    if GPIO_AVAILABLE:
                        GPIO.output(LED_GPIO_PIN, GPIO.LOW)
                        response = "OK LED OFF"
                        logging.info(f"Turned LED OFF (GPIO{LED_GPIO_PIN}) for {client_ip}:{client_port}")
                    else:
                        response = "ERROR: GPIO control not available on server"
                        logging.warning(f"LED OFF command failed: GPIO unavailable.")

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
            except RuntimeError as e: # Catch potential GPIO runtime errors
                response = f"ERROR: GPIO operation failed - {e}"
                logging.error(f"GPIO Runtime Error handling command '{data}' from {client_ip}:{client_port}: {e}")
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
        if isinstance(e, ssl.SSLError) and 'timed out' in str(e).lower(): # More specific timeout check
             logging.warning(f"SSL handshake/operation timed out with {client_ip}:{client_port}: {e}")
        elif isinstance(e, ssl.SSLError) and e.reason == 'SSLV3_ALERT_CERTIFICATE_UNKNOWN':
             logging.warning(f"Client {client_ip}:{client_port} disconnected possibly due to certificate issue: {e}")
        elif isinstance(e, socket.error) and e.errno == 104: # Connection reset by peer
             logging.info(f"Client {client_ip}:{client_port} reset the connection.")
        else:
             logging.error(f"Connection error with {client_ip}:{client_port}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in client handler for {client_ip}:{client_port}: {traceback.format_exc()}")
    finally:
        logging.info(f"Closing connection for {client_ip}:{client_port}")
        try:
            sslsock.shutdown(socket.SHUT_RDWR)
        except (socket.error, OSError): pass
        finally: sslsock.close()

def setup_gpio():
    """Sets up the GPIO pin for the LED."""
    if not GPIO_AVAILABLE:
        logging.warning("Skipping GPIO setup as library is not available.")
        return False
    try:
        # Using BCM numbering to match GPIOxx labels
        GPIO.setmode(GPIO.BCM)
        # Set warnings off to suppress channel already in use warnings if script restarts
        GPIO.setwarnings(False)
        # Set up LED pin as output and default to OFF
        GPIO.setup(LED_GPIO_PIN, GPIO.OUT)
        GPIO.output(LED_GPIO_PIN, GPIO.LOW)
        logging.info(f"GPIO{LED_GPIO_PIN} set up as output (LED control). Initial state: OFF.")
        return True
    except RuntimeError as e:
        logging.error(f"Failed to set up GPIO: {e}. Check permissions (run with sudo?) or pin conflicts.")
        return False
    except Exception as e: # Catch any other unexpected errors during setup
        logging.error(f"Unexpected error during GPIO setup: {e}")
        return False


def tls_i2c_server(server_address, server_port, certfile, keyfile, bus_number=1):
    """Starts the TLS secured I2C server with GPIO control."""
    server_sock = None
    i2c_handler = None
    gpio_initialized = False

    if not os.path.exists(certfile): logging.error(f"Certificate file not found: {certfile}"); return
    if not os.path.exists(keyfile): logging.error(f"Key file not found: {keyfile}"); return

    try:
        # --- Setup I2C Handler ---
        try:
            i2c_handler = I2CHandler(bus_number)
        except I2CError as e:
            logging.warning(f"Could not initialize I2C Handler on bus {bus_number}: {e}. I2C commands will fail.")
            # Allow server to continue if only GPIO is needed, I2C commands will error out in handler.

        # --- Setup GPIO ---
        gpio_initialized = setup_gpio()
        if not gpio_initialized and GPIO_AVAILABLE:
             # Decide if GPIO failure is critical. Here, we only warn.
             logging.warning("GPIO setup failed, LED commands might not work.")

        # --- Setup SSL Context ---
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # --- Setup Server Socket ---
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((server_address, server_port))
        server_sock.listen(5)
        logging.info(f"TLS I2C/GPIO Server listening on {server_address}:{server_port} (I2C bus {bus_number}, LED GPIO{LED_GPIO_PIN})")
        logging.info(f"Using cert: {certfile}, key: {keyfile}")

        # --- Accept Connections Loop ---
        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                try:
                    sslsock = context.wrap_socket(client_sock, server_side=True)
                    client_thread = threading.Thread(
                        # Pass the initialized (or None) i2c_handler
                        target=handle_client,
                        args=(sslsock, client_addr, i2c_handler),
                        name=f"Client-{client_addr[0]}:{client_addr[1]}"
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except ssl.SSLError as e:
                    logging.error(f"SSL Handshake failed with {client_addr}: {e}")
                    client_sock.close()
                except Exception as e:
                     logging.error(f"Failed to start handler thread for {client_addr}: {e}")
                     client_sock.close()

            except KeyboardInterrupt:
                 logging.info("Shutdown signal received (KeyboardInterrupt).")
                 break
            except Exception as e:
                 logging.error(f"Error accepting connection: {e}")
                 time.sleep(0.1)

    except ssl.SSLError as e:
         logging.critical(f"SSL configuration error: {e} - Server cannot start.")
    except socket.error as e:
         logging.critical(f"Socket error during setup ({e.errno}): {e} - Server cannot start.")
         if e.errno == 98: # Address already in use
             logging.critical("Check if another instance of the server is running.")
    except Exception as e:
        logging.critical(f"Fatal server error during startup: {traceback.format_exc()}")
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
        # --- GPIO Cleanup ---
        if gpio_initialized: # Only clean up if setup was successful
            try:
                GPIO.cleanup()
                logging.info("GPIO cleaned up.")
            except Exception as e:
                logging.error(f"Error during GPIO cleanup: {e}")
        elif GPIO_AVAILABLE:
             # Log even if not initialized, just in case some setup happened partially
             logging.debug("Attempting GPIO cleanup even though initialization may have failed.")
             try: GPIO.cleanup()
             except: pass # Suppress errors here

        logging.info("Server shut down complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS-secured I2C and GPIO Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=12345, help="Port to listen on (default: 12345)")
    parser.add_argument("--cert", default="keys/server.crt", help="Path to SSL certificate file (PEM format)")
    parser.add_argument("--key", default="keys/server.key", help="Path to SSL private key file (PEM format)")
    parser.add_argument("--bus", type=int, default=1, help="I2C bus number (default: 1 for RPi)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    key_dir = os.path.dirname(args.cert) if os.path.dirname(args.cert) else '.' # Handle cert in current dir
    if not os.path.exists(key_dir):
        try:
            os.makedirs(key_dir)
            logging.info(f"Created directory: {key_dir}")
        except OSError as e:
            logging.error(f"Failed to create directory {key_dir}: {e}")

    # Check for cert/key *before* starting server, provide generation hint
    if not (os.path.exists(args.cert) and os.path.exists(args.key)):
        print(f"ERROR: Certificate ({args.cert}) and/or key ({args.key}) not found.")
        print("You may need to generate them, e.g., using openssl:")
        # Ensure key_dir is included in the path suggestion if it's not the current dir
        key_path = os.path.join(key_dir, os.path.basename(args.key))
        cert_path = os.path.join(key_dir, os.path.basename(args.cert))
        print(f"  openssl req -x509 -newkey rsa:4096 -keyout {key_path} -out {cert_path} -sha256 -days 365 -nodes -subj '/CN=MyI2CServer'")
        exit(1) # Exit if certs are missing

    # Run the server
    tls_i2c_server(args.host, args.port, args.cert, args.key, args.bus)