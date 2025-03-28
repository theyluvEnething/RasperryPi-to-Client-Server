import socket
import ssl
import threading
import traceback
import os
import fcntl
import logging
import argparse
import time
import sys

# --- GPIO Import ---
try:
    import RPi.GPIO as GPIO
except ImportError:
    # Provide a dummy GPIO class if running on non-Pi for testing imports
    # Real operation will fail later if GPIO isn't actually available.
    print("WARNING: RPi.GPIO module not found. GPIO functionality will fail.", file=sys.stderr)
    class DummyGPIO:
        BCM = None
        OUT = None
        LOW = 0
        HIGH = 1
        def setmode(self, mode): pass
        def setup(self, pin, mode, initial): pass
        def output(self, pin, state): raise RuntimeError("RPi.GPIO not available")
        def cleanup(self): pass
        def setwarnings(self, flag): pass
    GPIO = DummyGPIO()


# I2C constants - Standard Linux ioctl numbers
I2C_SLAVE = 0x0703
I2C_SLAVE_FORCE = 0x0706
I2C_RDWR = 0x0707
I2C_M_RD = 0x0001

# Setup basic logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

class I2CError(IOError):
    """Custom exception for I2C specific errors."""
    pass

class GPIOError(RuntimeError):
    """Custom exception for GPIO specific errors."""
    pass

# --- I2CHandler Class (Unchanged from previous version) ---
class I2CHandler:
    def __init__(self, bus_number=1):
        self.bus_number = bus_number
        self.device_path = f"/dev/i2c-{self.bus_number}"
        self.fd = None
        self._lock = threading.Lock() # Lock for thread safety
        self.open()

    def open(self):
        self.close()
        logging.info(f"Opening I2C bus: {self.device_path}")
        try:
            self.fd = os.open(self.device_path, os.O_RDWR | os.O_CLOEXEC)
        except OSError as e:
            logging.error(f"Could not open I2C bus {self.device_path}: {e}")
            raise I2CError(f"Could not open I2C bus {self.device_path}: {e}") from e
        except Exception as e:
             logging.error(f"Unexpected error opening I2C bus {self.device_path}: {e}")
             raise I2CError(f"Unexpected error opening I2C bus {self.device_path}: {e}") from e

    def close(self):
        with self._lock:
            if self.fd is not None:
                logging.info(f"Closing I2C bus: {self.device_path}")
                try:
                    os.close(self.fd)
                except OSError as e:
                    logging.error(f"Error closing I2C file descriptor {self.fd}: {e}")
                finally:
                     self.fd = None

    def _set_address(self, address):
        if self.fd is None:
            raise I2CError("I2C bus not open")
        try:
            fcntl.ioctl(self.fd, I2C_SLAVE, address)
        except OSError as e:
            logging.warning(f"ioctl(I2C_SLAVE, 0x{address:02X}) failed: {e}. Trying I2C_SLAVE_FORCE.")
            try:
                fcntl.ioctl(self.fd, I2C_SLAVE_FORCE, address)
            except OSError as e_force:
                logging.error(f"ioctl(I2C_SLAVE_FORCE, 0x{address:02X}) failed: {e_force}")
                raise I2CError(f"Failed to set I2C slave address to 0x{address:02X}: {e_force}") from e_force

    def read_bytes(self, address, length):
        if length <= 0: return b''
        with self._lock:
            self._set_address(address)
            try:
                return os.read(self.fd, length)
            except OSError as e:
                logging.error(f"Failed to read {length} bytes from 0x{address:02X}: {e}")
                raise I2CError(f"Failed to read from 0x{address:02X}: {e}") from e

    def write_bytes(self, address, data):
        if not data: return
        with self._lock:
            self._set_address(address)
            try:
                write_data = bytes(data)
                bytes_written = os.write(self.fd, write_data)
                if bytes_written != len(write_data):
                     raise I2CError(f"Partial write to 0x{address:02X}: wrote {bytes_written}/{len(write_data)} bytes")
            except OSError as e:
                logging.error(f"Failed to write {len(data)} bytes to 0x{address:02X}: {e}")
                raise I2CError(f"Failed to write to 0x{address:02X}: {e}") from e

    def read_register(self, address, register, length=1):
        if length <= 0: return b''
        with self._lock:
            self._set_address(address)
            try:
                reg_bytes = bytes([register])
                bytes_written = os.write(self.fd, reg_bytes)
                if bytes_written != 1:
                     raise I2CError(f"Partial write for register address 0x{register:02X} on device 0x{address:02X}")
                read_data = os.read(self.fd, length)
                if len(read_data) != length:
                     logging.warning(f"Short read from 0x{address:02X}, register 0x{register:02X}. Expected {length}, got {len(read_data)}")
                return read_data
            except OSError as e:
                logging.error(f"Failed read from 0x{address:02X}, register 0x{register:02X}: {e}")
                raise I2CError(f"Failed read from 0x{address:02X}, register 0x{register:02X}: {e}") from e

    def write_register(self, address, register, data):
        with self._lock:
            self._set_address(address)
            try:
                write_data = bytes([register] + data)
                bytes_written = os.write(self.fd, write_data)
                if bytes_written != len(write_data):
                    raise I2CError(f"Partial write to 0x{address:02X}, register 0x{register:02X}: wrote {bytes_written}/{len(write_data)} bytes")
            except OSError as e:
                logging.error(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}")
                raise I2CError(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}") from e

    def scan_devices(self):
        devices = []
        for addr in range(0x03, 0x78):
            with self._lock:
                if self.fd is None: raise I2CError("I2C bus not open for scanning")
                try:
                    fcntl.ioctl(self.fd, I2C_SLAVE, addr)
                    try:
                        os.read(self.fd, 1)
                        devices.append(f"0x{addr:02x}")
                    except OSError as read_err:
                        if read_err.errno == 121: # Remote I/O error often means ACK but read fail
                             devices.append(f"0x{addr:02x}")
                             logging.debug(f"Device 0x{addr:02x} ACKed address but NACKed read (errno {read_err.errno}).")
                        else:
                             logging.debug(f"Read attempt failed for 0x{addr:02x}: {read_err}")
                             pass
                except OSError as e:
                    logging.debug(f"No device found at 0x{addr:02x}: {e}")
                    pass
        return devices

# --- NEW: GPIOHandler Class ---
class GPIOHandler:
    def __init__(self, led_pin):
        if led_pin is None:
            logging.warning("No LED pin specified, GPIO control disabled.")
            self.led_pin = None
            self.is_setup = False
            return

        self.led_pin = led_pin
        self.is_setup = False
        # Use BCM numbering (GPIOxx number)
        GPIO.setmode(GPIO.BCM)
        # Disable warnings like "This channel is already in use"
        GPIO.setwarnings(False)
        logging.info(f"GPIO mode set to BCM. LED pin configured as {self.led_pin}")

    def setup(self):
        """Sets up the GPIO pin for output."""
        if not self.led_pin:
            return # Do nothing if no pin is configured
        try:
            # Set the pin as output and initialize it to LOW (off)
            GPIO.setup(self.led_pin, GPIO.OUT, initial=GPIO.LOW)
            self.is_setup = True
            logging.info(f"GPIO pin {self.led_pin} set up as OUTPUT, initial state LOW.")
        except Exception as e:
            # Catch potential RuntimeErrors from RPi.GPIO or others
            logging.error(f"Failed to setup GPIO pin {self.led_pin}: {e}")
            self.is_setup = False
            raise GPIOError(f"Failed to setup GPIO pin {self.led_pin}: {e}") from e

    def led_on(self):
        """Turns the LED ON (sets pin HIGH)."""
        if not self.is_setup:
            raise GPIOError("GPIO pin not set up or setup failed.")
        try:
            GPIO.output(self.led_pin, GPIO.HIGH)
            logging.debug(f"Set GPIO pin {self.led_pin} HIGH (LED ON)")
        except Exception as e:
            logging.error(f"Failed to set GPIO pin {self.led_pin} HIGH: {e}")
            raise GPIOError(f"Failed to set GPIO pin {self.led_pin} HIGH: {e}") from e

    def led_off(self):
        """Turns the LED OFF (sets pin LOW)."""
        if not self.is_setup:
            raise GPIOError("GPIO pin not set up or setup failed.")
        try:
            GPIO.output(self.led_pin, GPIO.LOW)
            logging.debug(f"Set GPIO pin {self.led_pin} LOW (LED OFF)")
        except Exception as e:
            logging.error(f"Failed to set GPIO pin {self.led_pin} LOW: {e}")
            raise GPIOError(f"Failed to set GPIO pin {self.led_pin} LOW: {e}") from e

    def cleanup(self):
        """Cleans up GPIO resources."""
        if self.is_setup:
            logging.info(f"Cleaning up GPIO pin {self.led_pin}")
            try:
                # Optional: Set LED off before cleanup
                # self.led_off()
                GPIO.cleanup(self.led_pin) # Clean up only the pin we used
                self.is_setup = False
            except Exception as e:
                 logging.error(f"Error during GPIO cleanup for pin {self.led_pin}: {e}")
        # else:
             # logging.info("GPIO cleanup skipped (pin was not setup or configured).")


# --- Modified handle_client Function ---
def handle_client(sslsock, client_address, i2c_handler, gpio_handler): # Added gpio_handler
    """Handles communication with a single TLS client."""
    client_ip, client_port = client_address
    logging.info(f"Client connected: {client_ip}:{client_port}")
    try:
        while True:
            sslsock.settimeout(300.0)
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
                    devices = i2c_handler.scan_devices()
                    response = f"OK {' '.join(devices)}"

                # --- READ REGISTER command ---
                elif command == "read" and len(parts) >= 3:
                    addr = int(parts[1], 16)
                    reg = int(parts[2], 16)
                    length = int(parts[3]) if len(parts) > 3 else 1
                    if length <= 0 or length > 255: raise ValueError("Length must be between 1 and 255")
                    result_bytes = i2c_handler.read_register(addr, reg, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- WRITE REGISTER command ---
                elif command == "write" and len(parts) >= 4:
                    addr = int(parts[1], 16)
                    reg = int(parts[2], 16)
                    data_to_write = [int(x, 16) for x in parts[3:]]
                    if not data_to_write: raise ValueError("No data bytes provided for write")
                    i2c_handler.write_register(addr, reg, data_to_write)
                    response = "OK"

                # --- RAW READ BYTES command ---
                elif command == "rawread" and len(parts) == 3:
                    addr = int(parts[1], 16)
                    length = int(parts[2])
                    if length <= 0 or length > 255: raise ValueError("Length must be between 1 and 255")
                    result_bytes = i2c_handler.read_bytes(addr, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- RAW WRITE BYTES command ---
                elif command == "rawwrite" and len(parts) >= 3:
                    addr = int(parts[1], 16)
                    data_to_write = [int(x, 16) for x in parts[2:]]
                    if not data_to_write: raise ValueError("No data bytes provided for raw write")
                    i2c_handler.write_bytes(addr, data_to_write)
                    response = "OK"

                # --- DUMP command ---
                elif command == "dump" and len(parts) >= 2:
                    addr = int(parts[1], 16)
                    length = int(parts[2]) if len(parts) > 2 else 16
                    if length <= 0 or length > 255: raise ValueError("Length must be between 1 and 255")
                    result_bytes = i2c_handler.read_bytes(addr, length)
                    response = f"OK {result_bytes.hex(' ')}"

                # --- NEW: LED Control Command ---
                elif command == "led" and len(parts) == 2:
                    if not gpio_handler or not gpio_handler.is_setup:
                         response = "ERROR: LED control not configured or setup failed on server"
                    else:
                         sub_command = parts[1].lower()
                         if sub_command == "on":
                             gpio_handler.led_on()
                             response = "OK LED turned ON"
                         elif sub_command == "off":
                             gpio_handler.led_off()
                             response = "OK LED turned OFF"
                         else:
                             response = f"ERROR: Unknown LED command '{parts[1]}'. Use 'on' or 'off'."

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
            except GPIOError as e: # Catch GPIO specific errors
                 response = f"ERROR: GPIO operation failed - {e}"
                 logging.error(f"GPIO Error handling command '{data}' from {client_ip}:{client_port}: {e}")
            except Exception as e:
                response = f"ERROR: Unexpected server error - {e}"
                logging.error(f"Unexpected error handling command '{data}' from {client_ip}:{client_port}: {traceback.format_exc()}")

            # --- Send Response ---
            try:
                logging.debug(f"Sending response to {client_ip}:{client_port}: {response}")
                sslsock.sendall(response.encode())
            except (socket.error, ssl.SSLError) as e:
                 logging.error(f"Failed to send response to {client_ip}:{client_port}: {e}")
                 break

    # --- Error Handling for Connection ---
    except (ssl.SSLError, socket.error) as e:
        if isinstance(e, ssl.SSLError) and 'CERTIFICATE_UNKNOWN' in str(e):
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

# --- Modified tls_i2c_server Function ---
def tls_i2c_server(server_address, server_port, certfile, keyfile, bus_number=1, led_pin=None): # Added led_pin
    """Starts the TLS secured I2C and GPIO server."""
    server_sock = None
    i2c_handler = None
    gpio_handler = None # Initialize GPIO handler variable

    if not os.path.exists(certfile):
        logging.error(f"Certificate file not found: {certfile}")
        return
    if not os.path.exists(keyfile):
        logging.error(f"Key file not found: {keyfile}")
        return

    try:
        # --- Setup I2C Handler ---
        i2c_handler = I2CHandler(bus_number)

        # --- Setup GPIO Handler ---
        # Do this *after* I2C handler to ensure basic server setup is possible
        # but *before* starting the server loop
        gpio_handler = GPIOHandler(led_pin)
        if led_pin is not None: # Only setup if a pin was provided
            gpio_handler.setup() # Setup the pin

        # --- Setup SSL Context ---
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # --- Setup Server Socket ---
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((server_address, server_port))
        server_sock.listen(5)
        logging.info(f"TLS I2C/GPIO Server listening on {server_address}:{server_port}")
        logging.info(f"  I2C Bus: {bus_number}")
        if gpio_handler and gpio_handler.led_pin is not None:
             logging.info(f"  GPIO LED Pin: {gpio_handler.led_pin} (BCM Mode)")
        else:
             logging.info("  GPIO LED Control: Disabled")
        logging.info(f"  Using cert: {certfile}, key: {keyfile}")


        # --- Accept Connections Loop ---
        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                try:
                    sslsock = context.wrap_socket(client_sock, server_side=True)
                    client_thread = threading.Thread(
                        target=handle_client,
                        # Pass both handlers to the client thread
                        args=(sslsock, client_addr, i2c_handler, gpio_handler),
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


    except (I2CError, GPIOError) as e: # Catch setup errors for I2C or GPIO
         logging.critical(f"Failed to initialize handlers: {e} - Server cannot start.")
    except ssl.SSLError as e:
         logging.critical(f"SSL configuration error: {e} - Server cannot start.")
    except socket.error as e:
         logging.critical(f"Socket error during setup: {e} - Server cannot start.")
    except Exception as e:
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
        if gpio_handler: # Check if gpio_handler was successfully created
            try:
                 gpio_handler.cleanup() # Cleanup GPIO resources
                 logging.info("GPIO handler cleaned up.")
            except Exception as e:
                 logging.error(f"Error cleaning up GPIO handler: {e}")
        logging.info("Server shut down complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS-secured I2C and GPIO Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=12345, help="Port to listen on (default: 12345)")
    parser.add_argument("--cert", default="keys/server.crt", help="Path to SSL certificate file (PEM format)")
    parser.add_argument("--key", default="keys/server.key", help="Path to SSL private key file (PEM format)")
    parser.add_argument("--bus", type=int, default=1, help="I2C bus number (default: 1 for RPi)")
    # --- New Argument for LED Pin ---
    parser.add_argument("--led-pin", type=int, default=17, help="BCM GPIO pin number for the LED (default: 17). Set to -1 to disable.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle disabling LED pin
    led_pin_to_use = args.led_pin if args.led_pin >= 0 else None

    key_dir = os.path.dirname(args.cert)
    # (Key generation check remains the same as before)
    if key_dir and not os.path.exists(key_dir):
        try:
            os.makedirs(key_dir)
            logging.info(f"Created directory: {key_dir}")
            if not (os.path.exists(args.cert) and os.path.exists(args.key)):
                 print(f"NOTE: Certificate ({args.cert}) and key ({args.key}) not found.")
                 print("You need to generate them, e.g., using openssl:")
                 print(f"  openssl req -x509 -newkey rsa:4096 -keyout {args.key} -out {args.cert} -sha256 -days 365 -nodes -subj '/CN=MyI2CServer'")
                 exit(1)
        except OSError as e:
            logging.error(f"Failed to create directory {key_dir}: {e}")
            # Continue, start will fail if files are missing

    # Pass the led_pin_to_use to the server function
    tls_i2c_server(args.host, args.port, args.cert, args.key, args.bus, led_pin_to_use)