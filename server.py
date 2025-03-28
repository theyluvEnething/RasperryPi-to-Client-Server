import socket
import ssl
import threading
import traceback
import os
import fcntl
import logging
import argparse
import time
import struct # Useful for byte conversion, though int.from_bytes is also good

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

# --- LSM9DS1 Gyro Constants ---
LSM9DS1_AG_ADDR = 0x6A  # Default Accel/Gyro I2C address
LSM9DS1_MAG_ADDR = 0x1C # Default Magnetometer I2C address (not used in this cmd)

LSM9DS1_WHO_AM_I_AG = 0x0F # Should return 0x68
LSM9DS1_CTRL_REG1_G = 0x10 # Gyroscope control register 1
LSM9DS1_CTRL_REG6_XL = 0x20 # Accelerometer control register 6
LSM9DS1_OUT_X_L_G = 0x18   # Gyroscope output registers (X LSB)
# LSM9DS1_OUT_X_H_G = 0x19
# LSM9DS1_OUT_Y_L_G = 0x1A
# LSM9DS1_OUT_Y_H_G = 0x1B
# LSM9DS1_OUT_Z_L_G = 0x1C
# LSM9DS1_OUT_Z_H_G = 0x1D

# Gyro configuration value based on i2cset 0x6a 0x10 0xa0
# 0xA0 = 1010 0000
# ODR = 101 -> 952 Hz
# FS = 00 -> 245 dps
# BW = 00 (ignored based on datasheet logic when ODR high)
GYRO_CONFIG_CTRL1 = 0xA0
# Sensitivity for 245 dps scale (from datasheet)
GYRO_SENSITIVITY_245DPS = 0.00875 # dps per LSB

# Accel config based on i2cset 0x6a 0x20 0xa0 (used for setup consistency)
# 0xA0 = 1010 0000
# ODR = 101 -> 952 Hz
# FS = 00 -> +/- 2g
# BW_XL = 00 -> ODR based filtering
ACCEL_CONFIG_CTRL6 = 0xA0

# --- Setup basic logging ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

class I2CError(IOError):
    """Custom exception for I2C specific errors."""
    pass

# --- I2CHandler Class (No changes needed from previous version) ---
class I2CHandler:
    def __init__(self, bus_number=1):
        self.bus_number = bus_number
        self.device_path = f"/dev/i2c-{self.bus_number}"
        self.fd = None
        self._lock = threading.Lock() # Lock for thread safety
        try:
            self.open()
        except I2CError as e:
            logging.error(f"I2C Initialization Error: {e}")
            raise

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
        if self.fd is None: raise I2CError("I2C bus not open")
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
        if self.fd is None: raise I2CError("I2C bus is not available.")
        with self._lock:
            self._set_address(address)
            try:
                return os.read(self.fd, length)
            except OSError as e:
                logging.error(f"Failed to read {length} bytes from 0x{address:02X}: {e}")
                raise I2CError(f"Failed to read from 0x{address:02X}: {e}") from e

    def write_bytes(self, address, data):
        if not data: return
        if self.fd is None: raise I2CError("I2C bus is not available.")
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
        if self.fd is None: raise I2CError("I2C bus is not available.")
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
        if self.fd is None: raise I2CError("I2C bus is not available.")
        with self._lock:
            self._set_address(address)
            try:
                write_data = bytes([register] + list(data))
                bytes_written = os.write(self.fd, write_data)
                if bytes_written != len(write_data):
                    raise I2CError(f"Partial write to 0x{address:02X}, register 0x{register:02X}: wrote {bytes_written}/{len(write_data)} bytes")
            except OSError as e:
                logging.error(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}")
                raise I2CError(f"Failed write to 0x{address:02X}, register 0x{register:02X}: {e}") from e
            except TypeError:
                 raise ValueError("Data for write_register must be an iterable of integers")

    def scan_devices(self):
        # --- scan_devices method remains the same ---
        if self.fd is None:
            raise I2CError("I2C bus not open for scanning")
        devices = []
        for addr in range(0x03, 0x78):
            with self._lock:
                try:
                    fcntl.ioctl(self.fd, I2C_SLAVE, addr)
                    try:
                        os.read(self.fd, 1)
                        devices.append(f"0x{addr:02x}")
                        logging.debug(f"Device 0x{addr:02x} responded to read.")
                    except OSError as read_err:
                        if read_err.errno == 121:
                             devices.append(f"0x{addr:02x}")
                             logging.debug(f"Device 0x{addr:02x} ACKed address but NACKed read (errno {read_err.errno}).")
                        elif read_err.errno not in [6, 110]:
                             logging.warning(f"Unexpected OSError during read scan at 0x{addr:02x}: {read_err}")
                except OSError as e:
                     if e.errno == 16:
                         logging.warning(f"Address 0x{addr:02x} is busy (likely used by kernel driver).")
                     else:
                         logging.debug(f"No device found at 0x{addr:02x}: {e}")
        return devices


# --- Helper function for Gyro data conversion ---
def raw_gyro_to_dps(raw_val):
    """Converts raw 16-bit signed gyro value to degrees per second (dps)
       Assumes 245 dps full-scale setting.
    """
    # Ensure it's treated as signed 16-bit
    if raw_val >= 32768: # 2^15
        raw_val -= 65536 # 2^16
    return raw_val * GYRO_SENSITIVITY_245DPS

def handle_client(sslsock, client_address, i2c_handler):
    """Handles communication with a single TLS client."""
    client_ip, client_port = client_address
    logging.info(f"Client connected: {client_ip}:{client_port}")
    is_streaming_gyro = False # Flag to manage gyro stream state for this client
    default_sock_timeout = 300.0 # Store original timeout

    try:
        # Set initial timeout
        sslsock.settimeout(default_sock_timeout)

        while True:
            # --- Receive Command (only if not streaming gyro) ---
            # If streaming, we handle receive inside the stream loop check
            if not is_streaming_gyro:
                try:
                    data_raw = sslsock.recv(4096)
                    if not data_raw:
                        logging.info(f"Client {client_ip}:{client_port} disconnected gracefully.")
                        break
                    data = data_raw.decode().strip()
                except socket.timeout:
                    logging.warning(f"Client {client_ip}:{client_port} timed out waiting for command.")
                    break
                except UnicodeDecodeError:
                    logging.warning(f"Client {client_ip}:{client_port} sent non-UTF8 data.")
                    sslsock.sendall(b"ERROR: Invalid encoding. Use UTF-8.")
                    continue
                except (socket.error, ssl.SSLError) as e:
                    logging.error(f"Socket error receiving command from {client_ip}:{client_port}: {e}")
                    break # Assume connection broken

                logging.debug(f"Received command from {client_ip}:{client_port}: {data}")
                parts = data.split()
                if not parts:
                    continue

                command = parts[0].lower()
                response = "ERROR: Invalid command format" # Default response for this cycle if needed

            # --- Command Processing ---
            # Only process commands if not currently handling the gyro stream continuation
            # (The gyro stream itself is handled within its own loop logic below)
            if not is_streaming_gyro:
                try:
                    # --- SCAN command ---
                    if command == "scan" and len(parts) == 1:
                        if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                        devices = i2c_handler.scan_devices()
                        response = f"OK {' '.join(devices)}"

                    # --- READ REGISTER command ---
                    elif command == "read" and len(parts) >= 3:
                        if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                        addr = int(parts[1], 16)
                        reg = int(parts[2], 16)
                        length = 1
                        if len(parts) > 3: length = int(parts[3])
                        if length <= 0 or length > 255: raise ValueError("Length must be 1-255")
                        result_bytes = i2c_handler.read_register(addr, reg, length)
                        response = f"OK {result_bytes.hex(' ')}"

                    # --- WRITE REGISTER command ---
                    elif command == "write" and len(parts) >= 4:
                        if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                        addr = int(parts[1], 16)
                        reg = int(parts[2], 16)
                        data_to_write = [int(x, 16) for x in parts[3:]]
                        if not data_to_write: raise ValueError("No data bytes provided")
                        i2c_handler.write_register(addr, reg, data_to_write)
                        response = "OK"

                    # --- RAW READ/WRITE/DUMP commands (Simplified for brevity) ---
                    elif command == "rawread" and len(parts) == 3:
                        if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                        addr = int(parts[1], 16); length = int(parts[2])
                        if length <= 0 or length > 255: raise ValueError("Length must be 1-255")
                        result_bytes = i2c_handler.read_bytes(addr, length)
                        response = f"OK {result_bytes.hex(' ')}"
                    elif command == "rawwrite" and len(parts) >= 3:
                        if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                        addr = int(parts[1], 16); data_to_write = [int(x, 16) for x in parts[2:]]
                        if not data_to_write: raise ValueError("No data bytes provided")
                        i2c_handler.write_bytes(addr, data_to_write)
                        response = "OK"
                    elif command == "dump" and len(parts) >= 2:
                        if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")
                        addr = int(parts[1], 16); length = 16
                        if len(parts) > 2: length = int(parts[2])
                        if length <= 0 or length > 255: raise ValueError("Length must be 1-255")
                        result_bytes = i2c_handler.read_bytes(addr, length)
                        response = f"OK {result_bytes.hex(' ')}"

                    # --- LED commands ---
                    elif command == "turnonled" and len(parts) == 1:
                        if GPIO_AVAILABLE: GPIO.output(LED_GPIO_PIN, GPIO.HIGH); response = "OK LED ON"
                        else: response = "ERROR: GPIO control not available"
                    elif command == "turnoffled" and len(parts) == 1:
                        if GPIO_AVAILABLE: GPIO.output(LED_GPIO_PIN, GPIO.LOW); response = "OK LED OFF"
                        else: response = "ERROR: GPIO control not available"

                    # --- **NEW** READGYRO command ---
                    elif command == "readgyro":
                        if i2c_handler.fd is None: raise I2CError("I2C bus is not available.")

                        gyro_addr = LSM9DS1_AG_ADDR # Default address
                        if len(parts) > 1:
                            try: gyro_addr = int(parts[1], 16)
                            except ValueError: raise ValueError("Invalid I2C address format")

                        logging.info(f"Starting gyro stream from 0x{gyro_addr:02X} for {client_ip}:{client_port}")

                        # --- Configure LSM9DS1 Gyro ---
                        try:
                            # Optional: Verify WHO_AM_I
                            # who_am_i = i2c_handler.read_register(gyro_addr, LSM9DS1_WHO_AM_I_AG, 1)
                            # if who_am_i != bytes([0x68]):
                            #    raise I2CError(f"WHO_AM_I check failed for 0x{gyro_addr:02X}. Expected 0x68, got {who_am_i.hex()}")

                            # Set Gyro ODR/Scale (952Hz, 245dps)
                            i2c_handler.write_register(gyro_addr, LSM9DS1_CTRL_REG1_G, [GYRO_CONFIG_CTRL1])
                            # Set Accel ODR/Scale (952Hz, +/-2g) - Good practice even if only reading gyro
                            i2c_handler.write_register(gyro_addr, LSM9DS1_CTRL_REG6_XL, [ACCEL_CONFIG_CTRL6])
                            time.sleep(0.01) # Short delay after config change

                            sslsock.sendall(b"OK Starting gyro stream. Send 'stop' to end.\n")
                            is_streaming_gyro = True # Enter streaming mode for this client

                        except (I2CError, ValueError) as config_e:
                            response = f"ERROR: Failed to configure gyro - {config_e}"
                            sslsock.sendall(response.encode()) # Send config error
                            continue # Go back to wait for next command

                        # --- Gyro Streaming Loop ---
                        while is_streaming_gyro:
                            try:
                                # Read 6 bytes (X, Y, Z, 16-bit each, little-endian)
                                raw_data = i2c_handler.read_register(gyro_addr, LSM9DS1_OUT_X_L_G, 6)
                                if len(raw_data) != 6:
                                    logging.warning(f"Gyro read short: got {len(raw_data)} bytes")
                                    time.sleep(0.1) # Wait before retrying
                                    continue

                                # Unpack raw data (little-endian signed short)
                                gx_raw, gy_raw, gz_raw = struct.unpack('<hhh', raw_data)

                                # Convert to DPS
                                gx_dps = gx_raw * GYRO_SENSITIVITY_245DPS
                                gy_dps = gy_raw * GYRO_SENSITIVITY_245DPS
                                gz_dps = gz_raw * GYRO_SENSITIVITY_245DPS

                                # Format and send data (add newline for client parsing)
                                stream_response = f"GYRO X:{gx_dps:+.2f} Y:{gy_dps:+.2f} Z:{gz_dps:+.2f}\n"
                                sslsock.sendall(stream_response.encode())

                                # Throttle the loop (e.g., ~10Hz)
                                time.sleep(0.1)

                                # --- Check for STOP command ---
                                sslsock.settimeout(0.01) # Very short timeout
                                try:
                                    stop_cmd_raw = sslsock.recv(64)
                                    if stop_cmd_raw:
                                        stop_cmd = stop_cmd_raw.decode().strip().lower()
                                        if stop_cmd == 'stop':
                                            logging.info(f"Stopping gyro stream for {client_ip}:{client_port} via 'stop' command.")
                                            try:
                                                sslsock.sendall(b"OK Gyro stream stopped.\n")
                                            except Exception as send_err:
                                                logging.warning(f"Could not send 'stream stopped' confirmation: {send_err}")
                                            is_streaming_gyro = False # Exit streaming loop
                                        else:
                                            logging.debug(f"Ignoring unexpected data during gyro stream: {stop_cmd}")
                                            # Note: If valid commands can be interleaved, this needs more complex handling.

                                except socket.timeout:
                                    pass # No 'stop' command received, continue loop

                                # --- **MODIFICATION HERE** ---
                                # Specifically handle EOF/disconnect errors during the 'stop' check gracefully
                                except ssl.SSLEOFError:
                                    # Client closed the connection without saying 'stop' - expected with current client
                                    logging.info(f"Client {client_ip}:{client_port} disconnected during gyro stream (EOF). Stopping stream.")
                                    is_streaming_gyro = False # Stop streaming
                                except socket.error as sock_check_err:
                                    # Handle other potential socket errors during the check, e.g., ConnectionResetError
                                    if sock_check_err.errno == 104: # Connection reset by peer
                                        logging.info(f"Client {client_ip}:{client_port} reset connection during gyro stream. Stopping stream.")
                                    else:
                                        logging.error(f"Socket error during gyro stream 'stop' check: {sock_check_err}")
                                    is_streaming_gyro = False # Stop streaming
                                # --- End of Modification ---

                                except Exception as recv_check_err:
                                    # Catch any other unexpected errors during the check
                                    logging.error(f"Unexpected error during gyro stream 'stop' check: {recv_check_err}")
                                    is_streaming_gyro = False # Stop streaming
                                finally:
                                    # Restore original timeout ONLY if we are continuing the stream
                                    if is_streaming_gyro:
                                        try:
                                            sslsock.settimeout(default_sock_timeout)
                                        except socket.error:
                                             # Socket might already be dead if an error occurred above
                                             is_streaming_gyro = False


                            except (I2CError, struct.error) as read_e:
                                logging.error(f"Error reading/processing gyro data: {read_e}")
                                try:
                                    sslsock.sendall(f"ERROR: Reading gyro data failed - {read_e}\n".encode())
                                except: pass
                                is_streaming_gyro = False
                            except (socket.error, ssl.SSLError) as sock_e:
                                # This catches errors during the main sendall() of gyro data
                                logging.error(f"Socket error during gyro stream send: {sock_e}")
                                is_streaming_gyro = False
                            except Exception as stream_loop_err:
                                # Catch-all for other unexpected errors in the stream loop
                                logging.error(f"Unexpected error in gyro stream loop: {stream_loop_err}")
                                is_streaming_gyro = False

                        # --- End of 'while is_streaming_gyro' loop ---
                        logging.debug(f"Exited gyro stream loop for {client_ip}:{client_port}.")
                        # Ensure timeout is reset if loop exited abruptly
                        try:
                            sslsock.settimeout(default_sock_timeout)
                        except socket.error: pass # Ignore if socket already closed

                        # After stream ends (normally or via error), wait for next command
                        continue

                    # --- UNKNOWN command ---
                    else:
                        response = f"ERROR: Unknown command or incorrect parameters: '{data}'"

                    # --- Send Non-Streaming Response ---
                    # This is only reached for commands other than readgyro start
                    logging.debug(f"Sending response to {client_ip}:{client_port}: {response}")
                    sslsock.sendall(response.encode() + b'\n') # Add newline for consistency


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

                # --- Send Error Response (if applicable and not streaming) ---
                if not is_streaming_gyro and response.startswith("ERROR:"):
                    try:
                        logging.debug(f"Sending error response: {response}")
                        sslsock.sendall(response.encode() + b'\n')
                    except (socket.error, ssl.SSLError) as send_e:
                        logging.error(f"Failed to send error response to {client_ip}:{client_port}: {send_e}")
                        break # Assume client connection is broken

    # --- Error Handling for Connection ---
    # (Outer try...except block remains mostly the same)
    except (ssl.SSLError, socket.error) as e:
        # ... (error logging as before) ...
         if isinstance(e, socket.timeout): # Catch timeout from initial recv
             logging.warning(f"Client {client_ip}:{client_port} timed out waiting for initial command.")
         elif isinstance(e, ssl.SSLError) and 'timed out' in str(e).lower():
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

# --- setup_gpio function remains the same ---
def setup_gpio():
    """Sets up the GPIO pin for the LED."""
    if not GPIO_AVAILABLE:
        logging.warning("Skipping GPIO setup as library is not available.")
        return False
    try:
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        GPIO.setup(LED_GPIO_PIN, GPIO.OUT)
        GPIO.output(LED_GPIO_PIN, GPIO.LOW)
        logging.info(f"GPIO{LED_GPIO_PIN} set up as output (LED control). Initial state: OFF.")
        return True
    except RuntimeError as e:
        logging.error(f"Failed to set up GPIO: {e}. Check permissions (run with sudo?) or pin conflicts.")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during GPIO setup: {e}")
        return False

# --- tls_i2c_server function remains the same ---
def tls_i2c_server(server_address, server_port, certfile, keyfile, bus_number=1):
    """Starts the TLS secured I2C server with GPIO control."""
    server_sock = None
    i2c_handler = None
    gpio_initialized = False

    if not os.path.exists(certfile): logging.error(f"Certificate file not found: {certfile}"); return
    if not os.path.exists(keyfile): logging.error(f"Key file not found: {keyfile}"); return

    try:
        try:
            i2c_handler = I2CHandler(bus_number)
        except I2CError as e:
            logging.warning(f"Could not initialize I2C Handler on bus {bus_number}: {e}. I2C commands will fail.")

        gpio_initialized = setup_gpio()
        if not gpio_initialized and GPIO_AVAILABLE:
             logging.warning("GPIO setup failed, LED commands might not work.")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((server_address, server_port))
        server_sock.listen(5)
        logging.info(f"TLS I2C/GPIO Server listening on {server_address}:{server_port} (I2C bus {bus_number}, LED GPIO{LED_GPIO_PIN})")
        logging.info(f"Using cert: {certfile}, key: {keyfile}")

        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                try:
                    sslsock = context.wrap_socket(client_sock, server_side=True)
                    client_thread = threading.Thread(
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
         if e.errno == 98:
             logging.critical("Check if another instance of the server is running.")
    except Exception as e:
        logging.critical(f"Fatal server error during startup: {traceback.format_exc()}")
    finally:
        # --- Cleanup --- (Remains the same)
        logging.info("Shutting down server...")
        if server_sock:
            try: server_sock.close(); logging.info("Server socket closed.")
            except Exception as e: logging.error(f"Error closing server socket: {e}")
        if i2c_handler:
            try: i2c_handler.close(); logging.info("I2C handler closed.")
            except Exception as e: logging.error(f"Error closing I2C handler: {e}")
        if gpio_initialized:
            try: GPIO.cleanup(); logging.info("GPIO cleaned up.")
            except Exception as e: logging.error(f"Error during GPIO cleanup: {e}")
        elif GPIO_AVAILABLE:
             logging.debug("Attempting GPIO cleanup even though initialization may have failed.")
             try: GPIO.cleanup()
             except: pass
        logging.info("Server shut down complete.")

# --- __main__ block remains the same ---
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

    key_dir = os.path.dirname(args.cert) if os.path.dirname(args.cert) else '.'
    if not os.path.exists(key_dir):
        try: os.makedirs(key_dir); logging.info(f"Created directory: {key_dir}")
        except OSError as e: logging.error(f"Failed to create directory {key_dir}: {e}")

    if not (os.path.exists(args.cert) and os.path.exists(args.key)):
        print(f"ERROR: Certificate ({args.cert}) and/or key ({args.key}) not found.")
        print("You may need to generate them, e.g., using openssl:")
        key_path = os.path.join(key_dir, os.path.basename(args.key))
        cert_path = os.path.join(key_dir, os.path.basename(args.cert))
        print(f"  openssl req -x509 -newkey rsa:4096 -keyout {key_path} -out {cert_path} -sha256 -days 365 -nodes -subj '/CN=MyI2CServer'")
        exit(1)

    # Run the server
    tls_i2c_server(args.host, args.port, args.cert, args.key, args.bus)