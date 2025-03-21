import socket
import ssl
import threading
import traceback
import os
import fcntl
import struct

# I2C constants
I2C_SLAVE = 0x0703
I2C_SLAVE_FORCE = 0x0706
I2C_RDWR = 0x0707
I2C_M_RD = 0x0001

class I2CHandler:
    def __init__(self, bus_number=1):
        self.bus_number = bus_number
        self.fd = None
        self.open()
    
    def open(self):
        try:
            self.fd = os.open(f"/dev/i2c-{self.bus_number}", os.O_RDWR)
        except Exception as e:
            raise RuntimeError(f"Could not open I2C bus: {e}")
    
    def close(self):
        if self.fd:
            os.close(self.fd)
    
    def set_address(self, address):
        try:
            fcntl.ioctl(self.fd, I2C_SLAVE, address)
        except:
            fcntl.ioctl(self.fd, I2C_SLAVE_FORCE, address)
    
    def read_bytes(self, length):
        return list(os.read(self.fd, length))
    
    def write_bytes(self, data):
        os.write(self.fd, bytes(data))
    
    def read_register(self, address, register, length=1):
        try:
            self.set_address(address)
            self.write_bytes([register])
            return self.read_bytes(length)
        except Exception as e:
            return str(e)
    
    def write_register(self, address, register, data):
        try:
            self.set_address(address)
            self.write_bytes([register] + data)
            return True
        except Exception as e:
            return str(e)
    
    def scan_devices(self):
        devices = []
        for addr in range(0x03, 0x78):
            try:
                fcntl.ioctl(self.fd, I2C_SLAVE, addr)
                os.read(self.fd, 1)
                devices.append(hex(addr))
            except Exception:
                pass
        return devices

def handle_client(sslsock, client_address, i2c_handler):
    try:
        while True:
            data = sslsock.recv(4096).decode().strip()
            if not data:
                print(f"Client {client_address} disconnected.")
                break
            
            print(f"Received command: {data}")
            parts = data.split()
            response = "ERROR: Invalid command"
            
            try:
                if parts[0].lower() == "dump" and len(parts) == 2:
                    address = int(parts[1], 16)
                    i2c_handler.set_address(address)
                    result = i2c_handler.read_bytes(16)
                    response = f"OK {result}"
                
                elif parts[0].lower() == "read" and len(parts) >= 3:
                    address = int(parts[1], 16)
                    register = int(parts[2], 16)
                    length = int(parts[3]) if len(parts) > 3 else 1
                    result = i2c_handler.read_register(address, register, length)
                    response = f"OK {result}" if isinstance(result, list) else f"ERROR {result}"
                
                elif parts[0].lower() == "write" and len(parts) >= 4:
                    address = int(parts[1], 16)
                    register = int(parts[2], 16)
                    data = [int(x, 16) for x in parts[3:]]
                    result = i2c_handler.write_register(address, register, data)
                    response = "OK" if result is True else f"ERROR {result}"
                
                elif parts[0].lower() == "scan":
                    devices = i2c_handler.scan_devices()
                    response = f"OK {devices}"
                
                else:
                    response = "ERROR: Unknown command"
            
            except (ValueError, IndexError) as e:
                response = f"ERROR: Invalid parameters - {e}"
            except Exception as e:
                response = f"ERROR: {e}"
            
            sslsock.sendall(response.encode())
    
    except (ssl.SSLError, socket.error) as e:
        print(f"Connection error: {e}")
    finally:
        sslsock.close()

def tls_i2c_server(server_address, server_port, certfile, keyfile, bus_number=1):
    sock = None
    i2c_handler = None
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((server_address, server_port))
        sock.listen(5)
        
        i2c_handler = I2CHandler(bus_number)
        print(f"TLS I2C Server started on {server_address}:{server_port}")
        
        while True:
            client_sock, client_addr = sock.accept()
            try:
                sslsock = context.wrap_socket(client_sock, server_side=True)
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(sslsock, client_addr, i2c_handler)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                print(f"Connection setup failed: {e}")
                client_sock.close()
    
    except Exception as e:
        print(f"Server error: {traceback.format_exc()}")
    finally:
        if sock:
            sock.close()
        if i2c_handler:
            i2c_handler.close()

if __name__ == "__main__":
    SERVER_ADDRESS = "0.0.0.0"
    SERVER_PORT = 12345
    CERTFILE = "keys/server.crt"
    KEYFILE = "keys/server.key"
    I2C_BUS = 1  # Use 1 for Raspberry Pi 3/4
    
    tls_i2c_server(SERVER_ADDRESS, SERVER_PORT, CERTFILE, KEYFILE, I2C_BUS)