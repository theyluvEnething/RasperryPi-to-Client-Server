import socket
import ssl
import threading
import traceback
from smbus2 import SMBus, i2c_msg

class I2CServer:
    def __init__(self, bus_number=1):
        self.bus = SMBus(bus_number)
    
    def i2c_dump(self, address, length=16):
        """Read block of data from I2C device"""
        try:
            msg = i2c_msg.read(address, length)
            self.bus.i2c_rdwr(msg)
            return list(msg)
        except Exception as e:
            return str(e)
    
    def i2c_read(self, address, register, length=1):
        """Read from specific register"""
        try:
            return self.bus.read_i2c_block_data(address, register, length)
        except Exception as e:
            return str(e)
    
    def i2c_write(self, address, register, data):
        """Write to specific register"""
        try:
            self.bus.write_i2c_block_data(address, register, data)
            return True
        except Exception as e:
            return str(e)

def handle_client(sslsock, client_address, i2c_server):
    try:
        while True:
            data = sslsock.recv(4096).decode().strip()
            if not data:
                print(f"Client {client_address} disconnected.")
                break
            
            print(f"Received command from {client_address}: {data}")
            parts = data.split()
            response = "ERROR: Invalid command"
            
            try:
                if parts[0].lower() == "dump" and len(parts) == 2:
                    address = int(parts[1], 16)
                    result = i2c_server.i2c_dump(address)
                    response = f"OK {result}" if isinstance(result, list) else f"ERROR {result}"
                
                elif parts[0].lower() == "read" and len(parts) >= 3:
                    address = int(parts[1], 16)
                    register = int(parts[2], 16)
                    length = int(parts[3]) if len(parts) > 3 else 1
                    result = i2c_server.i2c_read(address, register, length)
                    response = f"OK {result}" if isinstance(result, list) else f"ERROR {result}"
                
                elif parts[0].lower() == "write" and len(parts) >= 4:
                    address = int(parts[1], 16)
                    register = int(parts[2], 16)
                    data = [int(x, 16) for x in parts[3:]]
                    result = i2c_server.i2c_write(address, register, data)
                    response = "OK" if result is True else f"ERROR {result}"
                
                elif parts[0].lower() == "scan":
                    devices = []
                    for address in range(0x03, 0x77):
                        try:
                            self.bus.read_byte(address)
                            devices.append(hex(address))
                        except:
                            pass
                    response = f"OK {devices}"
                
                else:
                    response = "ERROR: Unknown command or invalid parameters"
            
            except ValueError:
                response = "ERROR: Invalid parameter format"
            
            sslsock.sendall(response.encode())
    
    except (ssl.SSLError, socket.error) as e:
        print(f"Connection error with {client_address}: {e}")
    except Exception as e:
        print(f"Unexpected error with {client_address}: {e}")
    finally:
        sslsock.close()

def tls_i2c_server(server_address, server_port, certfile, keyfile, bus_number=1):
    sock = None
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((server_address, server_port))
        sock.listen(5)
        
        i2c_server = I2CServer(bus_number)
        print(f"TLS I2C Server listening on {server_address}:{server_port}")
        
        while True:
            client_sock, client_addr = sock.accept()
            try:
                sslsock = context.wrap_socket(client_sock, server_side=True)
                client_thread = threading.Thread(target=handle_client, 
                                                args=(sslsock, client_addr, i2c_server))
                client_thread.daemon = True
                client_thread.start()
            except ssl.SSLError as e:
                print(f"SSL handshake error with {client_addr}: {e}")
                client_sock.close()
    
    except Exception as e:
        print(traceback.format_exc())
    finally:
        if sock:
            sock.close()

if __name__ == "__main__":
    SERVER_ADDRESS = "0.0.0.0"  # Listen on all interfaces
    SERVER_PORT = 12345
    CERTFILE = "keys/server.crt"
    KEYFILE = "keys/server.key"
    I2C_BUS = 1  # Typically 1 for Raspberry Pi 3/4
    
    tls_i2c_server(SERVER_ADDRESS, SERVER_PORT, CERTFILE, KEYFILE, I2C_BUS)