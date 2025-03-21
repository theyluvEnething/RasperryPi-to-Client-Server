import socket
import ssl
import threading
import traceback
import smbus

# Initialize I2C (assuming device address 0x1)
I2C_BUS = 1
I2C_ADDRESS = 0x1
i2c_bus = smbus.SMBus(I2C_BUS)

def handle_client(sslsock, client_address):
    try:
        while True:
            data = sslsock.recv(4096)
            if not data:
                print(f"Client {client_address} disconnected.")
                break

            # Decode the received command
            command = data.decode().strip().lower()
            print(f"Received command from {client_address}: {command}")

            # Process the command
            response = process_command(command)
            sslsock.sendall(response.encode())
    except ssl.SSLError as e:
        print(f"SSL error from {client_address}: {e}")
    except socket.error as e:
        print(f"Socket error from {client_address}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred with {client_address}: {e}")
    finally:
        sslsock.close()

def process_command(command):
    """
    Process the client command and return the appropriate response.
    """
    if command == "dump":
        # Dump I2C data (example: read 16 bytes from I2C)
        try:
            data = i2c_bus.read_i2c_block_data(I2C_ADDRESS, 0, 16)
            return f"DUMP: {data}"
        except Exception as e:
            return f"ERROR: {e}"

    elif command.startswith("i2c"):
        # Example: i2c read <register> or i2c write <register> <value>
        parts = command.split()
        if len(parts) == 3 and parts[1] == "read":
            try:
                register = int(parts[2], 16)
                value = i2c_bus.read_byte_data(I2C_ADDRESS, register)
                return f"READ: Register {hex(register)} = {hex(value)}"
            except Exception as e:
                return f"ERROR: {e}"
        elif len(parts) == 4 and parts[1] == "write":
            try:
                register = int(parts[2], 16)
                value = int(parts[3], 16)
                i2c_bus.write_byte_data(I2C_ADDRESS, register, value)
                return f"WRITE: Register {hex(register)} set to {hex(value)}"
            except Exception as e:
                return f"ERROR: {e}"
        else:
            return "ERROR: Invalid I2C command format. Use 'i2c read <register>' or 'i2c write <register> <value>'."

    elif command.startswith("set"):
        # Example: set <register> <value>
        parts = command.split()
        if len(parts) == 3:
            try:
                register = int(parts[1], 16)
                value = int(parts[2], 16)
                i2c_bus.write_byte_data(I2C_ADDRESS, register, value)
                return f"SET: Register {hex(register)} set to {hex(value)}"
            except Exception as e:
                return f"ERROR: {e}"
        else:
            return "ERROR: Invalid SET command format. Use 'set <register> <value>'."

    else:
        return "ERROR: Unknown command. Supported commands: dump, i2c read <register>, i2c write <register> <value>, set <register> <value>."

def tls_server(server_address, server_port, certfile, keyfile):
    sock = None
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((server_address, server_port))
        sock.listen(5)
        print(f"TLS Server listening on {server_address}:{server_port}")
        while True:
            client_sock, client_addr = sock.accept()
            try:
                sslsock = context.wrap_socket(client_sock, server_side=True)
            except ssl.SSLError as e:
                print(f"SSL handshake error with {client_addr}: {e}")
                client_sock.close()
                continue
            client_thread = threading.Thread(target=handle_client, args=(sslsock, client_addr))
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        print(traceback.format_exc())
    finally:
        if sock:
            sock.close()

if __name__ == "__main__":
    server_address = "0.0.0.0"  # Listen on all interfaces
    server_port = 12345
    certfile = "keys/server.crt"
    keyfile = "keys/server.key"
    tls_server(server_address, server_port, certfile, keyfile)