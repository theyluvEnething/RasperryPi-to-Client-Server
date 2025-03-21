import socket
import ssl

def tls_echo_client(server_address, server_port, message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sslsock = context.wrap_socket(sock, server_hostname=server_address)
        sslsock.connect((server_address, server_port))

        print(f"Sending message: {message.decode()}")
        sslsock.sendall(message)

        response = sslsock.recv(4096)
        print(f"Received echo: {response.decode()}")

        sslsock.close()
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    server_address = "127.0.0.1"
    server_port = 12345
    message = b"Hello, TLS Echo Server!"
    tls_echo_client(server_address, server_port, message)
