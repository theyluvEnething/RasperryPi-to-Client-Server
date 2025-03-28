import socket
import ssl
import sys
import traceback
import time
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import font as tkFont  # Import font module

# --- Configuration ---
# !! Important: Replace with the actual IP address of your Raspberry Pi !!
DEFAULT_SERVER_ADDRESS = "172.20.10.3" # Replace with your Pi's IP
DEFAULT_SERVER_PORT = 12345
CONNECTION_TIMEOUT = 5.0 # Seconds to wait for connection
RECEIVE_TIMEOUT = 10.0   # Seconds to wait for response

# --- TLS Communication Logic ---
def send_command(server_address, server_port, command_str, status_callback=None):
    """
    Connects to the TLS server, sends a command, and returns the response.

    Args:
        server_address (str): The IP address or hostname of the server.
        server_port (int): The port number of the server.
        command_str (str): The command string to send.
        status_callback (func): Optional function to call with status updates.

    Returns:
        str: The decoded response from the server, or an error string starting with "ERROR:".
    """
    sock = None
    sslsock = None

    def update_status(message):
        if status_callback:
            status_callback(message)
        else:
            print(message) # Fallback for non-GUI use

    try:
        # 1. Create SSL Context (INSECURE - Disables Verification)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE # <<< INSECURE! For testing only.

        # 2. Create and Connect Socket
        update_status(f"Connecting to {server_address}:{server_port}...")
        sock = socket.create_connection((server_address, server_port), timeout=CONNECTION_TIMEOUT)

        # 3. Wrap Socket with SSL/TLS
        sslsock = context.wrap_socket(sock, server_hostname=server_address)
        update_status(f"Connected via {sslsock.version()}. Sending: {command_str}")

        # 4. Send Command
        sslsock.sendall(command_str.encode('utf-8'))

        # 5. Receive Response
        sslsock.settimeout(RECEIVE_TIMEOUT)
        response_bytes = sslsock.recv(4096)
        if not response_bytes:
            update_status("Server closed connection unexpectedly.")
            return "ERROR: Server closed connection."
        response_str = response_bytes.decode('utf-8')
        update_status(f"Received: {response_str}")
        return response_str

    except ssl.SSLCertVerificationError as e:
        err_msg = f"ERROR: SSL CERTIFICATE VERIFICATION FAILED: {e}\n (Is server using a self-signed cert? This client uses CERT_NONE - INSECURE)"
        update_status(err_msg)
        return err_msg
    except ssl.SSLError as e:
        err_msg = f"ERROR: SSL ERROR: {e}\n (Check TLS/SSL versions and cert validity?)"
        update_status(err_msg)
        return err_msg
    except socket.timeout:
        err_msg = f"ERROR: Connection or receive timed out ({CONNECTION_TIMEOUT}/{RECEIVE_TIMEOUT}s)"
        update_status(err_msg)
        return err_msg
    except socket.error as e:
        err_msg = f"ERROR: SOCKET ERROR: {e}\n (Is the server running at {server_address}:{server_port}?)"
        update_status(err_msg)
        return err_msg
    except Exception as e:
        err_msg = f"ERROR: An unexpected error occurred: {e}\n{traceback.format_exc()}"
        update_status(err_msg)
        return err_msg
    finally:
        # 6. Close Connection
        if sslsock:
            try:
                sslsock.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass
            finally:
                sslsock.close()
                update_status("Connection closed.")
        elif sock:
            sock.close()
            update_status("Connection closed (socket only).")

# --- GUI Application Class ---
class I2CGuiClient:
    def __init__(self, master):
        self.master = master
        master.title("TLS I2C/GPIO Client")

        # Increase default font size
        default_font = tkFont.nametofont("TkDefaultFont")
        default_font.configure(size=11)
        master.option_add("*Font", default_font)

        # Frame for connection details
        conn_frame = tk.Frame(master, padx=10, pady=5)
        conn_frame.pack(fill=tk.X)

        tk.Label(conn_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=2)
        self.ip_entry = tk.Entry(conn_frame, width=15)
        self.ip_entry.grid(row=0, column=1, padx=2)
        self.ip_entry.insert(0, DEFAULT_SERVER_ADDRESS)

        tk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=2)
        self.port_entry = tk.Entry(conn_frame, width=6)
        self.port_entry.grid(row=0, column=3, padx=2)
        self.port_entry.insert(0, str(DEFAULT_SERVER_PORT))

        # Frame for common command buttons
        button_frame = tk.Frame(master, padx=10, pady=5)
        button_frame.pack(fill=tk.X)

        self.led_on_button = tk.Button(button_frame, text="LED ON", command=self.send_led_on)
        self.led_on_button.pack(side=tk.LEFT, padx=5)

        self.led_off_button = tk.Button(button_frame, text="LED OFF", command=self.send_led_off)
        self.led_off_button.pack(side=tk.LEFT, padx=5)

        self.scan_button = tk.Button(button_frame, text="Scan I2C Bus", command=self.send_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # Frame for custom command entry
        custom_cmd_frame = tk.Frame(master, padx=10, pady=5)
        custom_cmd_frame.pack(fill=tk.X)

        tk.Label(custom_cmd_frame, text="Command:").pack(side=tk.LEFT, padx=2)
        self.cmd_entry = tk.Entry(custom_cmd_frame)
        self.cmd_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        self.cmd_entry.bind("<Return>", self.send_custom_command_event) # Bind Enter key

        self.send_button = tk.Button(custom_cmd_frame, text="Send", command=self.send_custom_command)
        self.send_button.pack(side=tk.LEFT, padx=5)

        # Frame for output/log
        output_frame = tk.Frame(master, padx=10, pady=10)
        output_frame.pack(expand=True, fill=tk.BOTH)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15, width=60)
        self.output_text.pack(expand=True, fill=tk.BOTH)
        self.output_text.configure(state='disabled') # Make read-only initially

        # Initial Warning
        self.log_message("*" * 40, tag="warning")
        self.log_message(" WARNING: SSL certificate verification is DISABLED.", tag="warning")
        self.log_message(" Connection is encrypted but not authenticated.", tag="warning")
        self.log_message(" DO NOT use in production without proper cert validation.", tag="warning")
        self.log_message("*" * 40, tag="warning")
        self.output_text.tag_config("warning", foreground="red", font=(default_font.actual()['family'], default_font.actual()['size'], 'bold'))
        self.output_text.tag_config("command", foreground="blue")
        self.output_text.tag_config("response", foreground="darkgreen")
        self.output_text.tag_config("error", foreground="red")
        self.output_text.tag_config("status", foreground="grey")


    def log_message(self, message, tag=None):
        """Appends a message to the output text area."""
        self.output_text.configure(state='normal') # Enable writing
        self.output_text.insert(tk.END, message + '\n', tag)
        self.output_text.configure(state='disabled') # Disable writing
        self.output_text.see(tk.END) # Scroll to the end
        self.master.update_idletasks() # Refresh GUI immediately

    def update_status_for_send(self, message):
        """Callback for send_command to log status messages."""
        self.log_message(message, tag="status")

    def execute_command(self, command):
        """Gets connection details, sends command, and logs result."""
        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()

        if not ip:
            messagebox.showerror("Error", "Server IP address cannot be empty.")
            return
        try:
            port = int(port_str)
            if not (0 < port < 65536):
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Error", f"Invalid port number: {port_str}")
            return

        self.log_message(f"CMD> {command}", tag="command")
        response = send_command(ip, port, command, self.update_status_for_send)

        if response:
            if response.startswith("ERROR:"):
                 self.log_message(f"RES< {response}", tag="error")
            else:
                 self.log_message(f"RES< {response}", tag="response")
        else:
            # send_command logs errors internally via callback, but handle None just in case
             self.log_message("RES< No response received or error occurred.", tag="error")


    def send_led_on(self):
        self.execute_command("turnonled")

    def send_led_off(self):
        self.execute_command("turnoffled")

    def send_scan(self):
        self.execute_command("scan")

    def send_custom_command(self):
        custom_cmd = self.cmd_entry.get().strip()
        if custom_cmd:
            self.execute_command(custom_cmd)
            self.cmd_entry.delete(0, tk.END) # Clear entry after sending
        else:
            self.log_message("Status: No custom command entered.", tag="status")

    def send_custom_command_event(self, event):
        """Handles the Enter key press in the command entry."""
        self.send_custom_command()


# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = I2CGuiClient(root)
    root.mainloop()