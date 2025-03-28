import socket
import ssl
import sys
import traceback
import time
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import font as tkFont
import threading # Import threading

# --- Configuration ---
DEFAULT_SERVER_ADDRESS = "172.20.10.3" # Replace with your Pi's IP
DEFAULT_SERVER_PORT = 12345
CONNECTION_TIMEOUT = 5.0
RECEIVE_TIMEOUT = 10.0   # Timeout for initial responses/non-streaming commands
STREAM_RECV_TIMEOUT = 1.0 # Timeout for recv() inside the streaming loop

# --- Simple Command Function (Unchanged, used for non-streaming) ---
def send_command(server_address, server_port, command_str, status_callback=None):
    # ... (Keep the original send_command function exactly as it was) ...
    sock = None
    sslsock = None

    def update_status(message):
        if status_callback: status_callback(message)
        else: print(message)

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        update_status(f"Connecting to {server_address}:{server_port}...")
        sock = socket.create_connection((server_address, server_port), timeout=CONNECTION_TIMEOUT)
        sslsock = context.wrap_socket(sock, server_hostname=server_address)
        update_status(f"Connected via {sslsock.version()}. Sending: {command_str}")
        sslsock.sendall(command_str.encode('utf-8'))
        sslsock.settimeout(RECEIVE_TIMEOUT)
        response_bytes = sslsock.recv(4096)
        if not response_bytes:
            update_status("Server closed connection unexpectedly.")
            return "ERROR: Server closed connection."
        response_str = response_bytes.decode('utf-8').strip() # Strip potential newlines
        update_status(f"Received: {response_str}")
        return response_str
    except ssl.SSLCertVerificationError as e:
        err_msg = f"ERROR: SSL CERTIFICATE VERIFICATION FAILED: {e}\n (Is server using a self-signed cert? This client uses CERT_NONE - INSECURE)"
        update_status(err_msg); return err_msg
    except ssl.SSLError as e:
        err_msg = f"ERROR: SSL ERROR: {e}\n (Check TLS/SSL versions and cert validity?)"
        update_status(err_msg); return err_msg
    except socket.timeout:
        err_msg = f"ERROR: Connection or receive timed out ({CONNECTION_TIMEOUT}/{RECEIVE_TIMEOUT}s)"
        update_status(err_msg); return err_msg
    except socket.error as e:
        err_msg = f"ERROR: SOCKET ERROR: {e}\n (Is the server running at {server_address}:{server_port}?)"
        update_status(err_msg); return err_msg
    except Exception as e:
        err_msg = f"ERROR: An unexpected error occurred: {e}\n{traceback.format_exc()}"
        update_status(err_msg); return err_msg
    finally:
        if sslsock:
            try: sslsock.shutdown(socket.SHUT_RDWR)
            except: pass
            finally: sslsock.close(); update_status("Connection closed.")
        elif sock:
            sock.close(); update_status("Connection closed (socket only).")

# --- GUI Application Class ---
class I2CGuiClient:
    def __init__(self, master):
        self.master = master
        master.title("TLS I2C/GPIO Client")
        master.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close

        # --- State Variables ---
        self.is_streaming = False
        self.streaming_socket = None
        self.stream_thread = None
        self.stop_streaming_flag = threading.Event() # Use Event for thread signaling

        default_font = tkFont.nametofont("TkDefaultFont")
        default_font.configure(size=11)
        master.option_add("*Font", default_font)

        # --- Connection Frame ---
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

        # --- Common/Non-Streaming Command Frame ---
        common_button_frame = tk.Frame(master, padx=10, pady=5)
        common_button_frame.pack(fill=tk.X)
        self.led_on_button = tk.Button(common_button_frame, text="LED ON", command=self.send_led_on)
        self.led_on_button.pack(side=tk.LEFT, padx=5)
        self.led_off_button = tk.Button(common_button_frame, text="LED OFF", command=self.send_led_off)
        self.led_off_button.pack(side=tk.LEFT, padx=5)
        self.scan_button = tk.Button(common_button_frame, text="Scan I2C Bus", command=self.send_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # --- Streaming Command Frame ---
        stream_button_frame = tk.Frame(master, padx=10, pady=5)
        stream_button_frame.pack(fill=tk.X)
        self.start_stream_button = tk.Button(stream_button_frame, text="Start Gyro Stream", command=self.start_gyro_stream)
        self.start_stream_button.pack(side=tk.LEFT, padx=5)
        self.stop_stream_button = tk.Button(stream_button_frame, text="Stop Gyro Stream", command=self.stop_gyro_stream, state=tk.DISABLED)
        self.stop_stream_button.pack(side=tk.LEFT, padx=5)

        # --- Custom Command Frame ---
        custom_cmd_frame = tk.Frame(master, padx=10, pady=5)
        custom_cmd_frame.pack(fill=tk.X)
        tk.Label(custom_cmd_frame, text="Command:").pack(side=tk.LEFT, padx=2)
        self.cmd_entry = tk.Entry(custom_cmd_frame)
        self.cmd_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        self.cmd_entry.bind("<Return>", self.send_custom_command_event)
        self.send_button = tk.Button(custom_cmd_frame, text="Send", command=self.send_custom_command)
        self.send_button.pack(side=tk.LEFT, padx=5)

        # --- Output Frame ---
        output_frame = tk.Frame(master, padx=10, pady=10)
        output_frame.pack(expand=True, fill=tk.BOTH)
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15, width=60)
        self.output_text.pack(expand=True, fill=tk.BOTH)
        self.output_text.configure(state='disabled')

        # --- Tag Configurations ---
        self.output_text.tag_config("warning", foreground="red", font=(default_font.actual()['family'], default_font.actual()['size'], 'bold'))
        self.output_text.tag_config("command", foreground="blue")
        self.output_text.tag_config("response", foreground="darkgreen")
        self.output_text.tag_config("error", foreground="red")
        self.output_text.tag_config("status", foreground="grey")
        self.output_text.tag_config("stream", foreground="#5555AA") # Different color for stream data

        # Initial Warning
        self._log_message_threadsafe("*" * 40, tag="warning")
        self._log_message_threadsafe(" WARNING: SSL certificate verification is DISABLED.", tag="warning")
        # ... (rest of warnings) ...
        self._log_message_threadsafe("*" * 40, tag="warning")


    # --- Logging (Thread-Safe) ---
    def _log_message_threadsafe(self, message, tag=None):
        """ Safely appends a message to the output text area from any thread. """
        # Use master.after to schedule the GUI update on the main thread
        self.master.after(0, self._update_log_widget, message, tag)

    def _update_log_widget(self, message, tag):
        """ Actual widget update, MUST run on main GUI thread. """
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, message + '\n', tag)
        self.output_text.configure(state='disabled')
        self.output_text.see(tk.END)

    def _update_status_callback(self, message):
        """ Callback for status updates, uses thread-safe logging. """
        self._log_message_threadsafe(message, tag="status")

    # --- Execute Non-Streaming Command ---
    def execute_non_streaming_command(self, command):
        """ Sends a single command and gets a single response, then disconnects. """
        if self.is_streaming:
            messagebox.showwarning("Busy", "Cannot send command while streaming.")
            return

        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        # ... (IP/Port validation as before) ...
        if not ip or not port_str.isdigit():
             messagebox.showerror("Error", "Invalid IP or Port.")
             return
        port = int(port_str)

        self._log_message_threadsafe(f"CMD> {command}", tag="command")
        # Run send_command in a separate thread to avoid blocking GUI during connect/recv
        thread = threading.Thread(target=self._send_command_thread_target, args=(ip, port, command), daemon=True)
        thread.start()

    def _send_command_thread_target(self, ip, port, command):
        """Target for running send_command in a background thread."""
        response = send_command(ip, port, command, self._update_status_callback)
        if response:
            tag = "error" if response.startswith("ERROR:") else "response"
            self._log_message_threadsafe(f"RES< {response}", tag=tag)
        else:
             self._log_message_threadsafe("RES< No response received or error occurred.", tag="error")

    # --- Streaming Logic ---
    def start_gyro_stream(self):
        """Establishes connection and starts the gyro stream receiver thread."""
        if self.is_streaming:
            self._log_message_threadsafe("Status: Already streaming.", tag="status")
            return

        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        if not ip or not port_str.isdigit():
             messagebox.showerror("Error", "Invalid IP or Port.")
             return
        port = int(port_str)

        self._log_message_threadsafe("Attempting to start gyro stream...", tag="status")
        self._update_gui_for_streaming(True) # Disable buttons immediately

        # Run connection and stream setup in a background thread
        thread = threading.Thread(target=self._start_stream_thread_target, args=(ip, port), daemon=True)
        thread.start()

    def _start_stream_thread_target(self, ip, port):
        """Connects, sends 'readgyro', and starts receiver loop if successful."""
        sock = None
        sslsock = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self._update_status_callback(f"Connecting to {ip}:{port} for streaming...")
            sock = socket.create_connection((ip, port), timeout=CONNECTION_TIMEOUT)
            sslsock = context.wrap_socket(sock, server_hostname=ip)
            self._update_status_callback(f"Stream connected via {sslsock.version()}. Sending readgyro...")

            command = "readgyro" # Or add address if needed: f"readgyro {addr_hex}"
            sslsock.sendall(command.encode('utf-8'))
            self._log_message_threadsafe(f"CMD> {command}", tag="command")

            # Receive initial confirmation
            sslsock.settimeout(RECEIVE_TIMEOUT)
            response_bytes = sslsock.recv(1024) # Expect "OK Starting..."
            response_str = response_bytes.decode('utf-8').strip()

            if response_str.startswith("OK"):
                self._log_message_threadsafe(f"RES< {response_str}", tag="response")
                # --- Success - Start the receiver thread ---
                self.streaming_socket = sslsock # Store the persistent socket
                self.is_streaming = True
                self.stop_streaming_flag.clear() # Ensure flag is False
                self.stream_thread = threading.Thread(target=self._stream_receiver_loop, daemon=True)
                self.stream_thread.start()
                # GUI state already updated optimistically, nothing more needed here
            else:
                # Initial command failed
                self._log_message_threadsafe(f"RES< {response_str}", tag="error")
                raise Exception(f"Server rejected stream start: {response_str}")

        except Exception as e:
            # Handle connection or initial command errors
            self._log_message_threadsafe(f"ERROR starting stream: {e}", tag="error")
            if sslsock:
                try: sslsock.close()
                except: pass
            elif sock:
                 try: sock.close()
                 except: pass
            self.streaming_socket = None
            self.is_streaming = False
            # Schedule GUI reset on main thread
            self.master.after(0, self._update_gui_for_streaming, False)

    def _stream_receiver_loop(self):
        """Runs in background thread, receives and logs stream data."""
        sslsock = self.streaming_socket # Use the stored socket
        if not sslsock: return

        self._log_message_threadsafe("Stream receiver thread started.", tag="status")
        buffer = b"" # Buffer for partial messages

        while not self.stop_streaming_flag.is_set():
            try:
                sslsock.settimeout(STREAM_RECV_TIMEOUT) # Short timeout to allow checking stop_flag
                chunk = sslsock.recv(4096)

                if not chunk:
                    # Server closed connection cleanly (or uncleanly detected as EOF)
                    self._log_message_threadsafe("Stream connection closed by server.", tag="status")
                    self.stop_streaming_flag.set() # Signal loop end
                    break

                buffer += chunk
                # Process complete lines (separated by newline)
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    try:
                        decoded_line = line.decode('utf-8').strip()
                        if decoded_line: # Avoid logging empty lines
                            self._log_message_threadsafe(f"{decoded_line}", tag="stream")
                    except UnicodeDecodeError:
                        self._log_message_threadsafe(f"Received non-UTF8 stream data: {line!r}", tag="error")

            except socket.timeout:
                continue # Expected, just loop again to check stop_flag

            except (ssl.SSLEOFError, socket.error, ssl.SSLError) as e:
                # Connection error during stream
                self._log_message_threadsafe(f"Stream connection error: {e}", tag="error")
                self.stop_streaming_flag.set() # Signal loop end
                break # Exit loop

            except Exception as e:
                 # Unexpected error in loop
                 self._log_message_threadsafe(f"Unexpected error in stream receiver: {e}\n{traceback.format_exc()}", tag="error")
                 self.stop_streaming_flag.set() # Signal loop end
                 break # Exit loop

        # --- Loop finished ---
        self._log_message_threadsafe("Stream receiver thread finished.", tag="status")
        # Signal main thread to clean up GUI and socket if not already stopped via button
        self.master.after(0, self._handle_stream_end)

    def stop_gyro_stream(self):
        """Sends 'stop' command and signals the receiver thread to terminate."""
        if not self.is_streaming or self.streaming_socket is None:
            self._log_message_threadsafe("Status: Not currently streaming.", tag="status")
            return

        self._log_message_threadsafe("Attempting to stop gyro stream...", tag="status")

        # Signal the receiver thread first
        self.stop_streaming_flag.set()

        # Send 'stop' command to server
        try:
            stop_cmd = "stop\n" # Ensure newline if server expects it
            self.streaming_socket.sendall(stop_cmd.encode('utf-8'))
            self._log_message_threadsafe(f"CMD> {stop_cmd.strip()}", tag="command")
        except (socket.error, ssl.SSLError) as e:
            self._log_message_threadsafe(f"Error sending 'stop' command: {e}. May need manual cleanup.", tag="error")
            # Proceed with cleanup anyway

        # Wait briefly for thread to finish (optional, cleanup happens via _handle_stream_end)
        # if self.stream_thread:
        #    self.stream_thread.join(timeout=1.0)

        # _handle_stream_end will be called via master.after from the receiver loop ending
        # Or we can call it directly here if we want immediate GUI update,
        # but need to be careful not to double-close the socket.
        # Let's rely on the receiver thread triggering the final cleanup.


    def _handle_stream_end(self):
        """Cleans up socket and resets GUI after streaming stops or fails."""
        # This ensures cleanup happens only once and on the main thread
        if not self.is_streaming and self.streaming_socket is None:
            return # Already cleaned up

        self._log_message_threadsafe("Cleaning up stream resources...", tag="status")
        self.is_streaming = False
        self.stop_streaming_flag.set() # Ensure flag is set if called due to error

        if self.stream_thread and self.stream_thread.is_alive():
             # Give thread a moment to exit based on flag
             self.stream_thread.join(timeout=0.5)
        self.stream_thread = None

        if self.streaming_socket:
            sock_to_close = self.streaming_socket
            self.streaming_socket = None # Prevent re-entry
            try:
                # Try receiving final confirmation? (Optional)
                # sock_to_close.settimeout(0.5)
                # final_msg = sock_to_close.recv(1024)
                # self._log_message_threadsafe(f"Final RES< {final_msg.decode().strip()}", tag="response")
                pass
            except: pass # Ignore errors during optional final recv
            finally:
                try:
                    sock_to_close.shutdown(socket.SHUT_RDWR)
                except: pass
                try:
                    sock_to_close.close()
                    self._log_message_threadsafe("Streaming socket closed.", tag="status")
                except Exception as e:
                    self._log_message_threadsafe(f"Error closing streaming socket: {e}", tag="error")

        self._update_gui_for_streaming(False) # Reset GUI state


    def _update_gui_for_streaming(self, is_starting):
        """Enable/disable buttons based on streaming state."""
        state_if_streaming = tk.DISABLED
        state_if_stopped = tk.NORMAL
        stop_button_state = tk.NORMAL if is_starting else tk.DISABLED

        # Buttons/Entries to disable during streaming
        self.led_on_button.config(state=state_if_streaming)
        self.led_off_button.config(state=state_if_streaming)
        self.scan_button.config(state=state_if_streaming)
        self.send_button.config(state=state_if_streaming)
        self.cmd_entry.config(state=state_if_streaming)
        self.ip_entry.config(state=state_if_streaming)
        self.port_entry.config(state=state_if_streaming)

        # Stream control buttons
        self.start_stream_button.config(state=state_if_streaming)
        self.stop_stream_button.config(state=stop_button_state)


    # --- Standard Command Methods (Use execute_non_streaming_command) ---
    def send_led_on(self):
        self.execute_non_streaming_command("turnonled")

    def send_led_off(self):
        self.execute_non_streaming_command("turnoffled")

    def send_scan(self):
        self.execute_non_streaming_command("scan")

    def send_custom_command(self):
        custom_cmd = self.cmd_entry.get().strip()
        if custom_cmd:
            # Check if it's a streaming command (simple check)
            if custom_cmd.lower().startswith("readgyro"):
                 messagebox.showinfo("Info", "Please use the 'Start Gyro Stream' button for streaming commands.")
            else:
                 self.execute_non_streaming_command(custom_cmd)
            self.cmd_entry.delete(0, tk.END)
        else:
            self._log_message_threadsafe("Status: No custom command entered.", tag="status")

    def send_custom_command_event(self, event):
        self.send_custom_command()

    # --- Window Closing Handler ---
    def on_closing(self):
        """Handle window close: stop stream if running."""
        if self.is_streaming:
            self._log_message_threadsafe("Window closing: Stopping stream...", tag="status")
            # Try to gracefully stop, but don't wait too long
            self.stop_streaming_flag.set()
            if self.streaming_socket:
                 try: self.streaming_socket.sendall(b"stop\n")
                 except: pass
            # Give thread a tiny bit of time
            if self.stream_thread and self.stream_thread.is_alive():
                 self.stream_thread.join(0.2)
            # Force close socket if needed
            if self.streaming_socket:
                 try: self.streaming_socket.close()
                 except: pass
        self.master.destroy()

# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = I2CGuiClient(root)
    root.mainloop()