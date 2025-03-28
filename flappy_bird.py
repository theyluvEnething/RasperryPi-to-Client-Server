import socket
import ssl
import sys
import traceback
import time
import tkinter as tk
from tkinter import font as tkFont
from tkinter import messagebox
import threading
import random
import queue # For thread-safe communication of accel data

# --- Game Constants ---
WIDTH, HEIGHT = 400, 600
GRAVITY = 0.4
FLAP_STRENGTH = -7  # Negative because Y=0 is top
PIPE_SPEED = -3
PIPE_GAP = 150
PIPE_WIDTH = 60
PIPE_SPAWN_RATE = 120 # Game loop iterations between new pipes
BIRD_X = 50
BIRD_WIDTH, BIRD_HEIGHT = 30, 20
UPDATE_INTERVAL = 30 # Milliseconds (approx 33 FPS)

# --- Sensor/Control Constants ---
# Threshold for Z-acceleration to trigger a flap (relative to resting ~1g)
# Adjust this based on testing! Start high, then lower it.
ACCEL_FLAP_THRESHOLD = 1.3 # e.g., flap if Z > 1.3g
FLAP_COOLDOWN = 8 # Game loop iterations cooldown after a flap

# --- Network Configuration ---
DEFAULT_SERVER_ADDRESS = "172.20.10.3" # Replace with your Pi's IP
DEFAULT_SERVER_PORT = 12345
CONNECTION_TIMEOUT = 5.0
STREAM_RECV_TIMEOUT = 0.5 # Timeout for recv() inside the streaming loop

# --- Game State Enum ---
class GameState:
    START = 0
    PLAYING = 1
    GAME_OVER = 2

# --- Main Game Class ---
class FlappyAccelGame:
    def __init__(self, master):
        self.master = master
        master.title("Flappy Accelerometer")
        master.geometry(f"{WIDTH}x{HEIGHT+50}") # Extra space for controls/status
        master.resizable(False, False)
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # --- Network/Sensor State ---
        self.is_connected = False
        self.streaming_socket = None
        self.stream_thread = None
        self.stop_streaming_flag = threading.Event()
        self.accel_queue = queue.Queue(maxsize=5) # Queue to pass Z accel data
        self.last_z_accel = 1.0 # Initialize near resting

        # --- Game State ---
        self.game_state = GameState.START
        self.bird_y = HEIGHT // 2
        self.bird_velocity = 0
        self.pipes = [] # List of pipe rectangles [top_rect_id, bottom_rect_id, x_pos]
        self.score = 0
        self.frames_since_pipe = 0
        self.flap_cooldown_counter = 0

        # --- GUI Elements ---
        self.setup_gui()

        # Start game loop
        self.game_loop()

    def setup_gui(self):
        default_font = tkFont.nametofont("TkDefaultFont")
        default_font.configure(size=10)
        self.master.option_add("*Font", default_font)

        # Control Frame
        control_frame = tk.Frame(self.master, pady=5)
        control_frame.pack(side=tk.TOP, fill=tk.X)

        self.ip_entry = tk.Entry(control_frame, width=15)
        self.ip_entry.insert(0, DEFAULT_SERVER_ADDRESS)
        self.port_entry = tk.Entry(control_frame, width=6)
        self.port_entry.insert(0, str(DEFAULT_SERVER_PORT))

        self.connect_button = tk.Button(control_frame, text="Connect", command=self.connect_and_start_stream)
        self.disconnect_button = tk.Button(control_frame, text="Disconnect", command=self.disconnect_stream, state=tk.DISABLED)

        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.connect_button.pack(side=tk.LEFT, padx=5)
        self.disconnect_button.pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(control_frame, text="Status: Disconnected", fg="red", anchor="w")
        self.status_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # Game Canvas
        self.canvas = tk.Canvas(self.master, width=WIDTH, height=HEIGHT, bg="#70c5ce") # Sky blue
        self.canvas.pack(side=tk.TOP)

        # Score Display (on canvas)
        self.score_text_id = self.canvas.create_text(WIDTH / 2, 50, text="Score: 0", fill="white", font=("Arial", 24, "bold"))

        # Bird Graphics (simple rectangle)
        self.bird_id = self.canvas.create_rectangle(0, 0, 0, 0, fill="#fafa00", outline="black") # Yellow bird
        self.update_bird_position()

        # Message Text (Start/Game Over)
        self.message_text_id = self.canvas.create_text(WIDTH / 2, HEIGHT / 3, text="", fill="white", font=("Arial", 28, "bold"), state=tk.HIDDEN)

    def update_status(self, text, is_connected):
        color = "darkgreen" if is_connected else "red"
        self.status_label.config(text=f"Status: {text}", fg=color)
        self.connect_button.config(state=tk.DISABLED if is_connected else tk.NORMAL)
        self.disconnect_button.config(state=tk.NORMAL if is_connected else tk.DISABLED)
        self.ip_entry.config(state=tk.DISABLED if is_connected else tk.NORMAL)
        self.port_entry.config(state=tk.DISABLED if is_connected else tk.NORMAL)

    # --- Network Methods ---
    def connect_and_start_stream(self):
        if self.is_connected: return

        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        if not ip or not port_str.isdigit():
            messagebox.showerror("Error", "Invalid IP or Port.")
            return
        port = int(port_str)

        self.update_status("Connecting...", False)
        # Run connect/start in background thread
        thread = threading.Thread(target=self._connect_thread_target, args=(ip, port), daemon=True)
        thread.start()

    def _connect_thread_target(self, ip, port):
        sock = None
        sslsock = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE # INSECURE
            self.master.after(0, self.update_status, f"Connecting to {ip}:{port}...", False)
            sock = socket.create_connection((ip, port), timeout=CONNECTION_TIMEOUT)
            sslsock = context.wrap_socket(sock, server_hostname=ip)
            self.master.after(0, self.update_status, f"Connected. Sending readaccel...", True)

            # --- Send command to start ACCEL stream ---
            command = "readaccel\n" # Ensure newline
            sslsock.sendall(command.encode('utf-8'))

            # --- Receive initial confirmation ---
            sslsock.settimeout(RECEIVE_TIMEOUT)
            response_bytes = sslsock.recv(1024) # Expect "OK Starting..."
            response_str = response_bytes.decode('utf-8').strip()

            if "ok" in response_str.lower() and "starting" in response_str.lower():
                 self.master.after(0, self.update_status, "Streaming Accelerometer Data", True)
                 # --- Success - Start receiver thread ---
                 self.streaming_socket = sslsock
                 self.is_connected = True
                 self.stop_streaming_flag.clear()
                 self.stream_thread = threading.Thread(target=self._stream_receiver_loop, daemon=True)
                 self.stream_thread.start()
                 # Start game if not already playing
                 self.master.after(0, self.start_game) # Schedule game start on main thread
            else:
                raise Exception(f"Server rejected stream start: {response_str}")

        except Exception as e:
            self.master.after(0, self.update_status, f"Connection Failed: {e}", False)
            if sslsock: try: sslsock.close()
            except: pass
            elif sock: try: sock.close()
            except: pass
            self.streaming_socket = None
            self.is_connected = False

    def _stream_receiver_loop(self):
        sslsock = self.streaming_socket
        if not sslsock: return
        buffer = b""
        self._log_status_threadsafe("Stream receiver thread started.")

        while not self.stop_streaming_flag.is_set():
            try:
                sslsock.settimeout(STREAM_RECV_TIMEOUT)
                chunk = sslsock.recv(1024)
                if not chunk:
                    self._log_status_threadsafe("Stream connection closed by server.")
                    self.stop_streaming_flag.set()
                    break
                buffer += chunk
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    try:
                        decoded_line = line.decode('utf-8').strip()
                        if decoded_line.startswith("ACCEL"):
                            # Parse ACCEL X: Y: Z:
                            parts = decoded_line.split()
                            z_val = 1.0 # Default
                            for part in parts:
                                if part.startswith("Z:"):
                                    try: z_val = float(part[2:])
                                    except ValueError: pass
                                    break # Found Z
                            # Put the Z value in the queue (non-blocking)
                            try: self.accel_queue.put_nowait(z_val)
                            except queue.Full: pass # Ignore if queue is full
                    except UnicodeDecodeError: pass # Ignore bad data
            except socket.timeout:
                continue # Normal, check stop flag
            except Exception as e:
                self._log_status_threadsafe(f"Stream error: {e}")
                self.stop_streaming_flag.set()
                break

        self._log_status_threadsafe("Stream receiver thread finished.")
        self.master.after(0, self._handle_disconnect) # Ensure cleanup on main thread

    def disconnect_stream(self):
        if not self.is_connected: return
        self._log_status_threadsafe("Disconnecting...")
        self.stop_streaming_flag.set() # Signal thread
        if self.streaming_socket:
            try: self.streaming_socket.sendall(b"stop\n") # Ask server to stop
            except: pass
        # Cleanup will happen via _handle_disconnect called from receiver thread exit

    def _handle_disconnect(self):
         # Ensures cleanup runs on main thread and only once
        if not self.is_connected and self.streaming_socket is None: return

        was_connected = self.is_connected
        self.is_connected = False
        self.stop_streaming_flag.set()

        if self.stream_thread and self.stream_thread.is_alive():
            self.stream_thread.join(timeout=0.5)
        self.stream_thread = None

        if self.streaming_socket:
            sock_to_close = self.streaming_socket
            self.streaming_socket = None
            try: sock_to_close.shutdown(socket.SHUT_RDWR)
            except: pass
            try: sock_to_close.close()
            except: pass
            if was_connected: self._log_status_threadsafe("Disconnected.")

        # Clear the queue
        while not self.accel_queue.empty():
            try: self.accel_queue.get_nowait()
            except queue.Empty: break

        # Reset game state if we disconnected unexpectedly during play
        if self.game_state == GameState.PLAYING:
             self.game_state = GameState.START # Go back to start screen
             self.reset_game()


    def _log_status_threadsafe(self, message):
        # Helper to update status label from threads
        self.master.after(0, self.update_status, message, self.is_connected)

    # --- Game Logic Methods ---
    def reset_game(self):
        self.bird_y = HEIGHT // 2
        self.bird_velocity = 0
        self.score = 0
        self.frames_since_pipe = 0
        self.flap_cooldown_counter = 0
        # Clear existing pipes from canvas and list
        for top_id, bottom_id, _ in self.pipes:
            self.canvas.delete(top_id)
            self.canvas.delete(bottom_id)
        self.pipes = []
        self.canvas.itemconfig(self.score_text_id, text="Score: 0")
        self.canvas.itemconfig(self.message_text_id, state=tk.HIDDEN)
        self.update_bird_position()

    def start_game(self):
        if self.game_state != GameState.PLAYING and self.is_connected:
            self.reset_game()
            self.game_state = GameState.PLAYING
            self.canvas.itemconfig(self.message_text_id, state=tk.HIDDEN)

    def game_over(self):
        self.game_state = GameState.GAME_OVER
        self.canvas.itemconfig(self.message_text_id, text=f"GAME OVER\nScore: {self.score}\nFlap Z > {ACCEL_FLAP_THRESHOLD:.1f}g to Restart", state=tk.NORMAL)
        # Stop stream on game over? Optional. For now, keep streaming.
        # self.disconnect_stream()


    def flap(self):
        if self.game_state == GameState.PLAYING and self.flap_cooldown_counter <= 0:
            self.bird_velocity = FLAP_STRENGTH
            self.flap_cooldown_counter = FLAP_COOLDOWN # Start cooldown
        elif self.game_state == GameState.START and self.is_connected:
             self.start_game()
        elif self.game_state == GameState.GAME_OVER:
             # Require a flap to restart
             self.start_game()


    def update_bird_position(self):
        x0 = BIRD_X - BIRD_WIDTH / 2
        y0 = self.bird_y - BIRD_HEIGHT / 2
        x1 = BIRD_X + BIRD_WIDTH / 2
        y1 = self.bird_y + BIRD_HEIGHT / 2
        self.canvas.coords(self.bird_id, x0, y0, x1, y1)

    def spawn_pipe(self):
        gap_y = random.randint(PIPE_GAP // 2 + 50, HEIGHT - PIPE_GAP // 2 - 50)
        x = WIDTH

        # Top Pipe
        y0_top = 0
        y1_top = gap_y - PIPE_GAP // 2
        top_id = self.canvas.create_rectangle(x, y0_top, x + PIPE_WIDTH, y1_top, fill="green", outline="black")

        # Bottom Pipe
        y0_bottom = gap_y + PIPE_GAP // 2
        y1_bottom = HEIGHT
        bottom_id = self.canvas.create_rectangle(x, y0_bottom, x + PIPE_WIDTH, y1_bottom, fill="green", outline="black")

        self.pipes.append([top_id, bottom_id, x]) # Store IDs and x-position

    def move_objects(self):
        # Bird physics
        self.bird_velocity += GRAVITY
        self.bird_y += self.bird_velocity
        self.update_bird_position()

        # Update flap cooldown
        if self.flap_cooldown_counter > 0:
            self.flap_cooldown_counter -= 1

        # Pipe movement & spawning
        pipes_to_remove = []
        scored_this_frame = False
        for i in range(len(self.pipes)):
            top_id, bottom_id, x_pos = self.pipes[i]
            new_x = x_pos + PIPE_SPEED
            self.canvas.move(top_id, PIPE_SPEED, 0)
            self.canvas.move(bottom_id, PIPE_SPEED, 0)
            self.pipes[i][2] = new_x # Update stored x-position

            # Check for score
            pipe_right_edge = new_x + PIPE_WIDTH
            if pipe_right_edge < BIRD_X and not scored_this_frame:
                # Check if this pipe hasn't been scored yet (needs better tracking, but good enough for simple version)
                # Simple check: if the previous pipe (if any) is far enough left
                is_new_score = True
                if i > 0:
                    prev_pipe_right_edge = self.pipes[i-1][2] + PIPE_WIDTH
                    if prev_pipe_right_edge > BIRD_X - PIPE_WIDTH: # Avoid double scoring
                       is_new_score = False

                if is_new_score:
                    self.score += 1
                    self.canvas.itemconfig(self.score_text_id, text=f"Score: {self.score}")
                    scored_this_frame = True # Prevent scoring multiple pipes in one frame


            # Check for removal
            if new_x + PIPE_WIDTH < 0:
                pipes_to_remove.append(i)

        # Remove off-screen pipes
        for index in sorted(pipes_to_remove, reverse=True):
            top_id, bottom_id, _ = self.pipes.pop(index)
            self.canvas.delete(top_id)
            self.canvas.delete(bottom_id)

        # Spawn new pipes
        self.frames_since_pipe += 1
        if self.frames_since_pipe >= PIPE_SPAWN_RATE:
            self.spawn_pipe()
            self.frames_since_pipe = 0

    def check_collisions(self):
        bird_coords = self.canvas.coords(self.bird_id)
        if not bird_coords: return False # Bird not drawn yet
        bx0, by0, bx1, by1 = bird_coords

        # Ground/Ceiling collision
        if by1 > HEIGHT or by0 < 0:
            return True

        # Pipe collision
        for top_id, bottom_id, _ in self.pipes:
            # Check overlap with top pipe
            if self.check_overlap(bird_coords, self.canvas.coords(top_id)):
                return True
            # Check overlap with bottom pipe
            if self.check_overlap(bird_coords, self.canvas.coords(bottom_id)):
                return True

        return False

    def check_overlap(self, coords1, coords2):
        # Simple rectangle overlap check
        if not coords1 or not coords2 or len(coords1) < 4 or len(coords2) < 4:
            return False
        x0_1, y0_1, x1_1, y1_1 = coords1
        x0_2, y0_2, x1_2, y1_2 = coords2
        return x0_1 < x1_2 and x1_1 > x0_2 and y0_1 < y1_2 and y1_1 > y0_2


    # --- Main Game Loop ---
    def game_loop(self):
        # --- Process Sensor Input ---
        try:
            # Get the latest Z accel value from the queue (non-blocking)
            self.last_z_accel = self.accel_queue.get_nowait()
            # Check for flap condition
            if self.last_z_accel > ACCEL_FLAP_THRESHOLD:
                self.flap()
        except queue.Empty:
            pass # No new data, use last value (or handle differently if needed)


        # --- Update Game State ---
        if self.game_state == GameState.PLAYING:
            self.move_objects()
            if self.check_collisions():
                self.game_over()
        elif self.game_state == GameState.START:
             if not self.is_connected:
                 self.canvas.itemconfig(self.message_text_id, text="Connect to Server\nto Start", state=tk.NORMAL)
             else:
                 self.canvas.itemconfig(self.message_text_id, text=f"Flap Z > {ACCEL_FLAP_THRESHOLD:.1f}g\nto Start", state=tk.NORMAL)
        elif self.game_state == GameState.GAME_OVER:
            # Logic handled by flap() checking game state
            pass

        # Schedule next loop iteration
        self.master.after(UPDATE_INTERVAL, self.game_loop)

    # --- Window Closing Handler ---
    def on_closing(self):
        self.stop_streaming_flag.set() # Signal thread
        if self.streaming_socket:
            try: self.streaming_socket.sendall(b"stop\n")
            except: pass
            time.sleep(0.1) # Give server a moment
            try: self.streaming_socket.close()
            except: pass
        self.master.destroy()

# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    game = FlappyAccelGame(root)
    root.mainloop()