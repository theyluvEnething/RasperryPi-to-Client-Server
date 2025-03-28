import RPi.GPIO as GPIO
import time

# Use BCM GPIO numbers (these match the labels on your breakout board like GPIO17)
GPIO.setmode(GPIO.BCM)

# Define the GPIO pin connected to the LED (via the resistor)
LED_PIN = 5

# Set the LED pin as an output pin
GPIO.setup(LED_PIN, GPIO.OUT)

print("LED test started. Press CTRL+C to exit.")

try:
    while True:
        # --- Turn LED ON (Write HIGH bit) ---
        print("LED ON")
        GPIO.output(LED_PIN, GPIO.HIGH) # Sets GPIO17 to 3.3V
        time.sleep(1) # Keep it on for 1 second

        # --- Turn LED OFF (Write LOW bit) ---
        print("LED OFF")
        GPIO.output(LED_PIN, GPIO.LOW) # Sets GPIO17 to 0V (Ground)
        time.sleep(1) # Keep it off for 1 second

except KeyboardInterrupt:
    # Allows you to exit the loop cleanly with CTRL+C
    print("Exiting program.")

finally:
    # This cleanup step is important! It resets the GPIO pins you've used.
    GPIO.cleanup()
    print("GPIO cleaned up.")