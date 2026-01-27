import pyttsx3
import threading

def speak_message(message):
    """Running TTS in a separate thread to not block the firewall."""
    def _speak():
        try:
            engine = pyttsx3.init()
            engine.setProperty('rate', 160) # Speed
            engine.say(message)
            engine.runAndWait()
        except:
            pass
    
    t = threading.Thread(target=_speak, daemon=True)
    t.start()