# run.py
from loggs import register_on_incident_opened, repl
from main import handle_incident_opened_event

if __name__ == "__main__":
    # 1. Register the in-memory agent callback
    register_on_incident_opened(handle_incident_opened_event)
    
    # 2. Start the interactive console / application
    repl()