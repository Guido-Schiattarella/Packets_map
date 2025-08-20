import webview
import os
import threading
import time
import sniffer as sn
import map

stop_event = threading.Event()  


class MonitorBuffer:
    def __init__(self):
        self.buffer = None    
        self.full = False     
        self.condition = threading.Condition()

def producer(monitor):

    while not stop_event.is_set():
        packet_received = sn.sniffer()
        print(f"[PRODUCER] pacchetto prodotto: {packet_received}")
        if monitor.full:
            packet_received = ""

        if packet_received:
            #print(f"Ricevuto: {decoded}")

            with monitor.condition:
                
                while monitor.full:
                    monitor.condition.wait(timeout=0.5)
                    if stop_event.is_set():
                        return
               
                monitor.buffer = packet_received
                monitor.full = True
                #print(f"Prodotto: {decoded}")
                monitor.condition.notify()
        else:
            time.sleep(0.1)

def consumer(monitor, window_ref):
    while not stop_event.is_set():
        with monitor.condition:
            
            while not monitor.full:
                monitor.condition.wait(timeout=0.5)
                if stop_event.is_set():
                    return
            
            data = monitor.buffer
            print(f"[CONSUMER] pacchetto consumato: {data}")
            #print(f"Consumato: {data}")
            map.packet_listener(window_ref, data)  
            monitor.buffer = None
            monitor.full = False
            monitor.condition.notify()
            print("Ora si può produrre")


if __name__ == '__main__':

    """
    Avvia la finestra e il thread di aggiornamento.
    """
    global window
    
    
    map_template_path = os.path.abspath("map_template.html")
    if not os.path.exists(map_template_path):
        print(f"Errore: File 'map_template.html' non trovato. Assicurati che sia nella stessa cartella.")
        sys.exit(1)

    print("Avvio applicazione...")
    
    window = webview.create_window(
        "Packets Map",
        f"{map_template_path}",
        width=1280,
        height=800
    )

    
    time.sleep(2)

    try:    

       
        monitor = MonitorBuffer()

        
        print("inizializzo i thread")
        producer_thread = threading.Thread(target=producer, args=(monitor,))
        consumer_thread = threading.Thread(target=consumer, args=(monitor, window))
        
        producer_thread.start()
        consumer_thread.start()

        webview.start() 
    except KeyboardInterrupt as e:
        print("Interruzione da parte dell'utente")
    finally:
        
        stop_event.set()
        print("Terminazione dei thread")

        
        producer_thread.join()
        consumer_thread.join()
    
