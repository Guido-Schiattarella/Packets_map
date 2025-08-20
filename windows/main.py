import webview
import os
import threading
import time
import map
import asyncio
import sys
import multiprocessing
from queue import Empty
import sniffer as sn

stop_event = threading.Event()


class MonitorBuffer:
    def __init__(self):
        self.buffer = None    
        self.full = False     
        self.condition = threading.Condition()

def producer(monitor, packet_queue):
    while not stop_event.is_set():
        try:
            # Get packet from the sniffer process
            packet_received = packet_queue.get(timeout=1.0)
            print(f"[PRODUCER] pacchetto prodotto: {packet_received}")
            
            if packet_received and not monitor.full:
                with monitor.condition:
                    while monitor.full:
                        monitor.condition.wait(timeout=0.5)
                        if stop_event.is_set():
                            return
                   
                    monitor.buffer = packet_received
                    monitor.full = True
                    monitor.condition.notify()
                    
        except Empty:
            # No packet available, continue
            continue
        except Exception as e:
            print(f"Producer error: {e}")
            time.sleep(0.5)

def consumer(monitor, window_ref):
    while not stop_event.is_set():
        with monitor.condition:
            while not monitor.full:
                monitor.condition.wait(timeout=0.5)
                if stop_event.is_set():
                    return
            
            data = monitor.buffer
            print(f"[CONSUMER] pacchetto consumato: {data}")
            try:
                map.packet_listener(window_ref, data)  
            except Exception as e:
                print(f"Consumer error: {e}")
                
            monitor.buffer = None
            monitor.full = False
            monitor.condition.notify()
            print("Ora si può produrre")

if __name__ == '__main__':
    # Required for multiprocessing on Windows
    multiprocessing.freeze_support()
    
    global window
    
    map_template_path = os.path.abspath("map_template.html")
    if not os.path.exists(map_template_path):
        print(f"Errore: File 'map_template.html' non trovato. Assicurati che sia nella stessa cartella.")
        sys.exit(1)
    
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    print("Avvio applicazione...")
    
    window = webview.create_window(
        "Packets Map",
        f"{map_template_path}",
        width=1280,
        height=800
    )
    
    # Create multiprocessing queue and stop event for sniffer
    packet_queue = multiprocessing.Queue()
    sniffer_stop_event = multiprocessing.Event()
    
    # Start the sniffer process
    print("Starting sniffer process...")
    sniffer_process = multiprocessing.Process(
        target=sn.packet_sniffer_process,
        args=(packet_queue, sniffer_stop_event)
    )
    sniffer_process.start()
    
    time.sleep(2)
    try:    
        monitor = MonitorBuffer()
        
        print("inizializzo i thread")
        producer_thread = threading.Thread(target=producer, args=(monitor, packet_queue))
        consumer_thread = threading.Thread(target=consumer, args=(monitor, window))
        
        producer_thread.daemon = True
        consumer_thread.daemon = True
        
        producer_thread.start()
        consumer_thread.start()
        
        webview.start() 
        
    except KeyboardInterrupt as e:
        print("Interruzione da parte dell'utente")
    finally:
        print("Cleaning up...")
        stop_event.set()
        sniffer_stop_event.set()
        
        print("Terminazione dei thread")
        producer_thread.join(timeout=3)
        consumer_thread.join(timeout=3)
        
        print("Terminazione processo sniffer")
        sniffer_process.terminate()
        sniffer_process.join(timeout=5)
        
        if sniffer_process.is_alive():
            print("Force killing sniffer process")
            sniffer_process.kill()
            sniffer_process.join()
            
        print("Cleanup completed")
