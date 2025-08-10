import requests
import time
from threading import Thread


TARGET_URL = "http://127.0.0.1:5000"  
LOGIN_URL = f"{TARGET_URL}/login"
PROTECTED_ENDPOINTS = ["/encryption", "/decryption", "/managedata"]

NUM_THREADS = 5  
REQUESTS_PER_THREAD = 20 
DELAY_BETWEEN_REQUESTS = 0.1 

def send_malicious_request(thread_id):
    """Simulate brute-force behavior"""
    session = requests.Session()
    for i in range(REQUESTS_PER_THREAD):
        try:
            if i % 2 == 0:
                response = session.post(
                    LOGIN_URL,
                    data={"email": "attacker@example.com", "password": "password123"},
                    headers={"X-Malicious-Attempt": "true"}  
                )
            else:
                endpoint = PROTECTED_ENDPOINTS[i % len(PROTECTED_ENDPOINTS)]
                response = session.get(f"{TARGET_URL}{endpoint}")

            print(f"Thread {thread_id}, Request {i}: Status {response.status_code}")
            
            if response.status_code == 302 and "activate" in response.headers.get("Location", ""):
                print(f"[!] THREAD {thread_id}: QUANTUM ESCAPE TRIGGERED!")
                break

        except Exception as e:
            print(f"Thread {thread_id} error: {str(e)}")
        
        time.sleep(DELAY_BETWEEN_REQUESTS)

if __name__ == "__main__":
    print(f"[*] Starting {NUM_THREADS} attack threads...")
    threads = []
    for i in range(NUM_THREADS):
        t = Thread(target=send_malicious_request, args=(i,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    print("[*] Attack simulation complete.")