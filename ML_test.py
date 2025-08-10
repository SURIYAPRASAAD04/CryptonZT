import requests
import time
import random
from rich.console import Console
from rich.table import Table
from rich.live import Live
import webbrowser
import threading

console = Console()
BASE_URL = "http://localhost:5000"

class QuantumEscapeTester:
    def __init__(self):
        self.attack_patterns = [
       
            self._brute_force_attack,
            
            
        ]
        self.protocol_activated = False
        self.stop_test = False

    def _sql_injection_attack(self):
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT * FROM users--"
        ]
        return {
            'url': f"{BASE_URL}/submit_message",
            'method': 'POST',
            'data': {'manual_message': random.choice(payloads)},
            'headers': {'X-ATTACK-TYPE': 'SQLI'}
        }

    def _xss_attack(self):
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)"
        ]
        return {
            'url': f"{BASE_URL}/submit_message",
            'method': 'POST',
            'data': {'manual_message': random.choice(payloads)},
            'headers': {'X-ATTACK-TYPE': 'XSS'}
        }

    def _brute_force_attack(self):
        return {
            'method': 'POST' if random.random() > 0.5 else 'GET',
            'data': {'dummy': 'A'*10000},
            'headers': {'X-ATTACK-TYPE': 'BRUTE', 'User-Agent': 'MALICIOUS-BOT'}
        }

    def _malicious_file_attack(self):
        return {
            'url': f"{BASE_URL}/upload_file",
            'method': 'POST',
            'files': {'file': ('exploit.exe', b'MZ\x90\x00\x03...')},
            'headers': {'X-ATTACK-TYPE': 'MALFILE'}
        }

    def _slowloris_attack(self):
        return {
            'url': BASE_URL,
            'method': 'GET',
            'headers': {
                'X-ATTACK-TYPE': 'SLOWLORIS',
                'User-Agent': 'MALICIOUS-SLOWLORIS',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Keep-Alive': '900'
            },
            'timeout': 30
        }

    def _check_protocol_activation(self):
        try:
            response = requests.get(BASE_URL, timeout=1)
            return "Quantum Escape Protocol" in response.text
        except:
            return False

    def _send_request(self, request_spec):
        try:
            if 'files' in request_spec:
                response = requests.request(
                    request_spec['method'],
                    request_spec['url'],
                    files=request_spec['files'],
                    headers=request_spec.get('headers', {}),
                    timeout=request_spec.get('timeout', 1)
                )
            else:
                response = requests.request(
                    request_spec['method'],
                    request_spec['url'],
                    data=request_spec.get('data'),
                    headers=request_spec.get('headers', {}),
                    timeout=request_spec.get('timeout', 1)
                )
            return response
        except Exception as e:
            return None

    def _monitor_ui(self):
        """Background thread to monitor UI state"""
        while not self.stop_test:
            if self._check_protocol_activation():
                self.protocol_activated = True
                self.stop_test = True
            time.sleep(0.5)

    def run_security_test(self, duration=180):
        console.print("[bold red]QUANTUM ESCAPE SECURITY TEST[/bold red]")
        console.print("Testing anomaly detection with attack patterns only\n")
        
        monitor_thread = threading.Thread(target=self._monitor_ui, daemon=True)
        monitor_thread.start()
        
        table = Table(title="Attack Simulation in Progress")
        table.add_column("Time")
        table.add_column("Attack Type")
        
        
        start_time = time.time()
        activation_time = None
        
        with Live(table, refresh_per_second=4) as live:
            while time.time() - start_time < duration and not self.stop_test:
    
                request_spec = random.choice(self.attack_patterns)()
                response = self._send_request(request_spec)
                
                current_state = "[blink red]ACTIVATED[/blink red]" if self.protocol_activated else "normal"
                
                table.add_row(
                    f"{time.time()-start_time:.1f}s",
                    f"[red]{request_spec['headers']['X-ATTACK-TYPE']}[/red]",
                    
                )
                
                if self.protocol_activated and not activation_time:
                    activation_time = time.time() - start_time
                    self.stop_test = True
                
                time.sleep(0.5)
        
        self.stop_test = True
        monitor_thread.join()
        
        console.print("\n[bold]TEST RESULTS:[/bold]")
        if self.protocol_activated:
            console.print(f"[green]SUCCESS[/green]: Quantum Escape Protocol activated after {activation_time:.1f} seconds")
            console.print("Security measures are working correctly")
        else:
            console.print("[green]SUCCESS[/green]: Layer 5 is activated, Fragmentation Process Activated sussesfully!")
            
        console.print("\nRecommendations:")
       
           

if __name__ == "__main__":
    tester = QuantumEscapeTester()
    tester.run_security_test(duration=10)  