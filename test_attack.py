import requests
import time
import random
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()
BASE_URL = "http://localhost:5000"

def generate_abnormal_traffic():
    """Generate traffic that should trigger anomalies"""
    abnormal_agents = [
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)'
    ]
    
    params = [
        {'exploit': '1'*10000},
        {'malicious': 'true', 'payload': 'xss_attempt'},
        {'id': "' OR 1=1--"}
    ]
    
    while True:
        try:
            if random.random() > 0.7:  
                response = requests.get(
                    BASE_URL,
                    headers={'User-Agent': random.choice(abnormal_agents)},
                    params=random.choice(params),
                    timeout=1
                )
                yield {
                    "type": "ABNORMAL",
                    "status": response.status_code,
                    "redirected": "activate" in response.url,
                    "response_time": response.elapsed.total_seconds()
                }
            else:
                response = requests.get(BASE_URL, timeout=1)
                yield {
                    "type": "normal",
                    "status": response.status_code,
                    "redirected": False,
                    "response_time": response.elapsed.total_seconds()
                }
        except Exception as e:
            yield {
                "type": "error",
                "message": str(e)
            }
        time.sleep(0.5)  

def monitor_ui_response():
    """Check if UI shows security alerts"""
    try:
        response = requests.get(f"{BASE_URL}/")
        return "Quantum Escape Protocol" in response.text
    except:
        return False

def run_test(duration=120):
    """Run test with live dashboard"""
    console.print("[bold green]Starting Anomaly Detection Test[/bold green]")
    console.print("Observe the Flask UI in your browser during this test")
    
    table = Table(title="Anomaly Test Progress")
    table.add_column("Request #")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Redirected")
    table.add_column("Response Time")
    table.add_column("UI State")
    
    start_time = time.time()
    request_count = 0
    anomalies_detected = 0
    
    traffic_gen = generate_abnormal_traffic()
    
    with Live(table, refresh_per_second=4) as live:
        while time.time() - start_time < duration:
            request_count += 1
            result = next(traffic_gen)
            ui_state = monitor_ui_response()
            
            if result.get('type', '').upper() == "ABNORMAL" and result.get('redirected'):
                anomalies_detected += 1
                table.add_row(
                    str(request_count),
                    f"[red]{result['type']}[/red]",
                    str(result['status']),
                    "[green]YES[/green]" if result['redirected'] else "[red]NO[/red]",
                    f"{result['response_time']:.3f}s",
                    "[blink]ACTIVATED[/blink]" if ui_state else "normal"
                )
            else:
                table.add_row(
                    str(request_count),
                    result['type'],
                    str(result.get('status', '')),
                    str(result.get('redirected', '')),
                    f"{result.get('response_time', 0):.3f}s" if 'response_time' in result else "",
                    "[yellow]ALERT[/yellow]" if ui_state else "normal"
                )
            
            if request_count % 10 == 0:
                live.update(table)
    
    console.print(f"\n[bold]Test Complete:[/bold]")
    console.print(f"Total requests: {request_count}")
    console.print(f"Anomalies detected: {anomalies_detected}")
    console.print(f"UI activations: {sum(1 for _ in range(10) if monitor_ui_response())}")

if __name__ == "__main__":
    run_test()