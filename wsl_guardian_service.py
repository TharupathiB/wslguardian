"""
WSL Guardian Service - FIXED VERSION 34
Continuously monitors WSL for unauthorized commands with improved pattern matching
All Rights Reserved
NEXUS GUARD
"""

import os
import sys
import time
import psutil
import signal
import re
import logging
import argparse
import subprocess
import win32serviceutil
import win32service
import win32event
import servicemanager
from datetime import datetime
from threading import Thread, Event

# Configure logging
LOG_FILE = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'WSLGuardian', 'wsl_guardian.log')
LOG_DIR = os.path.dirname(LOG_FILE)

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('wsl_guardian')

# List of unauthorized commands that will trigger termination
# Each entry is a dictionary with the command name and pattern to match
UNAUTHORIZED_COMMANDS = [
    {"name": "nmap", "pattern": r"\bnmap\b"},  # Word boundary for exact match
    {"name": "nc", "pattern": r"\bnc\b"},      # Match exactly "nc" as a word
    {"name": "netcat", "pattern": r"\bnetcat\b"}, #terminates whenever the command line detect netcat as a whole
    {"name": "curl", "pattern": r"\bcurl\b"},
    {"name": "wget", "pattern": r"\bwget\b"},
    {"name": "tcpdump", "pattern": r"\btcpdump\b"}, #packet spamming is terminated
    {"name": "wireshark", "pattern": r"\bwireshark\b"},
    {"name": "hashcat", "pattern": r"\bhashcat\b"},
    {"name": "hydra", "pattern": r"\bhydra\b"},
    {"name": "john", "pattern": r"\bjohn\s+\w+\b"},  # Match "john" followed by parameters
    {"name": "mimikatz", "pattern": r"\bmimikatz\b"},
    {"name": "crackmapexec", "pattern": r"\bcrackmapexec\b"},
    {"name": "metasploit", "pattern": r"\bmetasploit\b"},
    {"name": "msfconsole", "pattern": r"\bmsfconsole\b"},
    {"name": "msfvenom", "pattern": r"\bmsfvenom\b"},
    {"name": "powershell -e", "pattern": r"\bpowershell\s+(-|/)e\b"},  # Match powershell with -e flag
    {"name": "base64 encode/decode", "pattern": r"\bbase64\s+(-d|--decode)\b"},  # Match base64 with decode flags
    {"name": "certutil decode", "pattern": r"\bcertutil\s+(-decode|-decodehex)\b"}  # Match certutil with decode flags
]

class WSLGuardian:
    """Main WSL monitoring and protection class"""
    
    def __init__(self):
        """Initialize the WSL Guardian"""
        self.wsl_processes = {}  # Track WSL processes
        self.running = True
        self.stop_event = Event()
        
        # Create directory for detailed logs
        self.detailed_log_dir = os.path.join(LOG_DIR, 'detailed_logs')
        if not os.path.exists(self.detailed_log_dir):
            os.makedirs(self.detailed_log_dir)
        
        logger.info("WSL Guardian initialized")
        logger.info(f"Monitoring for {len(UNAUTHORIZED_COMMANDS)} unauthorized commands")
        
    def log_detailed(self, pid, message):
        """Log detailed information about a specific WSL process"""
        try:
            log_file = os.path.join(self.detailed_log_dir, f'wsl_process_{pid}.log')
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(log_file, 'a') as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception as e:
            logger.error(f"Error writing detailed log for PID {pid}: {e}")
            
    def terminate_wsl(self, pid, reason):
        """Forcefully terminate a WSL process"""
        logger.warning(f"TERMINATING WSL [{pid}] - Reason: {reason}")
        
        self.log_detailed(pid, f"TERMINATION TRIGGERED: {reason}")
        
        # Try multiple termination methods to ensure it's killed
        try:
            # Method 1: taskkill (Windows specific)
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                          check=True, capture_output=True)
            logger.info(f"Successfully terminated process {pid} using taskkill")
            return True
        except Exception as e:
            logger.warning(f"Error with taskkill: {e}")
            
        try:
            # Method 2: psutil
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
            logger.info(f"Successfully terminated process {pid} using psutil")
            return True
        except Exception as e:
            logger.warning(f"Error with psutil termination: {e}")
            
        try:
            # Method 3: kill signal
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            if psutil.pid_exists(pid):
                os.kill(pid, signal.SIGKILL) #Signal terminates
            logger.info(f"Successfully terminated process {pid} with kill signal")
            return True
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
            
        # Final attempt: extreme measure - 'wsl --terminate'
        try:
            subprocess.run(['wsl', '--terminate'], 
                          check=False, capture_output=True)
            logger.info("Executed 'wsl --terminate' as final termination attempt")
        except Exception as e:
            logger.error(f"Error with wsl --terminate: {e}")
            
        return False
    
    def check_for_unauthorized_commands(self, text):
        
        """
        Check if text contains any unauthorized commands using regex patterns
        Returns (found, command_name) tuple
        check for comman usage pattern
        """
        
        if not text:
            return False, None
            
        for cmd in UNAUTHORIZED_COMMANDS:
            if re.search(cmd["pattern"], text):
                return True, cmd["name"]
                
        return False, None
            
    def check_process_commands(self, pid):
        """Check commands running in a WSL process"""
        try:
         
            result = subprocess.run(
                f'wsl -p {pid} ps aux', 
                shell=True, 
                capture_output=True, 
                text=True, 
                check=False
                   # First try to use wsl -p to specify the WSL instance
            )
            
            # If that didn't work, try general WSL command
            if result.returncode != 0:
                result = subprocess.run(
                    ['wsl', 'ps', 'aux','ls'], 
                    capture_output=True, 
                    text=True, 
                    check=False
                )
            
            output = result.stdout.lower()
            
            # Only log if we actually got some output
            if output and len(output) > 10:
                self.log_detailed(pid, f"Process list:\n{output}")
            
                # Check for unauthorized commands in process output
                found, cmd_name = self.check_for_unauthorized_commands(output)
                if found:
                    logger.warning(f"Unauthorized command detected: {cmd_name}")
                    self.terminate_wsl(pid, f"Unauthorized command: {cmd_name}")
                    return True
            
            # Monitor command history file for additional detection
            try:
                # First try .bash_history
                result = subprocess.run(
                    f'wsl -p {pid} cat ~/.bash_history 2>/dev/null || wsl -p {pid} cat ~/.zsh_history 2>/dev/null', 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    check=False
                )
                
                if result.returncode == 0 and result.stdout:
                    history = result.stdout.lower()
                    
                    # Only log if there's substantial history
                    if len(history) > 10:
                        self.log_detailed(pid, f"Command history (last 10 lines):\n{history.splitlines()[-10:]}")
                    
                    # Check the last few commands in history
                    for line in history.splitlines()[-10:]:  # Last 10 commands
                        found, cmd_name = self.check_for_unauthorized_commands(line)
                        if found:
                            logger.warning(f"Unauthorized command in history: {line}")
                            self.terminate_wsl(pid, f"Unauthorized command in history: {cmd_name} ({line})")
                            return True
            except Exception as e:
                logger.debug(f"Error checking command history: {e}")
                
            return False
        except Exception as e:
            logger.error(f"Error checking WSL process {pid}: {e}")
            return False
            
    def find_wsl_processes(self):
        """Find all WSL processes"""
        current_processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check for WSL processes
                proc_name = proc.info['name'].lower()
                if 'wsl' in proc_name or 'bash' in proc_name:
                    pid = proc.info['pid']
                    cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                    
                    current_processes[pid] = {
                        'pid': pid,
                        'name': proc.info['name'],
                        'cmdline': cmdline,
                        'first_seen': self.wsl_processes.get(pid, {}).get('first_seen', datetime.now()),
                        'last_checked': datetime.now()
                    }
                    
                    # Log new WSL processes
                    if pid not in self.wsl_processes:
                        logger.info(f"New WSL process detected: PID={pid}, CMD={cmdline}")
                        self.log_detailed(pid, f"Process started: {cmdline}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        # Check for terminated processes
        for pid in list(self.wsl_processes.keys()):
            if pid not in current_processes:
                logger.info(f"WSL process terminated: PID={pid}")
                self.log_detailed(pid, "Process terminated")
                
        self.wsl_processes = current_processes
        return current_processes
            
    def monitor_wsl(self):
        logger.info("Starting WSL monitoring")

        while not self.stop_event.is_set():
            try:
                processes = self.find_wsl_processes()

                # If no WSL processes are running, wait and retry
                if not processes:
                    logger.debug("No WSL processes found, sleeping...")
                    time.sleep(2)
                    continue

                for pid, info in processes.items():
                    if self.stop_event.is_set():
                        break
                    self.check_process_commands(pid)

                time.sleep(1)

            except Exception as e:
                logger.error(f"[Monitoring Error] {e}")
                time.sleep(5)


    def start(self):
        """Start the WSL guardian monitor"""
        logger.info("Starting WSL Guardian")
        self.stop_event.clear()
        self.running = True
        
        # Start monitoring thread
        monitor_thread = Thread(target=self.monitor_wsl)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return monitor_thread
        
    def stop(self):
        """Stop the WSL guardian monitor"""
        logger.info("Stopping WSL Guardian")
        self.stop_event.set()
        self.running = False
        

class WSLGuardianService(win32serviceutil.ServiceFramework):
    """Windows Service wrapper for WSL Guardian"""
    
    _svc_name_ = "WSLGuardian"
    _svc_display_name_ = "WSL Guardian Service"
    _svc_description_ = "Monitors WSL for unauthorized commands and terminates instances if detected"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.guardian = WSLGuardian()
        self.monitor_thread = None
        
    def SvcStop(self):
        """Stop the service"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        
        # Signal the guardian to stop
        if self.guardian:
            self.guardian.stop()
            
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)
        
    def SvcDoRun(self):
        """Run the service"""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        # Start the guardian
        self.monitor_thread = self.guardian.start()
        
        # Wait for service stop signal
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="WSL Guardian - Monitors and terminates unauthorized WSL commands")
    parser.add_argument('--install', action='store_true', help='Install as Windows service')
    parser.add_argument('--uninstall', action='store_true', help='Uninstall the Windows service')
    parser.add_argument('--start', action='store_true', help='Start the Windows service')
    parser.add_argument('--stop', action='store_true', help='Stop the Windows service')
    parser.add_argument('--debug', action='store_true', help='Run in console/debug mode (not as service)')
    parser.add_argument('--test', action='store_true', help='Test detection patterns')
    args = parser.parse_args()
    
    # Test detection patterns
    if args.test:
        print("Testing command detection patterns...")
        test_strings = [
            "ls -la", "cd /etc", "grep -r password",  # Common legitimate commands
            "nmap 192.168.1.1", "nc -lvp 4444", "curl -X POST",  # Unauthorized commands
            "python -c script.py", "python3 manage.py runserver",  # Python commands
            "ls names", "test names", "hostname"  # Strings with 'ns' substring
        ]
        
        guardian = WSLGuardian()
        for test in test_strings:
            found, cmd = guardian.check_for_unauthorized_commands(test)
            status = "BLOCKED" if found else "ALLOWED"
            print(f"{status}: '{test}' {f'(detected as {cmd})' if found else ''}")
        return
    
    # Service management
    if args.install:
        try:
            win32serviceutil.InstallService(
                pythonClassString="wsl_guardian_service.WSLGuardianService",
                serviceName="WSLGuardian",
                displayName="WSL Guardian Service",
                description="Monitors WSL for unauthorized commands and terminates instances if detected",
                startType=win32service.SERVICE_AUTO_START
            )
            print(f"WSL Guardian Service installed successfully.")
            print(f"Logs will be written to: {LOG_FILE}")
            print("To start the service, use: --start or go to Services in Windows")
        except Exception as e:
            print(f"Error installing service: {e}")
            
    elif args.uninstall:
        try:
            win32serviceutil.RemoveService("WSLGuardian")
            print("WSL Guardian Service uninstalled successfully.")
        except Exception as e:
            print(f"Error uninstalling service: {e}")
            
    elif args.start:
        try:
            win32serviceutil.StartService("WSLGuardian")
            print("WSL Guardian Service started successfully.")
        except Exception as e:
            print(f"Error starting service: {e}")
            
    elif args.stop:
        try:
            win32serviceutil.StopService("WSLGuardian")
            print("WSL Guardian Service stopped successfully.")
        except Exception as e:
            print(f"Error stopping service: {e}")
            
    elif args.debug:
        print(f"Starting WSL Guardian in console mode")
        print(f"Logs will be written to: {LOG_FILE}")
        print(f"Monitoring for {len(UNAUTHORIZED_COMMANDS)} unauthorized commands")
        print("Press Ctrl+C to stop")

    while True:
        try:
            guardian = WSLGuardian()
            monitor_thread = guardian.start()

            # Keep running unless manually stopped
            while guardian.running:
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n[Ctrl+C] Stopping WSL Guardian...")
            guardian.stop()
            break

        except Exception as e:
            print(f"[CRASH] Restarting monitor due to error: {e}")
            time.sleep(5)
        
    else:
        # If no arguments, show help
        print("WSL Guardian Service")
        print("This tool monitors WSL for unauthorized commands and terminates instances if detected.")
        print("\nOptions:")
        print("  --install    Install as Windows service")
        print("  --uninstall  Uninstall the Windows service")
        print("  --start      Start the Windows service")
        print("  --stop       Stop the Windows service")
        print("  --debug      Run in console/debug mode (not as service)")
        print("  --test       Test detection patterns")
        print("\nExample usage:")
        print("  python wsl_guardian_service.py --install")
        print("  python wsl_guardian_service.py --debug")
        
        
if __name__ == "__main__":
    main()