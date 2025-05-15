WSLGuardian

**WSLGuardian** is a lightweight Python-based security monitoring tool that detects and terminates unauthorized or suspicious command activity executed within the **Windows Subsystem for Linux (WSL)**. It fills a critical visibility gap left by most EDR and SIEM platforms, especially when monitoring WSL 2 environments.

---

Features
```bash
- Real-time monitoring** of WSL processes (`wsl.exe`, `bash.exe`, etc.)
- Regex-based rule engine** to detect malicious command patterns (e.g., `nmap`, `netcat`, `curl`, reverse shells)
- Automatic process termination** for matched threats
- Detailed structured logging** in JSON and plaintext formats (SIEM-ready)
- Multithreaded architecture** with efficient resource use
- Runs as a persistent Windows service**
- Optional **debug console mode** for testing and evaluation
```
---

How It Works
```bash
1. Scans active Windows processes for WSL-related executables.
2. Checks running commands and shell histories inside WSL using `wsl` and `ps` commands.
3. Matches content against a built-in list of **unauthorized command patterns** using regular expressions.
4. If a match is found, the offending process is forcefully terminated.
5. All events (normal and suspicious) are logged in `C:\ProgramData\WSLGuardian`.
```
---

Log Output
```bash
- Primary log file: `C:\ProgramData\WSLGuardian\wsl_guardian.log`
- Per-process logs: `C:\ProgramData\WSLGuardian\detailed_logs\wsl_process_<pid>.log`
- Log entries include: timestamp, process name, PID, command line, rule matched, and termination result.

```
Unauthorized Commands Detected

The tool is pre-configured to detect and block:
- Scanners (`nmap`, `netcat`, `tcpdump`, `wireshark`)
- Reverse shell patterns (`bash -i`, `python -c`, etc.)
- Data exfiltration tools (`curl`, `wget`)
- Password crackers (`john`, `hydra`, `hashcat`)
- Exploit frameworks (`metasploit`, `msfconsole`, `msfvenom`)
- Encoders and bypass tools (`base64 -d`, `certutil -decode`)

---

Installation & Usage

Run as a Windows Service

```bash
python wsl_guardian_service.py --install   # Install the service
python wsl_guardian_service.py --start     # Start the service
python wsl_guardian_service.py --stop      # Stop the service
python wsl_guardian_service.py --uninstall # Uninstall the service
