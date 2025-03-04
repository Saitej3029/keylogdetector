### Ultimate Keylogger Detector 🚀
  A powerful keylogger detection and prevention tool that identifies suspicious processes, network activity, and hidden malware in real-time.

## Features
✅ Detects & Terminates Keyloggers (Automatic Process Kill)
✅ Scans Files Against VirusTotal API (Checks for Malware)
✅ Detects Keyboard Hooks (Stealth Keylogging Prevention)
✅ Finds Suspicious Network Connections
✅ Detects Fake Key Presses (Injected Keystroke Monitoring)
✅ Scans for Hidden Log Files (Detect Keylogger Storage)
✅ Detects Hidden Malware Processes
✅ Sends Real-Time Alerts via Telegram


# <img width="578" alt="image" src="https://github.com/user-attachments/assets/fa24eaed-394a-4bcc-a557-8a2d2a918282" />



# 🔧 Installation
# Step 1: Clone the Repository
```bash
 git clone https://github.com/yourusername/keylogger-detector.git
 cd keylogger-detector
```

# Step 2: Install Dependencies
```bash
   pip install psutil requests pynput
```

# Step 3: Get API Keys
Telegram API Key: Create a bot with BotFather and get your API token.
VirusTotal API Key: Sign up at VirusTotal and generate an API key.


# Step 4: Edit Configuration
Edit the script and add your Telegram Bot Token and VirusTotal API Key:
```bash
  TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
  TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
  VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

# 1️⃣ Windows Installation
   🔹 Prerequisites:

   1.Python 3 (Install from Python.org)
   2.PowerShell or Command Prompt
# Step 1: Install Python and Pip
   1.Download Python 3 from Python.org
   2.During installation, check "Add Python to PATH"
   3.Open PowerShell and verify the installation:
```bash
  python --version
  pip --version
```

# Step 2: Clone the Repository
```bash
 git clone https://github.com/yourusername/keylogger-detector.git
 cd keylogger-detector
```

# Step 3: Install Dependencies
```bash
 pip install -r requirements.txt
```

# Step 4: Run the Script
  ```bash
python keylogger_detector.py
```

# 2️⃣ Linux Installation
  🔹 Works on Ubuntu, Debian, Fedora, Arch, Kali, ParrotOS

# Step 1: Install Python and Git
 ```bash
 sudo apt update && sudo apt install python3 python3-pip git -y
```

# For Fedora:
```bash
  sudo dnf install python3 python3-pip git -y
```

# For Arch:
```bash
  sudo pacman -S python python-pip git --noconfirm
```

# Step 2: Clone the Repository
```bash
   git clone https://github.com/yourusername/keylogger-detector.git
   cd keylogger-detector
```

# Step 3: Install Dependencies
```bash
   sudo apt install python3-psutil
   sudo apt install python3-requests
   sudo apt install python3-pynput
```

# Step 4: Run the Script
```bash
   python3 keylogger_detector.py
```

# 3️⃣ macOS Installation
 🔹 Requires Homebrew for installation

# Step 1: Install Python and Git
```bash
   brew install python git
```

# Step 2: Clone the Repository
```bash
 git clone https://github.com/yourusername/keylogger-detector.git
 cd keylogger-detector
```

# Step 3: Install Dependencies
```bash
   pip3 install -r requirements.txt
```

# Step 4: Run the Script
```bash
   python3 keylogger_detector.py
```

# 🛠️ Configuration
  Before running, edit the script to add API keys:
```bash
   TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
   TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
   VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```



## 📌 Example Output

   [🔍] Running Keylogger Detector....
   [⚠️] Suspicious Process Found: keylogger.exe (PID: 3210).
   [❌] Terminating keylogger.exe (PID: 3210).
   🚨*Terminated Suspicious Process:* keylogger.exe (PID: 3210).
   [⚠️] Keyboard Hook Detected!.
   🚨*Keyboard Hook Detected!* Possible keylogger activity.
   [✅] Scan Complete!.



###  📝 License
  

 MIT License

 Copyright (c) 2025 [Cybercafe]

   Permission is hereby granted, free of charge, to any person obtaining a copy  
   of this software and associated documentation files (the "Software"), to deal  
   in the Software without restriction, including without limitation the rights  
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
   copies of the Software, and to permit persons to whom the Software is  
   furnished to do so, subject to the following conditions:  

  The above copyright notice and this permission notice shall be included in all  
  copies or substantial portions of the Software.  

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN  
   THE SOFTWARE.  


## Contributing
   Pull requests are welcome! For major changes, please open an issue first.   

## Contact
For any issues, reach out via GitHub Issues or email us at cybercafestu@gmail.com.


