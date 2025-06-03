# 🎯 X10 - Advanced XSS Discovery Tool

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Discord](https://img.shields.io/badge/discord-integration-7289DA.svg)](https://discord.com)

> 🔍 A powerful and automated XSS (Cross-Site Scripting) discovery tool that combines multiple scanning techniques to identify potential XSS vulnerabilities in web applications.

![X10 Banner](https://i.postimg.cc/rwyV0wbV/Screenshot-2025-06-03-at-11-24-43-PM.png)

## ✨ Features

### 🎮 Multiple Scanning Modes
- **Domain Mode** 🏢 - Full scan of a target domain
- **Wildcard Mode** 🌐 - Scan all subdomains of a target domain
- **URL Mode** 🔗 - Scan a single URL

### 🔄 Advanced Scanning Pipeline
- **Passive Reconnaissance** 📡 - Using multiple tools
- **Active Scanning** 🎯 - With Katana
- **Parameter Discovery** 🔎 - Using fallparams
- **XSS Payload Generation** 💉 - And testing
- **Nuclei Integration** 🧪 - For vulnerability scanning

### 🧠 Smart Features
- **Batch Processing** 📦 - URLs processed in batches of 1000
- **Smart Filtering** 🚫 - Automatic filtering of non-relevant file types
- **JSON Detection** 📄 - Skip JSON responses automatically
- **Discord Alerts** 🔔 - Real-time vulnerability notifications
- **Configurable Options** ⚙️ - Flexible scanning parameters

---

## 📋 Prerequisites

### 🐍 Python Requirements
- Python 3.x
- Required packages:
  - `requests`
  - `python-dotenv`

### 🛠️ Required Tools
- `subfinder` - Subdomain enumeration
- `dnsx` - DNS toolkit
- `httpx` - HTTP toolkit
- `nuclei` - Vulnerability scanner
- `fallparams` - Parameter discovery
- `katana` - Web crawling
- `gau` - URL discovery

---

## 🚀 Installation

1. **Clone the repository**
```bash
git clone https://github.com/electro0nes/x10.git
cd x10
```

2. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment**
Create a `.env` file:
```env
# Discord webhook for real-time alerts
DISCORD_WEBHOOK_URL=your_discord_webhook_url

# Path to Nuclei templates
NUCLEI_ROUTE=path_to_nuclei_templates

# Path to X10 script
SCRIPT_ROUTE=path_to_x10_script

# Path to x10_passive.py
X9_PASSIVE=path_to_x10_passive
```

---

## 💻 Usage

### Basic Command
```bash
python3 x10_run.py [mode] [input] [options]
```

### 🎯 Scanning Modes

#### 1. Domain Mode
```bash
python3 x10_run.py domain example.com
```

#### 2. Wildcard Mode
```bash
python3 x10_run.py wildcard *.example.com
```

#### 3. URL Mode
```bash
python3 x10_run.py url https://example.com/page
```

### ⚙️ Available Options

| Option | Description |
|--------|-------------|
| `--fallparams` | Enable parameter discovery using fallparams |
| `--subs` | Include subdomains in gau command (domain mode only) |
| `--skip-fuzz` | Skip fuzzing if fuzz/*.part files exist |
| `--run-nuclei` | Run nuclei only if fuzz/x10.res exists |

### 📝 Usage Examples

1. **Full domain scan with subdomain discovery**
```bash
python3 x10_run.py domain example.com --subs
```

2. **Wildcard scan with fallparams**
```bash
python3 x10_run.py wildcard *.example.com --fallparams
```

3. **Single URL scan with nuclei only**
```bash
python3 x10_run.py url https://example.com/page --run-nuclei
```

---

## 📊 Output

The tool generates the following output files in the `fuzz` directory:

| File Type | Description |
|-----------|-------------|
| `*.part` | Intermediate URL lists |
| `x10.res` | Combined results from all scanning phases |
| `nuclei_findings/` | Directory containing detailed XSS findings |
| `*.katana` | Katana scanning results (wildcard mode only) |

---

## 🔔 Discord Integration

The tool sends real-time alerts to Discord when XSS vulnerabilities are detected. Each alert includes:
- 🚨 Vulnerability details
- 🔗 Affected URLs
- ⏰ Timestamp
- 🆔 Unique message ID

Configure your Discord webhook URL in the `.env` file to enable this feature.

---

## 📝 Notes

- 🔄 URLs are processed in batches of 1000 for optimal performance
- 🚫 Common file extensions (images, documents, etc.) are automatically filtered
- 📄 JSON responses are detected and skipped
- 🧹 Temporary files are automatically cleaned up
- ⚡ Rate limiting is implemented to prevent overwhelming targets

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

> ⚠️ **IMPORTANT**: This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before testing any website or application.

---

<div align="center">
Made with ❤️ by Electro0ne
</div>
