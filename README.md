# X10 - Advanced XSS Discovery Suite

![X10 Banner](https://archive.org/download/anonymus-hacker-computer-4k-wallpaper-preview/anonymus-hacker-computer-4k-wallpaper-preview.jpg "X10 Tool Banner")

## Overview

**X10** is a powerful automated Cross-Site Scripting (XSS) discovery suite that streamlines the entire process of uncovering XSS vulnerabilities. It uses a modular pipeline consisting of:

1. **URL Discovery** – Harvests URLs using Wayback Machine and GAU
2. **Parameter Analysis** – Extracts and analyzes query parameters
3. **XSS Fuzzing** – Runs intelligent fuzzing using crafted payloads

---

## Features

* 🔍 Comprehensive URL discovery via multiple sources
* 🧐 Smart parameter extraction and analysis
* 🎯 Intelligent and customizable XSS payload fuzzing
* 📊 Supports structured output (JSON, text)
* ⚡ Parallel and batch processing for faster scanning

---

## Installation

### Prerequisites

```bash
# Install required Python dependencies
pip3 install -r requirements.txt

# Install URO
git clone https://github.com/s0md3v/uro && cd uro && sudo python3 setup.py install

# Install Waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Install GAU
go install github.com/lc/gau/v2/cmd/gau@latest

# Install Fallparams
go install github.com/ImAyrix/fallparams@latest

# Install Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Make scripts executable:

```bash
chmod +x x10.py x10_run.py x10_fuzz.py x10_passive.py
```

---

## Configuration

Create a `.env` file with the following variables:

```bash
DISCORD_WEBHOOK_URL=""   # Discord webhook for notifications
NUCLEI_ROUTE=""          # Path to your Nuclei templates (e.g., xss-discovery.yaml)
SCRIPT_ROUTE=""          # Path to custom script: 10.py
X9_PASSIVE=""            # Path to passive script: 10_passive.py
```

---

## Usage

### 1. URL Discovery & Parameter Extraction

```bash
python3 x10_fuzz.py example.com <true/false> [--subs]
```

* `true` enables Katana for discovery (not recommended for general use)
* `false` sticks to GAU and Wayback
* `--subs` (optional) includes subdomains in gau passive collection

This step will:

* Gather URLs from multiple sources
* Deduplicate them
* Extract and identify parameters

---

### 2. XSS Testing

```bash
python3 x10.py -l discovered_urls.txt -v 'xss_payload' -p file,text -gs generate_strategy -vs value_strategy -o json -m get,post
```

**Options:**

* `-l` File containing URLs to test
* `-v` XSS payload to inject
* `-p` Parameter sources (`file`, `text`, or both)
* `-gs` Generation strategy (e.g., reflect-based, param combo)
* `-vs` Value strategy (e.g., random, static, mirrored)
* `-o` Output format (`json`, `text`)
* `-m` HTTP methods to test (`get`, `post`)

---

### 3. Advanced Fuzzing

```bash
python3 x10_run.py domain example.com [--fallparams] [--subs]
```

* `--fallparams` enables parameter discovery with fallparams
* `--subs` includes subdomains in gau passive collection

This step will:

* Process the collected URLs in batches
* Apply advanced payload fuzzing
* Test multiple parameter/value combinations

> ✅ Recommended: Use `false` for fallparams option unless explicitly needed.

---

## Example Workflow

```bash
# Step 1: Discover URLs (with subdomains)
python3 x10_fuzz.py target.com false --subs

# Step 2: Initial XSS Scan
python3 x10_run.py domain target.com --subs
```

---

## Output Formats

Supported formats:

* `JSON` – Machine-readable, useful for integrations
* `Text` – Human-readable, ideal for quick reviews

Use the `-o` flag to select the format:

```bash
-o json,text
```

---

## Bash Aliases

Add the following to your `.bashrc` or `.zshrc`:

```bash
alias x10_fuzz="python3 $HOME/Projects/automation/x10/x10_fuzz.py"
alias x10_run="python3 $HOME/Projects/automation/x10/x10_run.py"
alias x10="python3 $HOME/Projects/automation/x10/x10.py"
alias x10_passive="python3 $HOME/Projects/automation/x10/x10_passive.py"
```

---

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to suggest features or report bugs.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

> This tool is intended for **educational** and **authorized security testing** only.
> Unauthorized use of this tool against targets without permission is **illegal**.
