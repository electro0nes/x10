#x9_run.py
import os
import subprocess
import sys
import json
import requests
import datetime
from collections import defaultdict
from dotenv import load_dotenv  
import tempfile
import argparse
import shlex
load_dotenv()

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
NUCLEI_ROUTE = os.getenv("NUCLEI_ROUTE")
SCRIPT_ROUTE = os.getenv("SCRIPT_ROUTE")

def ensure_directory_exists(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")

def is_json_response(url):
    """Check if the URL is reachable and returns a JSON-like response."""
    try:
        response = requests.get(url, timeout=5)  # Try to connect

        content_type = response.headers.get("Content-Type", "").lower()

        return (
            "application/json" in content_type or
            "text/javascript" in content_type
        )
    except requests.exceptions.ConnectionError:
        print(f"❌ Skipping {url} (Connection refused or unreachable)")
        return True  # Skip it
    except requests.exceptions.Timeout:
        print(f"❌ Skipping {url} (Timeout)")
        return True  # Skip it
    except Exception as e:
        print(f"⚠️ Skipping {url} (Unknown error: {e})")
        return True  # Skip it

def send_discord_alert(nuclei_output):
    """Send a Discord notification with ANSI-colored output inside a code block."""
    if not DISCORD_WEBHOOK_URL:
        print("⚠️ DISCORD_WEBHOOK_URL is not set or is empty!")
        return

    now_timestamp = datetime.datetime.utcnow().isoformat()
    formatted_output = f"```ansi\n{nuclei_output}\n```"

    embed = {
        "title": "🚨 XSS Detected via X10!",
        "description": formatted_output,  
        "color": 16711680,  
        "footer": {
            "text": "XSS Alert | Automated System",
            "icon_url": "https://cdn-icons-png.flaticon.com/512/6192/6192510.png"
        },
        "timestamp": now_timestamp
    }

    message = {
        "username": "XSS Scanner",
        "embeds": [embed]
    }

    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=message, headers=headers)
        if response.status_code in [200, 204]:  
            print("✅ Discord alert sent successfully!")
        else:
            print(f"⚠️ Failed to send Discord alert: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"⚠️ Error sending Discord alert: {str(e)}")

def run_command_in_zsh(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error occurred: {result.stderr}")
            return None
        return result.stdout
    except subprocess.CalledProcessError as exc:
        print(f"Status: FAIL {exc.returncode}, {exc.output}")
        return None

def group_files_by_domain():
    """Group part files by their domain or subdomain."""
    fuzz_dir = 'fuzz'
    if not os.path.exists(fuzz_dir):
        print(f"⚠️ Directory '{fuzz_dir}' not found!")
        return {}

    files = sorted([f for f in os.listdir(fuzz_dir) if f.count('.') >= 2 and '.part' in f])
    domain_files = defaultdict(list)

    for part_file in files:
        domain_prefix = part_file.split('.part')[0]
        domain_files[domain_prefix].append(os.path.join(fuzz_dir, part_file))

    return domain_files

def run_x9_on_files(domain_files, output_file):
    """Run X9 and collect all fuzzed URLs, then run nuclei in batch."""
    all_fuzzed_urls = []
    for domain_prefix, files in domain_files.items():
        for part_file in files:
            with open(part_file, 'r') as file:
                urls = [url.strip() for url in file.readlines()]

            urls = filter_urls(urls)

            for url in urls:
                if is_json_response(url):
                    print(f"❌ Skipping {url} (JSON response, no XSS possible)")
                    continue  # Skip URLs with JSON responses

                print(f"Generating fuzzed URLs for {url} from {part_file}")
                x9_command = f'python3 {SCRIPT_ROUTE} -u \'{url}\' -gs all -vs suffix -v ">xxxx,xxxx\\",xxxx\',xxxx" -p parameters/top_xss_parameter.txt --rate-limit 1'
                output = run_command_in_zsh(x9_command)
                if output:
                    fuzzed_urls = [line.strip() for line in output.splitlines() if line.strip()]
                    all_fuzzed_urls.extend(fuzzed_urls)

                if output_file:
                    with open(output_file, 'a') as log_file:
                        log_file.write(f"--- Fuzzed URLs for {url} from {part_file} ---\n{output}\n")

            os.remove(part_file)
            print(f"Removed processed file: {part_file}")

    # After all fuzzed URLs are collected, run nuclei in batch
    batch_run_nuclei(all_fuzzed_urls)

def run_fallparams_on_files(domain_files, output_file):
    """Run fallparams on each URL, collect all fuzzed URLs, then run nuclei in batch."""
    all_fuzzed_urls = []
    for domain_prefix, files in domain_files.items():
        for part_file in files:
            with open(part_file, 'r') as file:
                urls = [url.strip() for url in file.readlines()]

            urls = filter_urls(urls)

            for url in urls:
                if is_json_response(url):
                    print(f"❌ Skipping {url} (JSON response, no XSS possible)")
                    continue

                print(f"Running fallparams on {url} from {part_file}")
                run_command_in_zsh(f"fallparams -u '{url}' -o parameters.txt")

                fallparams_params = []
                if os.path.exists("parameters.txt") and os.path.getsize("parameters.txt") > 0:
                    with open("parameters.txt", 'r', encoding='utf-8', errors='ignore') as pf:
                        fallparams_params = [p.strip() for p in pf.readlines()]
                else:
                    print(f"parameters.txt is missing or empty after running fallparams on {url} from {part_file}")

                top_xss_params = []
                if os.path.exists("parameters/top_xss_parameter.txt"):
                    with open("parameters/top_xss_parameter.txt", "r") as tf:
                        top_xss_params = [p.strip() for p in tf if p.strip()]

                combined_params = fallparams_params + top_xss_params
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_param_file:
                    for p in combined_params:
                        temp_param_file.write(f"{p}\n")
                    temp_param_path = temp_param_file.name

                json_output = {
                    "urls": [url],
                    "params": top_xss_params
                }
                x9_command = f'python3 {SCRIPT_ROUTE} -j \'{json.dumps(json_output)}\' -gs all -vs suffix -v ">xxxx,xxxx\\",xxxx\',xxxx" -p {temp_param_path} --rate-limit 1'
                output_j = run_command_in_zsh(x9_command)
                if output_j:
                    fuzzed_urls = [line.strip() for line in output_j.splitlines() if line.strip()]
                    all_fuzzed_urls.extend(fuzzed_urls)

                if output_file:
                    with open(output_file, 'a') as log_file:
                        log_file.write(f"--- Fuzzed URLs for {url} from {part_file} ---\n{output_j}\n")

            os.remove(part_file)
            print(f"Removed processed file: {part_file}")

    # After all fuzzed URLs are collected, run nuclei in batch
    batch_run_nuclei(all_fuzzed_urls)

def filter_urls(urls):
    """Filter out URLs that end with unwanted file extensions."""
    extensions = ['.m4v','.json', '.js', '.fnt', '.ogg', '.css', '.jpg', '.jpeg',
                  '.png', '.svg', '.img', '.gif', '.exe', '.mp4', '.flv',
                  '.pdf', '.doc', '.ogv', '.webm', '.wmv', '.webp', '.mov',
                  '.mp3', '.m4a', '.m4p', '.ppt', '.pptx', '.scss', '.tif',
                  '.tiff', '.ttf', '.otf', '.woff', '.woff2', '.bmp', '.ico',
                  '.eot', '.htc', '.swf', '.rtf', '.image', '.rf', '.txt',
                  '.xml', '.zip', '.msi', '.tar', '.gz', '.GZ', '.rar' , '.pdf%20' , '.pdf ']

    filtered_urls = []
    for url in urls:
        if not any(url.lower().endswith(ext) for ext in extensions):
            filtered_urls.append(url)

    return filtered_urls

def collect_urls_from_fuzz():
    """Collect all URLs from fuzz/*.part files."""
    urls = []
    fuzz_dir = 'fuzz'
    if not os.path.exists(fuzz_dir):
        return urls
    for fname in os.listdir(fuzz_dir):
        if fname.endswith('.part'):
            with open(os.path.join(fuzz_dir, fname), 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
    return urls

def batch_run_nuclei(urls):
    if not urls:
        print("No URLs to scan with nuclei.")
        return
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
        for url in urls:
            tmp.write(url + '\n')
        tmp_path = tmp.name
    print(f"[+] Running nuclei on {len(urls)} URLs...")
    nuclei_cmd = f"nuclei -l {tmp_path} -t {NUCLEI_ROUTE} -silent"
    output = run_command_in_zsh(nuclei_cmd)
    os.remove(tmp_path)
    # Log nuclei output to fuzz/x10.res
    ensure_directory_exists('fuzz')
    output_file = os.path.join('fuzz', 'x10.res')
    ensure_directory_exists(os.path.dirname(output_file))
    with open(output_file, 'a') as log_file:
        log_file.write(f"--- Nuclei batch output ---\n{output}\n")
    # If 'xxxx' is in the output, send a Discord alert
    if output and "xxxx" in output:
        send_discord_alert(output)

def run_subfinder_dnsx_httpx(domain):
    """Return list of alive subdomains using subfinder, dnsx, httpx."""
    cmd = f"subfinder -d {shlex.quote(domain)} -silent | dnsx -silent | httpx -silent"
    print(f"[+] Discovering subdomains for {domain}...")
    output = run_command_in_zsh(cmd)
    subdomains = [line.strip() for line in output.splitlines() if line.strip()]
    return subdomains

def run_x10py_generate_urls(url):
    """Run x10.py to generate fuzzed URLs for a single URL input."""
    cmd = f'python3 x10.py -u {url} -p parameters/top_xss_parameter.txt -gs all -vs suffix -v ">xxxx,xxxx\\",xxxx\',xxxx" '
    output = run_command_in_zsh(cmd)
    print(cmd)
    urls = [line.strip() for line in output.splitlines() if line.strip()]
    return urls

def main():
    parser = argparse.ArgumentParser(description="X10 Advanced XSS Discovery Runner")
    parser.add_argument('mode', choices=['domain', 'wildcard', 'url'], help='Mode of operation: domain, wildcard, or url')
    parser.add_argument('input', help='Domain, wildcard domain (*.domain.tld), or URL')
    parser.add_argument('--fallparams', action='store_true', help='Enable parameter discovery with fallparams')
    parser.add_argument('--subs', action='store_true', help='Include --subs in gau command (domain mode only)')
    args = parser.parse_args()

    if args.mode == 'domain':
        print(f"[MODE: DOMAIN] Running passive + active + x10_run + nuclei for {args.input}")
        fuzz_cmd = f"python3 x10_fuzz.py {shlex.quote(args.input)} true"
        if args.subs:
            fuzz_cmd += " --subs"
        run_command_in_zsh(fuzz_cmd)
        if args.fallparams:
            print("[+] Running fallparams pipeline...")
            output_file = os.path.join('fuzz', 'x10.res')
            domain_files = group_files_by_domain()
            run_fallparams_on_files(domain_files, output_file)
        else:
            print("[+] Running XSS pipeline...")
            output_file = os.path.join('fuzz', 'x10.res')
            domain_files = group_files_by_domain()
            run_x9_on_files(domain_files, output_file)
        urls = collect_urls_from_fuzz()
        batch_run_nuclei(urls)

    elif args.mode == 'wildcard':
        print(f"[MODE: WILDCARD] Running katana only for all subdomains and main domain for {args.input}")
        domain = args.input.replace('*.', '')
        subdomains = run_subfinder_dnsx_httpx(domain)
        # Ensure the main domain is included
        if domain not in subdomains:
            subdomains.append(domain)
        print(f"[+] Found {len(subdomains)} alive subdomains (including main domain).")
        # Run katana (x10_active.py) on each subdomain and main domain
        all_katana_urls = []
        for sub in subdomains:
            print(f"Running x10_active.py for: {sub}")
            run_command_in_zsh(f"python3 x10_active.py {shlex.quote(sub)}")
            katana_file = f"{sub}.katana"
            if os.path.exists(katana_file):
                with open(katana_file, 'r') as f:
                    katana_urls = [line.strip() for line in f if line.strip()]
                    all_katana_urls.extend(katana_urls)
                print(f"Added {len(katana_urls)} URLs from {katana_file}")
            else:
                print(f"No katana output file found: {katana_file}")
        # Deduplicate
        all_katana_urls = list(dict.fromkeys(all_katana_urls))
        print(f"Total unique katana URLs: {len(all_katana_urls)}")
        # Write all katana URLs to a single deduplicated file named fuzz/{domain}.katana
        ensure_directory_exists('fuzz')
        katana_merged_file = os.path.join('fuzz', f"{domain}.katana")
        with open(katana_merged_file, 'w') as f:
            for url in all_katana_urls:
                f.write(url + '\n')
        # Write to fuzz/domain.part1 for compatibility with rest of pipeline
        part_file = os.path.join('fuzz', f"{domain}.part1")
        with open(part_file, 'w') as f:
            for url in all_katana_urls:
                f.write(url + '\n')
        # Now run the rest of the pipeline
        output_file = os.path.join('fuzz', 'x10.res')
        domain_files = group_files_by_domain()
        if args.fallparams:
            print("[+] Running fallparams pipeline...")
            run_fallparams_on_files(domain_files, output_file)
        else:
            print("[+] Running XSS pipeline...")
            run_x9_on_files(domain_files, output_file)
        urls = collect_urls_from_fuzz()
        batch_run_nuclei(urls)

    elif args.mode == 'url':
        print(f"[MODE: URL] Running x10.py + param + nuclei for {args.input}")
        output_file = os.path.join('fuzz', 'x10.res')
        ensure_directory_exists(os.path.dirname(output_file))
        if args.fallparams:
            print("[+] Running fallparams for single URL...")
            # Run fallparams on the URL
            run_command_in_zsh(f"fallparams -u {shlex.quote(args.input)} -o parameters.txt")
            fallparams_params = []
            if os.path.exists("parameters.txt") and os.path.getsize("parameters.txt") > 0:
                with open("parameters.txt", 'r', encoding='utf-8', errors='ignore') as pf:
                    fallparams_params = [p.strip() for p in pf.readlines()]
            else:
                print(f"parameters.txt is missing or empty after running fallparams on {args.input}")
            top_xss_params = []
            if os.path.exists("parameters/top_xss_parameter.txt"):
                with open("parameters/top_xss_parameter.txt", "r") as tf:
                    top_xss_params = [p.strip() for p in tf if p.strip()]
            combined_params = fallparams_params + top_xss_params
            # Write combined params to a temp file
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_param_file:
                for p in combined_params:
                    temp_param_file.write(f"{p}\n")
                temp_param_path = temp_param_file.name
            # Generate fuzzed URLs using x10.py (safe quoting)
            x9_command = (
                f"python3 {SCRIPT_ROUTE} "
                f"-u {args.input} "
                f"-gs all -vs suffix "
                f"-v '>xxxx,xxxx\\',xxxx',xxxx\"' "
                f"-p {temp_param_path} --rate-limit 1"
            )
            output = run_command_in_zsh(x9_command)
            fuzzed_urls = [line.strip() for line in output.splitlines() if line.strip()]
            # Log fuzzed URLs
            with open(output_file, 'a') as log_file:
                log_file.write(f"--- Fuzzed URLs for {args.input} (fallparams) ---\n{output}\n")
            # Run nuclei in batch
            batch_run_nuclei(fuzzed_urls)
        else:
            urls = run_x10py_generate_urls(args.input)
            batch_run_nuclei(urls)
    else:
        print("Invalid mode!")
        sys.exit(1)

if __name__ == "__main__":
    main()