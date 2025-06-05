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
from urllib.parse import urlparse
import time
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

    def send_with_retry(message, headers, max_retries=3, initial_delay=1):
        """Helper function to send message with retry logic for rate limits."""
        retry_count = 0
        while retry_count < max_retries:
            try:
                print(f"[DEBUG] Attempting to send Discord message (attempt {retry_count + 1}/{max_retries})")
                print(f"[DEBUG] Message content: {json.dumps(message, indent=2)}")
                
                response = requests.post(DISCORD_WEBHOOK_URL, json=message, headers=headers)
                print(f"[DEBUG] Discord API Response Status: {response.status_code}")
                print(f"[DEBUG] Discord API Response Headers: {dict(response.headers)}")
                
                if response.status_code in [200, 204]:
                    # Verify the message was actually sent
                    if response.status_code == 204:
                        print("[DEBUG] Message sent successfully (204 No Content)")
                    else:
                        try:
                            response_json = response.json()
                            print(f"[DEBUG] Message sent successfully. Response: {json.dumps(response_json, indent=2)}")
                        except:
                            print(f"[DEBUG] Message sent successfully. Raw response: {response.text}")
                    return True, "Success"
                
                # Check for rate limit
                if response.status_code == 429:  # Too Many Requests
                    retry_after = int(response.headers.get('Retry-After', initial_delay))
                    delay = retry_after * (2 ** retry_count)  # Exponential backoff
                    print(f"⚠️ Discord rate limit hit. Waiting {delay} seconds before retry...")
                    print(f"[DEBUG] Rate limit response: {response.text}")
                    time.sleep(delay)
                    retry_count += 1
                    continue
                
                print(f"[DEBUG] Failed response: {response.text}")
                return False, f"HTTP {response.status_code}: {response.text}"
                
            except Exception as e:
                print(f"[DEBUG] Exception during send: {str(e)}")
                if retry_count < max_retries - 1:
                    delay = initial_delay * (2 ** retry_count)
                    print(f"⚠️ Error sending Discord message. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    retry_count += 1
                else:
                    return False, str(e)
        
        return False, "Max retries exceeded"

    try:
        now_timestamp = datetime.datetime.utcnow().isoformat()
        # Ensure the output is properly escaped and truncated if too long
        formatted_output = nuclei_output.replace('```', '\\`\\`\\`')  # Escape code blocks
        if len(formatted_output) > 4000:  # Discord has a 4096 character limit for description
            formatted_output = formatted_output[:3997] + "..."
        
        # Add a unique identifier to help track messages
        message_id = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        
        embed = {
            "title": f"🚨 XSS Detected via X10! [ID: {message_id}]",
            "description": f"```ansi\n{formatted_output}\n```",
            "color": 16711680,  # Red color
            "footer": {
                "text": f"XSS Alert | Automated System | ID: {message_id}"
            },
            "timestamp": now_timestamp
        }

        # Validate embed size
        if len(str(embed)) > 6000:  # Discord has a 6000 character limit for embeds
            embed["description"] = f"```ansi\nOutput too large to display in Discord. Check the logs for full details.\nMessage ID: {message_id}\n```"

        message = {
            "username": "XSS Scanner",
            "embeds": [embed],
            "content": f"🚨 New XSS Alert! [ID: {message_id}]"  # Add a content field to ensure visibility
        }

        print(f"[DEBUG] Preparing to send Discord alert with ID: {message_id}")
        print(f"[DEBUG] Webhook URL (first 20 chars): {DISCORD_WEBHOOK_URL[:20]}...")
        
        headers = {"Content-Type": "application/json"}
        
        # Try to send the main message with retry logic
        success, error_msg = send_with_retry(message, headers)
        if success:
            print(f"✅ Discord alert sent successfully! [ID: {message_id}]")
            print(f"[DEBUG] Please verify the message in Discord with ID: {message_id}")
        else:
            print(f"⚠️ Failed to send Discord alert: {error_msg}")
            # Try to send a simpler message if the embed fails
            simple_message = {
                "username": "XSS Scanner",
                "content": f"🚨 XSS Detected! Check the logs for details. [ID: {message_id}]"
            }
            success, error_msg = send_with_retry(simple_message, headers)
            if success:
                print(f"✅ Sent simplified Discord alert [ID: {message_id}]")
            else:
                print(f"⚠️ Failed to send simplified Discord alert: {error_msg}")
    except Exception as e:
        print(f"⚠️ Error preparing Discord alert: {str(e)}")
        print(f"[DEBUG] Full error details: {str(e)}")

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
    """Run X9 and collect all fuzzed URLs."""
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

    return all_fuzzed_urls

def run_fallparams_on_files(domain_files, output_file):
    """Run fallparams on each URL and collect all fuzzed URLs."""
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
                if not combined_params:  # Skip if no parameters found
                    continue
                
                temp_param_path = None
                try:
                    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_param_file:
                        for p in combined_params:
                            temp_param_file.write(f"{p}\n")
                        temp_param_path = temp_param_file.name

                    json_output = {
                        "urls": [url],
                        "params": combined_params
                    }
                    x9_command = f'python3 {SCRIPT_ROUTE} -j \'{json.dumps(json_output)}\' -gs all -vs suffix -v ">xxxx,xxxx\\",xxxx\',xxxx" -p {temp_param_path} --rate-limit 1'
                    output_j = run_command_in_zsh(x9_command)
                    if output_j:
                        fuzzed_urls = [line.strip() for line in output_j.splitlines() if line.strip()]
                        all_fuzzed_urls.extend(fuzzed_urls)

                    if output_file:
                        with open(output_file, 'a') as log_file:
                            log_file.write(f"--- Fuzzed URLs for {url} from {part_file} ---\n{output_j}\n")
                finally:
                    # Clean up temporary parameter file
                    if temp_param_path and os.path.exists(temp_param_path):
                        try:
                            os.remove(temp_param_path)
                            print(f"[+] Cleaned up temporary parameter file: {temp_param_path}")
                        except Exception as e:
                            print(f"Warning: Failed to remove temporary parameter file {temp_param_path}: {e}")

            os.remove(part_file)
            print(f"Removed processed file: {part_file}")

    return all_fuzzed_urls

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

def batch_run_nuclei(urls , domain):
    if not urls:
        print("No URLs to scan with nuclei.")
        return
    batch_size = 1000
    total_urls = len(urls)
    print(f"[+] Splitting {total_urls} URLs into batches of {batch_size}...")
    
    # Create a directory for nuclei findings if it doesn't exist
    nuclei_findings_dir = os.path.join('fuzz', 'nuclei_findings')
    ensure_directory_exists(nuclei_findings_dir)
    
    for i in range(0, total_urls, batch_size):
        batch = urls[i:i + batch_size]
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
                for url in batch:
                    tmp.write(url + '\n')
                tmp_path = tmp.name
            print(f"[+] Running nuclei on batch {i//batch_size + 1} ({len(batch)} URLs)...")
            nuclei_cmd = f"nuclei -l {tmp_path} -t {NUCLEI_ROUTE} -var domain=https://{domain} -silent"
            output = run_command_in_zsh(nuclei_cmd)
            
            # Log nuclei output to fuzz/x10.res
            ensure_directory_exists('fuzz')
            output_file = os.path.join('fuzz', 'x10.res')
            ensure_directory_exists(os.path.dirname(output_file))
            with open(output_file, 'a') as log_file:
                log_file.write(f"--- Nuclei batch {i//batch_size + 1} output ---\n{output}\n")
            
            # If 'xxxx' is in the output, save to a separate file and send Discord alert
            if output and "xxxx" in output:
                # Generate timestamp for the filename
                timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                finding_filename = f"xss_finding_{timestamp}.txt"
                finding_path = os.path.join(nuclei_findings_dir, finding_filename)
                
                # Save the nuclei output to a separate file
                with open(finding_path, 'w') as f:
                    f.write(f"=== XSS Finding from Nuclei Scan ===\n")
                    f.write(f"Timestamp: {datetime.datetime.utcnow().isoformat()}\n")
                    f.write(f"Domain: {domain}\n")
                    f.write(f"Batch: {i//batch_size + 1}\n")
                    f.write(f"Total URLs in batch: {len(batch)}\n")
                    f.write(f"Batch URLs:\n")
                    for url in batch:
                        f.write(f"- {url}\n")
                    f.write(f"\n=== Nuclei Output ===\n")
                    f.write(output)
                    f.write(f"\n=== End of Finding ===\n")
                
                print(f"[+] XSS finding saved to: {finding_path}")
                send_discord_alert(output)
        finally:
            # Clean up temporary file
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                    print(f"[+] Cleaned up temporary file: {tmp_path}")
                except Exception as e:
                    print(f"Warning: Failed to remove temporary file {tmp_path}: {e}")

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

def extract_domain_from_url(url):
    """Extract domain from a URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except Exception as e:
        print(f"Error extracting domain from URL: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="X10 Advanced XSS Discovery Runner")
    parser.add_argument('mode', choices=['domain', 'wildcard', 'url'], help='Mode of operation: domain, wildcard, or url')
    parser.add_argument('input', help='Domain, wildcard domain (*.domain.tld), or URL')
    parser.add_argument('--fallparams', action='store_true', help='Enable parameter discovery with fallparams')
    parser.add_argument('--subs', action='store_true', help='Include --subs in gau command (domain mode only)')
    parser.add_argument('--skip-fuzz', action='store_true', help='Skip fuzzing if fuzz/*.part files exist')
    parser.add_argument('--run-nuclei', action='store_true', help='Run nuclei only if fuzz/x10.res exists')
    args = parser.parse_args()

    if args.mode == 'domain':
        print(f"[MODE: DOMAIN] Running passive + active + x10_run + nuclei for {args.input}")
        # Only run x10_fuzz.py if --skip-fuzz is not set
        if not args.skip_fuzz:
            print("[+] Running passive + active scanning (x10_fuzz.py)...")
            fuzz_cmd = f"python3 x10_fuzz.py {shlex.quote(args.input)} true"
            if args.subs:
                fuzz_cmd += " --subs"
            run_command_in_zsh(fuzz_cmd)
        else:
            print("[+] Skipping passive + active scanning (x10_fuzz.py) due to --skip-fuzz")
        
        # Always run fallparams or x9 on existing files
        urls_to_scan = []
        if args.fallparams:
            print("[+] Running fallparams pipeline on existing files...")
            output_file = os.path.join('fuzz', 'x10.res')
            domain_files = group_files_by_domain()
            urls_to_scan = run_fallparams_on_files(domain_files, output_file)
        else:
            print("[+] Running XSS pipeline on existing files...")
            output_file = os.path.join('fuzz', 'x10.res')
            domain_files = group_files_by_domain()
            urls_to_scan = run_x9_on_files(domain_files, output_file)
        
        nuclei_output = os.path.join('fuzz', 'x10.res')
        if args.run_nuclei:
            if os.path.exists(nuclei_output):
                print("[+] Running nuclei (--run-nuclei) because fuzz/x10.res exists.")
                batch_run_nuclei(urls_to_scan , args.input)
            else:
                print("[+] Skipping nuclei (--run-nuclei) because fuzz/x10.res does not exist.")
        else:
            print("[+] Running nuclei (default behavior)...")
            batch_run_nuclei(urls_to_scan , args.input)

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
        
        # Only run x10_fuzz.py if --skip-fuzz is not set
        if not args.skip_fuzz:
            print("[+] Running passive + active scanning (x10_fuzz.py)...")
            fuzz_cmd = f"python3 x10_fuzz.py {shlex.quote(args.input)} true"
            if args.subs:
                fuzz_cmd += " --subs"
            run_command_in_zsh(fuzz_cmd)
        else:
            print("[+] Skipping passive + active scanning (x10_fuzz.py) due to --skip-fuzz")
        
        # Always run fallparams or x9 on existing files
        if args.fallparams:
            print("[+] Running fallparams pipeline on existing files...")
            output_file = os.path.join('fuzz', 'x10.res')
            domain_files = group_files_by_domain()
            urls_to_scan = run_fallparams_on_files(domain_files, output_file)
        else:
            print("[+] Running XSS pipeline on existing files...")
            output_file = os.path.join('fuzz', 'x10.res')
            domain_files = group_files_by_domain()
            urls_to_scan = run_x9_on_files(domain_files, output_file)
        
        nuclei_output = os.path.join('fuzz', 'x10.res')
        if args.run_nuclei:
            if os.path.exists(nuclei_output):
                print("[+] Running nuclei (--run-nuclei) because fuzz/x10.res exists.")
                batch_run_nuclei(urls_to_scan , domain)
            else:
                print("[+] Skipping nuclei (--run-nuclei) because fuzz/x10.res does not exist.")
        else:
            print("[+] Running nuclei (default behavior)...")
            batch_run_nuclei(urls_to_scan, domain)

    elif args.mode == 'url':
        print(f"[MODE: URL] Running x10.py + param + nuclei for {args.input}")
        output_file = os.path.join('fuzz', 'x10.res')
        ensure_directory_exists(os.path.dirname(output_file))
        
        # Extract domain from input URL
        domain = extract_domain_from_url(args.input)
        if not domain:
            print("Error: Could not extract domain from input URL")
            sys.exit(1)
        print(f"[+] Extracted domain: {domain}")
        
        # Only run x10_fuzz.py if --skip-fuzz is not set
        if not args.skip_fuzz:
            print("[+] Running passive + active scanning (x10_fuzz.py)...")
            fuzz_cmd = f"python3 x10_fuzz.py {shlex.quote(args.input)} true"
            if args.subs:
                fuzz_cmd += " --subs"
            run_command_in_zsh(fuzz_cmd)
        else:
            print("[+] Skipping passive + active scanning (x10_fuzz.py) due to --skip-fuzz")
        
        # Always run fallparams or x9 on existing files
        if args.fallparams:
            print("[+] Running fallparams for single URL on existing files...")
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
            temp_param_path = None
            try:
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_param_file:
                    for p in combined_params:
                        temp_param_file.write(f"{p}\n")
                    temp_param_path = temp_param_file.name
                x9_command = (
                    f"python3 {SCRIPT_ROUTE} "
                    f"-u {args.input} "
                    f"-gs all -vs suffix "
                    f"-v '>xxxx,xxxx\\',xxxx',xxxx\"' "
                    f"-p {temp_param_path} --rate-limit 1"
                )
                output = run_command_in_zsh(x9_command)
                fuzzed_urls = [line.strip() for line in output.splitlines() if line.strip()]
                with open(output_file, 'a') as log_file:
                    log_file.write(f"--- Fuzzed URLs for {args.input} (fallparams) ---\n{output}\n")
                batch_run_nuclei(fuzzed_urls, domain)
            finally:
                # Clean up temporary parameter file
                if temp_param_path and os.path.exists(temp_param_path):
                    try:
                        os.remove(temp_param_path)
                        print(f"[+] Cleaned up temporary parameter file: {temp_param_path}")
                    except Exception as e:
                        print(f"Warning: Failed to remove temporary parameter file {temp_param_path}: {e}")
        else:
            urls = run_x10py_generate_urls(args.input)
            batch_run_nuclei(urls, domain)
        
        nuclei_output = os.path.join('fuzz', 'x10.res')
        if args.run_nuclei:
            if os.path.exists(nuclei_output):
                print("[+] Running nuclei (--run-nuclei) because fuzz/x10.res exists.")
                batch_run_nuclei(urls, domain)
            else:
                print("[+] Skipping nuclei (--run-nuclei) because fuzz/x10.res does not exist.")
        else:
            print("[+] Running nuclei (default behavior)...")
            batch_run_nuclei(urls, domain)
    else:
        print("Invalid mode!")
        sys.exit(1)

if __name__ == "__main__":
    main()