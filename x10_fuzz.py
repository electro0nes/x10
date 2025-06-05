# x9_fuzz.py
import subprocess
import sys
import os
from urllib.parse import urlparse
from dotenv import load_dotenv  
import argparse

load_dotenv()

X9_PASSIVE = os.getenv("X9_PASSIVE")

def ensure_directory_exists(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")

def run_command_in_zsh(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error occurred:", result.stderr)
            return None
        return result.stdout
    except subprocess.CalledProcessError as exc:
        print("Status: FAIL", exc.returncode, exc.output)
        return None

def parse_domain(url):
    """Extract the domain from a URL."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

def normalize_url(url):
    """Convert HTTP to HTTPS and remove :80 or :443 from URLs."""
    parsed = urlparse(url)

    # Remove :80 for http and :443 for https
    netloc = parsed.netloc
    if parsed.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif parsed.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Replace scheme with https
    scheme = "https"

    # Rebuild the URL
    normalized_url = f"{scheme}://{netloc}{parsed.path}"
    if parsed.query:
        normalized_url += f"?{parsed.query}"
    if parsed.fragment:
        normalized_url += f"#{parsed.fragment}"

    return normalized_url

def split_and_save_urls(urls, base_domain, lines_per_file=1000):
    """Splits a list of URLs into multiple files with a specific number of URLs per file."""
    ensure_directory_exists('fuzz')
    
    total_urls = len(urls)
    print(f"Total URLs to process: {total_urls}")
    
    for i in range(0, total_urls, lines_per_file):
        part_number = (i // lines_per_file) + 1
        chunk = urls[i:i + lines_per_file]
        
        if chunk:  # Only save if we have URLs in this chunk
            part_file_name = os.path.join('fuzz', f"{base_domain}.part{part_number}")
            with open(part_file_name, 'w') as part_file:
                part_file.writelines(url + '\n' for url in chunk)
            print(f"Saved {len(chunk)} URLs to {part_file_name}")

def cleanup_files(domain):
    """Clean up temporary files related to the domain (.passive and .katana)."""
    extensions = [".passive", ".katana"]
    for ext in extensions:
        file_path = os.path.join('fuzz', f"{domain}{ext}")
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Cleaned up {file_path}")

def main(domain, run_katana, use_subs=False):
    urls = []

    # Run X9_PASSIVE to get URLs
    print(f"Running x10_passive for domain: {domain}")
    passive_file = os.path.join('fuzz', f"{domain}.passive")

    if not os.path.exists(passive_file):
        x9_passive_command = f"python3 x10_passive.py {domain}"
        if use_subs:
            x9_passive_command += " --subs"
        run_command_in_zsh(x9_passive_command)

    if os.path.exists(passive_file):
        with open(passive_file, 'r') as file:
            urls.extend(file.read().splitlines())
        print(f"Read {len(urls)} URLs from passive file")

    # Normalize URLs (https + remove :80/:443)
    urls = [normalize_url(url) for url in urls]

    # Run katana only on the provided domain
    katana_urls = []
    if run_katana.lower() == 'true':
        print(f"Running x10_active for domain: {domain}")
        katana_command = f"python3 x10_active.py {domain}"
        run_command_in_zsh(katana_command)
        katana_file = os.path.join('fuzz', f"{domain}.katana")
        if os.path.exists(katana_file):
            with open(katana_file, 'r') as f:
                host_katana_urls = f.read().splitlines()
                host_katana_urls = [normalize_url(url) for url in host_katana_urls]
                katana_urls.extend(host_katana_urls)
            print(f"Added {len(host_katana_urls)} URLs from {katana_file}")
        else:
            print(f"No katana output file found: {katana_file}")

    # Add katana URLs to the main list
    urls.extend(katana_urls)

    # Remove duplicates
    urls = list(dict.fromkeys(urls))
    print(f"Total unique URLs: {len(urls)}")

    # Split and save
    if urls:
        print("Splitting URLs into parts...")
        split_and_save_urls(urls, domain)
    else:
        print("No URLs found.")

    # Clean up
    cleanup_files(domain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="X10 Fuzz - Passive/Active URL collector with optional --subs for gau.")
    parser.add_argument('domain', help='Domain to scan')
    parser.add_argument('run_katana', help='Whether to run katana (true/false)')
    parser.add_argument('--subs', action='store_true', help='Include --subs in gau command')
    args = parser.parse_args()
    main(args.domain, args.run_katana, use_subs=args.subs)