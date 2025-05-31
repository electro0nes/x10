#!/usr/bin/env python3

import os
import sys
import subprocess
from urllib.parse import urlparse, urlsplit

COLOR_GRAY = "\033[90m"

EXT_FILTER = (
    "json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,"
    "ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,"
    "woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip"
)

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")

def extract_domain(url):
    """Extract domain from URL or return input if it's a domain."""
    if url.startswith("http"):
        return urlsplit(url).netloc
    return url.strip()

def run_katana(url, host):
    """Run katana command and write output to fuzz/host.katana"""
    katana_cmd = (
        f"echo {url} | katana "
        f"-js-crawl -jsluice -known-files all "
        f"-automatic-form-fill -silent "
        f"-crawl-scope {host} "
        f"-extension-filter {EXT_FILTER}"
    )
    print(f"{COLOR_GRAY}Running katana on: {url}{COLOR_GRAY}")
    try:
        ensure_directory_exists('fuzz')
        with open(os.path.join('fuzz', f"{host}.katana"), "w") as output_file:
            proc = subprocess.run(
                ["zsh", "-c", katana_cmd],
                stdout=output_file,
                stderr=subprocess.PIPE,
                text=True
            )
            if proc.returncode != 0:
                print(f"Katana error on {url}: {proc.stderr}")
    except Exception as e:
        print(f"Error running katana: {e}")

def get_input_source():
    """Read input from stdin or from a file/CLI arg."""
    if not sys.stdin.isatty():
        return [line.strip() for line in sys.stdin if line.strip()]
    elif len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], "r") as f:
            return [line.strip() for line in f if line.strip()]
    elif len(sys.argv) > 1:
        return [sys.argv[1].strip()]
    else:
        return []

def main():
    urls = get_input_source()
    if not urls:
        print("Usage examples:")
        print("  echo domain.com | python3 x10_active.py")
        print("  cat domains.txt | python3 x10_active.py")
        sys.exit(1)

    for url in urls:
        host = extract_domain(url)
        if host:
            run_katana(url, host)

if __name__ == "__main__":
    main()