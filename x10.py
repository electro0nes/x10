import argparse
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote_plus
import time
import os

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "X-Forwarded-For": "127.0.0.1"
}

def print_banner():
    banner = """
    ============================================================
    Electro0ne X10 - Bug Bounty Vulnerability Discovery Tool
    ============================================================
    """

def parse_headers(header_list):
    headers = DEFAULT_HEADERS.copy()
    if header_list:
        for header in header_list:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers

def read_parameters(param_source):
    all_params = []
    sources = param_source.split(',')

    for source in sources:
        source = source.strip()
        if os.path.isfile(source):
            try:
                with open(source, 'r') as f:
                    all_params.extend([line.strip() for line in f if line.strip()])
            except FileNotFoundError:
                raise FileNotFoundError(f"File not found: {source}")
        else:
            all_params.append(source)

    return all_params

def fuzz_parameters(url, params, chunk_size, value, value_strategy):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    generated_urls = set()

    if chunk_size > 1:
        for i in range(0, len(params), chunk_size):
            chunk = params[i:i + chunk_size]
            all_params_with_value = [f"{param}={quote_plus(value)}" for param in chunk]
            new_query = parsed_url.query + '&' + '&'.join(all_params_with_value) if parsed_url.query else '&'.join(all_params_with_value)
            combined_url = urlunparse(parsed_url._replace(query=new_query))
            generated_urls.add(combined_url)
    else:
        all_params_with_value = [f"{param}={quote_plus(value)}" for param in params]
        new_query = parsed_url.query + '&' + '&'.join(all_params_with_value) if parsed_url.query else '&'.join(all_params_with_value)
        combined_url = urlunparse(parsed_url._replace(query=new_query))
        generated_urls.add(combined_url)

    if value_strategy == 'suffix':
        for param in query_params.keys():
            combined_params = query_params.copy()
            for key in combined_params:
                if key == param:
                    combined_params[key] = combined_params[key][0] + value
                else:
                    combined_params[key] = combined_params[key][0]
            combined_url = urlunparse(parsed_url._replace(query=urlencode(combined_params, doseq=True)))
            generated_urls.add(combined_url)

    elif value_strategy == 'replace':
        for param in query_params.keys():
            replace_params = query_params.copy()
            replace_params[param] = quote_plus(value)
            replace_url = urlunparse(parsed_url._replace(query=urlencode(replace_params, doseq=True)))
            generated_urls.add(replace_url)

    return generated_urls

def format_url(url, params):
    encoded_params = urlencode(params, doseq=True)
    return f"{url}?{encoded_params}" if encoded_params else url

def send_get_request(url, headers=None):
    try:
        response = requests.get(url, headers=headers)
        print(f"GET {url} - {response.status_code}")
    except requests.RequestException as e:
        print(f"GET request failed: {e}")

def send_post_request(url, data, headers=None):
    try:
        response = requests.post(url, data=data, headers=headers)
        print(f"POST {url} - {response.status_code}")
    except requests.RequestException as e:
        print(f"POST request failed: {e}")

def process_json_input(json_input):
    try:
        data = json.loads(json_input)
        urls = data['urls'] if isinstance(data['urls'], list) else [data['urls']]
        params = data.get('params', [])
        return urls, params
    except json.JSONDecodeError:
        print("Error: Invalid JSON input")
        return [], []

def main():
    parser = argparse.ArgumentParser(description="Electro0ne X10 - Bug Bounty Vulnerability Discovery Tool")

    parser.add_argument('-u', '--url', help="Single URL to target")
    parser.add_argument('-l', '--list', help="List of URLs to target")
    parser.add_argument('-j', '--json', help="JSON input with urls and parameters")
    parser.add_argument('-p', '--params', help="File or comma-separated list of parameters to fuzz")
    parser.add_argument('-c', '--chunk', help="Chunk size of parameters", type=int, default=20)
    parser.add_argument('-v', '--value', help="Comma-separated values for fuzzing", required=True)
    parser.add_argument('-gs', '--generate_strategy', choices=['normal', 'ignore', 'combine', 'all'], required=True)
    parser.add_argument('-vs', '--value_strategy', choices=['replace', 'suffix'], required=True)
    parser.add_argument('-s', '--silent', help="Silent mode", action='store_true')
    parser.add_argument('-o', '--output', help="Output format", choices=['text', 'json'], default='text')
    parser.add_argument('-m', '--method', choices=['get', 'post'], help="HTTP method", default=None)
    parser.add_argument('-d', '--data', help="Data for POST requests", default=None)
    parser.add_argument('-H', '--header', action='append', help="Custom headers")
    parser.add_argument('--rate-limit', type=int, help="Rate limit (requests per second)")
    args = parser.parse_args()

    if not args.silent:
        print_banner()
    else:
        import sys
        sys.stdout = open('/dev/null', 'w')

    values = args.value.split(',')

    if args.params:
        try:
            params = read_parameters(args.params)
        except Exception as e:
            print(f"Error reading parameters: {e}")
            return
    else:
        params = []

    all_generated_urls = []

    if args.json:
        urls, params_from_json = process_json_input(args.json)
        if not params:
            params = params_from_json
        else:
            params.extend(params_from_json)

        for url in urls:
            for val in values:
                generated_urls = fuzz_parameters(url, params, args.chunk, val, args.value_strategy)
                all_generated_urls.extend(generated_urls)

    if args.url:
        for val in values:
            generated_urls = fuzz_parameters(args.url, params, args.chunk, val, args.value_strategy)
            all_generated_urls.extend(generated_urls)

    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls = f.readlines()
                for url in urls:
                    url = url.strip()
                    for val in values:
                        generated_urls = fuzz_parameters(url, params, args.chunk, val, args.value_strategy)
                        all_generated_urls.extend(generated_urls)
        except FileNotFoundError:
            print(f"File not found: {args.list}")
            return

    if args.output == 'json':
        json_output = [{"url": urlunparse(urlparse(url)._replace(query='')), "params": parse_qs(urlparse(url).query)} for url in all_generated_urls]
        print(json.dumps(json_output, indent=2))
    else:
        for url in all_generated_urls:
            print(url)

    headers = parse_headers(args.header)
    delay = 1 / args.rate_limit if args.rate_limit else 0
    if args.method:
        for url in all_generated_urls:
            if args.method == 'get':
                send_get_request(url, headers=headers)
            elif args.method == 'post':
                data = args.data if args.data else parse_qs(urlparse(url).query)
                send_post_request(url, data, headers=headers)
            if delay:
                time.sleep(delay)

if __name__ == "__main__":
    main()