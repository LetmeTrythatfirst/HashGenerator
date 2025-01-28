#!/usr/bin/env python3

import hashlib
import argparse
import requests
import json

# Your VirusTotal API key
API_KEY = "8c4512bd6e2767361a79d7b28c05efacced80dc2a81c5bd81e25d53e19f823f5"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Function to generate hash
def generate_hash(data, algorithm):
    try:
        # Get the hashing function from hashlib
        hash_func = getattr(hashlib, algorithm)
        # Encode the data and generate the hash
        hashed_value = hash_func(data.encode()).hexdigest()
        return hashed_value
    except AttributeError:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

# Function to check hash with VirusTotal
def check_virus_total(hash_value):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(f"{VT_URL}{hash_value}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        # Check the scan report status
        if 'data' in data:
            attributes = data['data']['attributes']
            scan_results = attributes['last_analysis_stats']
            malicious = scan_results.get('malicious', 0)
            harmless = scan_results.get('harmless', 0)
            suspicious = scan_results.get('suspicious', 0)
            if malicious > 0:
                return f"Malicious: {malicious} detectors flagged it"
            else:
                return f"Harmless: {harmless} detectors passed it"
        else:
            return "No scan data found."
    else:
        return f"Error: {response.status_code}, unable to fetch data."

def main():
    parser = argparse.ArgumentParser(description="A simple hash generator and VirusTotal checker.")
    parser.add_argument(
        "data", type=str, help="The input string to hash."
    )
    parser.add_argument(
        "--algorithm",
        type=str,
        default="sha256",
        choices=hashlib.algorithms_available,
        help="The hashing algorithm to use (default: sha256).",
    )

    args = parser.parse_args()

    try:
        hash_value = generate_hash(args.data, args.algorithm)
        print(f"Input: {args.data}")
        print(f"Algorithm: {args.algorithm}")
        print(f"Hash: {hash_value}")
        
        # Check the hash with VirusTotal
        result = check_virus_total(hash_value)
        print(f"VirusTotal result: {result}")
        
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
