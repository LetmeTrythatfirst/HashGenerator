#!/usr/bin/env python3

import hashlib
import argparse

def generate_hash(data, algorithm):
    try:
        # Get the hashing function from hashlib
        hash_func = getattr(hashlib, algorithm)
        # Encode the data and generate the hash
        hashed_value = hash_func(data.encode()).hexdigest()
        return hashed_value
    except AttributeError:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

def main():
    parser = argparse.ArgumentParser(description="A simple hash generator tool.")
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
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
