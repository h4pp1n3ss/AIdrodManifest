#!/usr/bin/env python3
"""
AndroidManifest Decoder
Supports:
  - Plain XML AndroidManifest.xml (from source projects)
  - Binary AndroidManifest.xml (from compiled APKs)
  - APK files (extracts and decodes the manifest automatically)
"""

import sys
import os
import xml.etree.ElementTree as ET
from utils import (
    is_apk,
    is_binary_xml,
    extract_manifest_from_apk,
    pretty_print_xml,
    decode_binary_xml
)
from utils.llm import analyze_manifest

def print_section(title: str, width: int = 60):
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python manifest_decoder.py <AndroidManifest.xml | file.apk>")
        print()
        print("Examples:")
        print("  python manifest_decoder.py AndroidManifest.xml")
        print("  python manifest_decoder.py MyApp.apk")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"[!] File not found: '{file_path}'")
        sys.exit(1)

    print(f"[*] File: {os.path.abspath(file_path)}")
    print(f"[*] Size: {os.path.getsize(file_path):,} bytes")

    # Step 1: Read manifest bytes
    if is_apk(file_path):
        print("[+] Format: APK — extracting AndroidManifest.xml...")
        try:
            manifest_data = extract_manifest_from_apk(file_path)
            print(f"[+] Manifest size: {len(manifest_data):,} bytes")
        except FileNotFoundError as e:
            print(f"[!] {e}")
            sys.exit(1)
    else:
        with open(file_path, 'rb') as f:
            manifest_data = f.read()

    # Step 2: Decode
    if is_binary_xml(manifest_data):
        print("[+] Encoding: Binary XML (AXML)")
        try:
            xml_text = decode_binary_xml(manifest_data)
        except RuntimeError as e:
            print(f"\n[!] {e}")
            sys.exit(1)
    else:
        print("[+] Encoding: Plain XML")
        try:
            xml_text = pretty_print_xml(manifest_data)
        except ET.ParseError as e:
            print(f"[!] XML parse error: {e}")
            sys.exit(1)

    # Step 3: Display
    print_section("ANDROID MANIFEST")
    print(xml_text)

    # Step 4: LLM attack surface analysis
    analyze_manifest(xml_text)


if __name__ == "__main__":
    main()
