# Nmap XML to JSON Converter
![No External Dependencies](/.github/badges/no-dependencies.svg)
![Py](/.github/badges/python.svg)

A simple and efficient utility to convert Nmap XML scan results into a flat JSON structure.

## Overview

This tool parses Nmap XML output files and generates a simplified, flat JSON structure that's easy to process and query. It extracts key information such as:

- IP addresses
- Hostnames
- Open ports
- Services
- Service details
- Script output

## Usage

### Command Line

```bash
python NmapXmlToJson.py -i input.xml [-o output.json] [-s STATUS]
```

Where:
- `-i, --input`: Input Nmap XML file (required)
- `-o, --output`: Output JSON file (if not specified, prints to stdout)
- `-s, --status`: Filter by port status (`open`, `closed`, `filtered`, or `all`) (default: `all`)

For example, to extract only open ports:

```bash
python NmapXmlToJson.py -i scan.xml -o results.json -s open
```

## Output Format

The output is a JSON array containing objects with the following structure:

```json
[
  {
    "fqdn": "example.com",
    "ip": "192.168.1.1",
    "port": "TCP/80",
    "port_status": "open",
    "service": "http",
    "detailed_service_info": {
      "product": "nginx",
      "version": "1.18.0",
      "combined_info": "nginx 1.18.0",
      "extrainfo": "Ubuntu",
      "method": "probed",
      "conf": "10"
    },
    "script_output": {
      "http-server-header": "nginx/1.18.0 (Ubuntu)",
      "http-title": "Welcome to nginx!"
    }
  },
]
```

## Features

- **Lightweight**: No external dependencies beyond the Python standard library
- **Fast**: Efficiently parses large XML files
- **Detailed**: Captures all important information from Nmap scans

## Requirements

- Python3
