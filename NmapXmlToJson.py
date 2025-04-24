#!/usr/bin/env python3
"""
NmapXmlToJson - Convert Nmap XML output to simplified flat JSON format.

Usage:
    python nmap_xml_to_json.py -i input.xml [-o output.json] [-s STATUS]
    
If output.json is not specified, will write to stdout.
STATUS can be: open, closed, filtered, or all (default)
"""

import sys
import json
import argparse
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any


def parse_nmap_xml(xml_file: str, port_status_filter: str = "all") -> List[Dict[str, Any]]:
    """
    Parse an Nmap XML file and convert to a flat list of dictionaries.
    
    Args:
        xml_file: Path to the Nmap XML file
        port_status_filter: Filter results by port status (open, closed, filtered, or all)
        
    Returns:
        List of dictionaries with flattened host/port information
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML file: {e}", file=sys.stderr)
        sys.exit(1)
    
    results = []
    
    # Process each host in the scan
    for host in root.findall(".//host"):
        # Get IP address
        ip_address = None
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip_address = address.get("addr")
                break
        
        if not ip_address:
            continue  # Skip hosts without IP addresses
        
        # Get hostname if available
        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name", "")
        
        # Process each port found on this host
        ports = host.find("ports")
        if ports is None:
            continue
            
        for port in ports.findall("port"):
            port_id = port.get("portid", "")
            protocol = port.get("protocol", "").upper()
            
            # Get port state
            state = port.find("state")
            port_state = state.get("state", "") if state is not None else ""
            
            # Skip this port if it doesn't match the filter
            if port_status_filter != "all" and port_state != port_status_filter:
                continue
            
            # Get service information
            service = port.find("service")
            service_name = ""
            service_details = {}
            
            if service is not None:
                service_name = service.get("name", "")
                
                # Extract additional service details
                for attr in ["product", "version", "extrainfo", "method", "conf"]:
                    if service.get(attr):
                        service_details[attr] = service.get(attr)
                
                # Add combined product/version field if both exist
                product = service.get("product")
                version = service.get("version")
                if product or version:
                    combined = []
                    if product:
                        combined.append(product)
                    if version:
                        combined.append(version)
                    service_details["combined_info"] = " ".join(combined)
            
            # Create a record for this port
            record = {
                "fqdn": hostname,
                "ip": ip_address,
                "port": f"{protocol}/{port_id}",
                "port_status": port_state,
                "service": service_name
            }
            
            # Add detailed service info if available
            if service_details:
                record["detailed_service_info"] = service_details
                
            # Add script output if available
            scripts = port.findall("script")
            if scripts:
                script_output = {}
                for script in scripts:
                    script_id = script.get("id", "")
                    if script_id:
                        script_output[script_id] = script.get("output", "")
                
                if script_output:
                    record["script_output"] = script_output
            
            results.append(record)
    
    return results


def main():
    """
    Main function to process command line arguments and execute the conversion.
    """
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Convert Nmap XML output to simplified JSON format.')
    parser.add_argument('-i', '--input', required=True, help='Input Nmap XML file')
    parser.add_argument('-o', '--output', help='Output JSON file (default: stdout)')
    parser.add_argument('-s', '--status', choices=['all', 'open', 'closed', 'filtered'], 
                        default='all', help='Filter by port status (default: all)')
    
    args = parser.parse_args()
    
    # Parse the Nmap XML with the specified filter
    results = parse_nmap_xml(args.input, args.status)
    
    # Format the output
    json_output = json.dumps(results, indent=2)
    
    # Output to file or stdout
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"Results written to {args.output}")
        except Exception as e:
            print(f"Error writing to output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(json_output)


if __name__ == "__main__":
    main()