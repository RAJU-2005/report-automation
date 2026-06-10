import os
import re
import csv
import json
import pdfplumber

def parse_scan_file(file_path, original_filename):
    """
    Main router to parse the vulnerability scan report based on file extension.
    Returns a dictionary with metadata, metrics, and vulnerabilities.
    """
    ext = os.path.splitext(original_filename)[1].lower()
    
    if ext == '.pdf':
        return _parse_pdf(file_path)
    elif ext == '.csv':
        return _parse_csv(file_path)
    elif ext in ['.json', '.txt']:
        # Try JSON first
        try:
            return _parse_json(file_path)
        except Exception:
            if ext == '.txt':
                return _parse_text_fallback(file_path)
            raise
    else:
        raise ValueError(f"Unsupported file format: {ext}. Please upload PDF, CSV, or JSON.")

def _normalize_severity(sev_str):
    """
    Normalizes severity strings to CRITICAL, HIGH, MEDIUM, LOW, or INFO.
    """
    if not sev_str:
        return "INFO"
    
    clean = str(sev_str).strip().upper()
    if "CRIT" in clean or clean == "4" or "RED" in clean:
        return "CRITICAL"
    elif "HIGH" in clean or clean == "3" or "ORANGE" in clean:
        return "HIGH"
    elif "MED" in clean or clean == "2" or "YELLOW" in clean:
        return "MEDIUM"
    elif "LOW" in clean or clean == "1" or "GREEN" in clean:
        return "LOW"
    elif "INFO" in clean or clean == "0" or "BLUE" in clean:
        return "INFO"
    
    return "MEDIUM"  # Default fallback

def _compute_metrics(vulns):
    """
    Computes summary statistics for a list of vulnerabilities.
    """
    metrics = {
        "total": len(vulns),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    for v in vulns:
        sev = v.get("severity", "INFO").lower()
        if sev in metrics:
            metrics[sev] += 1
    return metrics

def _parse_pdf(file_path):
    """
    Extracts text and tables from PDF reports using pdfplumber.
    Supports multi-page table continuation and None value cleaning.
    """
    vulnerabilities = []
    metadata = {
        "scan_name": "Vulnerability Scan Report",
        "scan_date": "",
        "target_scope": "See Vulnerability Table",
        "client_name": "Acme Corp",
        "tester_name": "Security Auditor"
    }

    def _clean_val(val, default=""):
        if val is None:
            return default
        s = str(val).strip()
        if s.lower() == 'none' or s == '':
            return default
        return s

    # Table parsing state to remember column layouts across pages
    active_col_map = None
    active_num_cols = 0

    try:
        with pdfplumber.open(file_path) as pdf:
            full_text = ""
            
            # Extract metadata and search for tables across all pages
            for idx, page in enumerate(pdf.pages):
                text = page.extract_text() or ""
                full_text += text + "\n"
                
                # Try to extract tables from pages
                tables = page.extract_tables()
                for table in tables:
                    if not table or len(table) < 1:
                        continue
                    
                    # Inspect headers of the first row on this page's table
                    headers = [str(cell).strip().lower() if cell else "" for cell in table[0]]
                    
                    is_vuln_table = False
                    col_map = {}
                    
                    # Look for keywords in headers to identify a new table header
                    for c_idx, h in enumerate(headers):
                        if any(k in h for k in ["severity", "risk", "level"]):
                            col_map["severity"] = c_idx
                            is_vuln_table = True
                        elif any(k in h for k in ["vulnerability", "title", "finding", "name", "issue"]):
                            col_map["title"] = c_idx
                            is_vuln_table = True
                        elif any(k in h for k in ["host", "ip", "target", "address"]):
                            col_map["host"] = c_idx
                        elif any(k in h for k in ["port", "protocol"]):
                            col_map["port"] = c_idx
                        elif any(k in h for k in ["description", "synopsis"]):
                            col_map["description"] = c_idx
                        elif any(k in h for k in ["solution", "remediation", "fix"]):
                            col_map["remediation"] = c_idx

                    # If this row matches as a header row, we treat it as a new table start
                    if is_vuln_table and "title" in col_map:
                        active_col_map = col_map
                        active_num_cols = len(table[0])
                        start_row = 1  # Skip header row
                    else:
                        # If it does not match headers, check if it matches the size of the active table
                        if active_col_map and len(table[0]) == active_num_cols:
                            is_vuln_table = True
                            col_map = active_col_map
                            start_row = 0  # Parse from row 0 since it is data, not header!
                        else:
                            is_vuln_table = False

                    # If this table is valid, extract rows
                    if is_vuln_table and "title" in col_map:
                        for row in table[start_row:]:
                            # Skip short rows
                            if not row or len(row) <= max(col_map.values()):
                                continue
                            
                            title = _clean_val(row[col_map["title"]])
                            # Skip if empty or a repeated header row on page breaks
                            if not title or title.lower() in ["vulnerability", "title", "name", "finding"]:
                                continue
                                
                            severity = _normalize_severity(_clean_val(row[col_map["severity"]], "MEDIUM"))
                            host = _clean_val(row[col_map["host"]], "N/A")
                            port = _clean_val(row[col_map["port"]], "N/A")
                            description = _clean_val(row[col_map["description"]], "No description provided.")
                            remediation = _clean_val(row[col_map["remediation"]], "Check vendor documentation.")
                            
                            vulnerabilities.append({
                                "id": len(vulnerabilities) + 1,
                                "severity": severity,
                                "title": title,
                                "host": host,
                                "port": port,
                                "description": description,
                                "remediation": remediation
                            })

            # Extract metadata from text using regexes
            # Search for dates like YYYY-MM-DD or Month DD, YYYY
            date_match = re.search(
                r'(?:scan\s+date|date\s+of\s+scan|date|generated\s+on)[:\s]+(\d{4}[-/]\d{2}[-/]\d{2}|[a-zA-Z]+\s+\d{1,2},\s+\d{4})', 
                full_text, 
                re.IGNORECASE
            )
            if date_match:
                metadata["scan_date"] = date_match.group(1).strip()
                
            # Search for Target IP or Scope
            target_match = re.search(
                r'(?:target|scope|ip\s+address|host(?:name)?s)[:\s]+([^\n]+)', 
                full_text, 
                re.IGNORECASE
            )
            if target_match:
                metadata["target_scope"] = target_match.group(1).strip()
                
            # Search for Client / Company
            client_match = re.search(
                r'(?:client|company|customer|organization)[:\s]+([^\n]+)', 
                full_text, 
                re.IGNORECASE
            )
            if client_match:
                metadata["client_name"] = client_match.group(1).strip()

            # Search for Scanner name
            scanner_match = re.search(
                r'(?:scanner|scan\s+engine|tool)[:\s]+([^\n]+)', 
                full_text, 
                re.IGNORECASE
            )
            if scanner_match:
                metadata["scan_name"] = scanner_match.group(1).strip() + " Report"

            # Fallback text parsing if no tables were extracted
            if not vulnerabilities:
                vulnerabilities = _parse_text_lines_fallback(full_text)

    except Exception as e:
        print(f"Error reading PDF: {e}")
        pass

    if not metadata.get("scan_date"):
        import datetime
        metadata["scan_date"] = datetime.date.today().strftime("%Y-%m-%d")

    return {
        "metadata": metadata,
        "metrics": _compute_metrics(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

def _parse_text_lines_fallback(text):
    """
    Helper to extract findings when tables can't be parsed directly.
    Scans line-by-line for severities followed by vulnerability titles.
    """
    vulns = []
    lines = text.split('\n')
    current_vuln = None
    
    # Common vulnerability patterns
    # e.g., "[High] SQL Injection" or "Severity: Critical - MS17-010"
    severity_pattern = re.compile(
        r'(?:\[|\b)(critical|high|medium|low)(?:\]|\b)[:\s-]*(.*)', 
        re.IGNORECASE
    )
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
            
        match = severity_pattern.search(line)
        if match:
            if current_vuln:
                vulns.append(current_vuln)
                
            severity = _normalize_severity(match.group(1))
            title = match.group(2).strip()
            if not title and i + 1 < len(lines):
                title = lines[i+1].strip()
                
            current_vuln = {
                "id": len(vulns) + 1,
                "severity": severity,
                "title": title or "Unnamed Vulnerability",
                "host": "N/A",
                "port": "N/A",
                "description": "",
                "remediation": ""
            }
        elif current_vuln:
            # Append text to description or check for hosts
            if "description" in line.lower() or "details" in line.lower():
                current_vuln["description"] = line
            elif "solution" in line.lower() or "remediation" in line.lower() or "fix" in line.lower():
                current_vuln["remediation"] = line
            elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line):
                current_vuln["host"] = line
            else:
                if len(current_vuln["description"]) < 300:
                    current_vuln["description"] += " " + line

    if current_vuln:
        vulns.append(current_vuln)
        
    # Standardize output
    for v in vulns:
        v["description"] = v["description"].strip() or "No description details extracted."
        v["remediation"] = v["remediation"].strip() or "Apply the latest security patches."
        
    return vulns

def _parse_csv(file_path):
    """
    Parses CSV scan reports. Custom handles Nessus-style formats.
    """
    vulnerabilities = []
    metadata = {
        "scan_name": "CSV Vulnerability Export",
        "scan_date": "",
        "target_scope": "Various Hosts",
        "client_name": "Acme Corp",
        "tester_name": "Security Auditor"
    }

    try:
        # Check encoding
        encoding = 'utf-8'
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read(1000)
        except UnicodeDecodeError:
            encoding = 'latin-1'

        with open(file_path, mode='r', newline='', encoding=encoding) as f:
            reader = csv.reader(f)
            # Read header row
            try:
                headers = next(reader)
            except StopIteration:
                return {"metadata": metadata, "metrics": _compute_metrics([]), "vulnerabilities": []}

            headers_lower = [h.strip().lower() for h in headers]
            
            # Map column indices
            col_map = {}
            for idx, h in enumerate(headers_lower):
                if h in ['risk', 'severity', 'severity rating']:
                    col_map['severity'] = idx
                elif h in ['name', 'vulnerability name', 'title', 'plugin name']:
                    col_map['title'] = idx
                elif h in ['host', 'ip', 'ip address', 'hostname']:
                    col_map['host'] = idx
                elif h in ['port', 'port number']:
                    col_map['port'] = idx
                elif h in ['description', 'synopsis']:
                    col_map['description'] = idx
                elif h in ['solution', 'remediation', 'fix']:
                    col_map['remediation'] = idx

            # If it's a Nessus CSV
            is_nessus = 'plugin id' in headers_lower and 'risk' in headers_lower
            
            for row in reader:
                if not row:
                    continue
                
                title = ""
                severity = "MEDIUM"
                host = "N/A"
                port = "N/A"
                description = ""
                remediation = ""

                if is_nessus:
                    # Nessus columns mapping
                    try:
                        title = row[headers_lower.index('name')]
                        severity = _normalize_severity(row[headers_lower.index('risk')])
                        host = row[headers_lower.index('host')]
                        port = row[headers_lower.index('port')]
                        description = row[headers_lower.index('description')]
                        remediation = row[headers_lower.index('solution')]
                    except Exception:
                        pass
                else:
                    # Generic CSV map
                    if 'title' in col_map and col_map['title'] < len(row):
                        title = row[col_map['title']]
                    if 'severity' in col_map and col_map['severity'] < len(row):
                        severity = _normalize_severity(row[col_map['severity']])
                    if 'host' in col_map and col_map['host'] < len(row):
                        host = row[col_map['host']]
                    if 'port' in col_map and col_map['port'] < len(row):
                        port = row[col_map['port']]
                    if 'description' in col_map and col_map['description'] < len(row):
                        description = row[col_map['description']]
                    if 'remediation' in col_map and col_map['remediation'] < len(row):
                        remediation = row[col_map['remediation']]

                # Skip info-level vulnerabilities to avoid bloating the report
                # unless there are only info levels
                if severity == "INFO" and len(vulnerabilities) > 0:
                    continue
                    
                if title:
                    vulnerabilities.append({
                        "id": len(vulnerabilities) + 1,
                        "severity": severity,
                        "title": title.strip(),
                        "host": host.strip() or "N/A",
                        "port": port.strip() or "N/A",
                        "description": description.strip() or "No description provided.",
                        "remediation": remediation.strip() or "Apply manufacturer patches."
                    })
                    
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        pass

    import datetime
    metadata["scan_date"] = datetime.date.today().strftime("%Y-%m-%d")
    
    return {
        "metadata": metadata,
        "metrics": _compute_metrics(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

def _parse_json(file_path):
    """
    Parses a JSON-based vulnerability report.
    Supports a general structure and normalizes key names.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    metadata = {
        "scan_name": "JSON Vulnerability Import",
        "scan_date": "",
        "target_scope": "N/A",
        "client_name": "Acme Corp",
        "tester_name": "Security Auditor"
    }
    
    # Try parsing metadata
    if "metadata" in data:
        metadata.update(data["metadata"])
    elif "scan_info" in data:
        metadata["scan_name"] = data["scan_info"].get("title", metadata["scan_name"])
        metadata["scan_date"] = data["scan_info"].get("date", "")
        metadata["target_scope"] = data["scan_info"].get("target", "N/A")
        
    if not metadata.get("scan_date"):
        import datetime
        metadata["scan_date"] = datetime.date.today().strftime("%Y-%m-%d")

    vulnerabilities = []
    
    # Try to find the vulnerabilities list
    raw_list = []
    if isinstance(data, list):
        raw_list = data
    elif "vulnerabilities" in data:
        raw_list = data["vulnerabilities"]
    elif "findings" in data:
        raw_list = data["findings"]
    elif "results" in data:
        raw_list = data["results"]
        
    for idx, item in enumerate(raw_list):
        if not isinstance(item, dict):
            continue
            
        title = item.get("title", item.get("name", item.get("vulnerability", "")))
        severity = _normalize_severity(item.get("severity", item.get("risk", item.get("level", "MEDIUM"))))
        host = item.get("host", item.get("ip", item.get("target", "N/A")))
        port = item.get("port", "N/A")
        description = item.get("description", item.get("synopsis", "No description provided."))
        remediation = item.get("remediation", item.get("solution", item.get("fix", "No solution provided.")))
        
        if title:
            vulnerabilities.append({
                "id": len(vulnerabilities) + 1,
                "severity": severity,
                "title": title,
                "host": host,
                "port": str(port),
                "description": description,
                "remediation": remediation
            })

    return {
        "metadata": metadata,
        "metrics": _compute_metrics(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

def _parse_text_fallback(file_path):
    """
    Fallback parser for unstructured plain text files.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    return {
        "metadata": {
            "scan_name": "Text Vulnerability Import",
            "scan_date": "",
            "target_scope": "Unknown",
            "client_name": "Acme Corp",
            "tester_name": "Security Auditor"
        },
        "metrics": {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        },
        "vulnerabilities": _parse_text_lines_fallback(text)
    }
