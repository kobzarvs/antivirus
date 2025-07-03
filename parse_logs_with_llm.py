"""
parse_logs_with_llm.py
------------------------------------
Parse various Windows AV log files for malware detections in a given time range
using local LLM models via Ollama or LM Studio.
"""

import argparse
import datetime
import json
import re
import sys
import pathlib
import requests
import glob
import calendar

# --- Configuration ---
OLLAMA_URL = "http://localhost:11434/api/generate"
LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
MAX_CHARS_PER_CHUNK = 20000
LLM_TIMEOUT = 300
SYSTEM_PROMPT = r"""### ROLE ###
You are an automated data extraction bot specialized in cybersecurity.

### TASK ###
Your mission is to parse raw antivirus log entries and extract only the malware detection events.

### INSTRUCTIONS ###
1.  **Identify Detection Events:** Scan the logs for entries indicating a threat. Keywords to look for include **detected**, **quarantined**, **deleted**, **found**, **threat**, and **"registered virus component"**.
2.  **Extract Key Data:** For each detection event, you must extract two pieces of information:
    *   The malware signature.
    *   The precise timestamp of the event.
3.  **One Event Per Line:** Treat each line as a separate potential event. A single line can contain at most one malware signature.
4.  **Handle Different Log Formats:**
    *   **Per-Line Timestamps:** Most logs have a timestamp on every line. Use that line's timestamp for the detection.
    *   **Global Timestamps:** Some logs have a single "Start time:" or a timestamp in the header line. You MUST use this single timestamp for ALL subsequent detections found in that log block.
    *   **Columnar Data:** If the log is structured in columns and one column is named `threat`, you MUST extract the value from that column as the signature.
5.  **Ignore Non-Detection Events:** You MUST ignore all routine operational messages.

### OUTPUT FORMAT ###
- Your output MUST be a valid JSON array.
- Each object in the array represents a single detection and MUST contain exactly two keys: `signature` and `timestamp`.
- **signature**: Provide the clean name of the malware. You MUST strip all prefixes, such as `Virus:`, `Malware:`, `Threat:`, `Name=`, etc.
- **timestamp**: Format the event time strictly as `YYYY-MM-DD HH:MM:SS`.
- If no detection events are found, you MUST return an empty array: `[]`.

### EXAMPLE ###
**Input Log Lines:**
2025-01-01 10:15:45 G DATA INFO Virus found Name=EICAR_Test_File Path=C:\Users\Downloads\eicar.com Action=Deleted
Start time: 01.07.2025 17:20:40
...
Object: eicar.com.txt
	Path: C:\Users\Пользователь\Downloads
	Status: File quarantined.
	Virus: EICAR-Test-File (not a virus)
path                        threat           timestamp
\\?\D:\Keygen.exe         Application.KeyGen.GO 2025-07-01 23:53:15

**Required JSON Output:**
[
  {
    "signature": "EICAR_Test_File",
    "timestamp": "2025-01-01 10:15:45"
  },
  {
    "signature": "EICAR-Test-File (not a virus)",
    "timestamp": "2025-07-01 17:20:40"
  },
  {
    "signature": "Application.KeyGen.GO",
    "timestamp": "2025-07-01 23:53:15"
  }
]
"""

# --- Universal Timestamp Parsers (for line-based logs) ---

def parse_timestamp_drweb(line):
    try:
        month_abbr_to_num = {name: num for num, name in enumerate(calendar.month_abbr) if num}
        parts = line.split()
        if len(parts) < 2: return None
        date_str, time_str = parts[0], parts[1]
        year, month_name, day = date_str.split('-')
        month = month_abbr_to_num.get(month_name)
        if not month: return None
        ts_str = f"{year}-{month:02d}-{int(day):02d} {time_str.split('.')[0]}"
        return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, IndexError):
        return None

def parse_timestamp_mpdetection(line):
    try:
        match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if match: return datetime.datetime.fromisoformat(match.group(1))
        return None
    except ValueError:
        return None

def parse_timestamp_standard(line):
    try:
        parts = line.split()
        if len(parts) < 2: return None
        ts_str = " ".join(parts[:2])
        return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

def parse_timestamp_db_dump(line):
    try:
        match = re.search(r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})$', line)
        if match: return datetime.datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
        return None
    except ValueError:
        return None

def parse_line_for_timestamp(line):
    """Tries a pipeline of parsing functions. Returns the first valid timestamp."""
    parsers = [parse_timestamp_mpdetection, parse_timestamp_drweb, parse_timestamp_standard, parse_timestamp_db_dump]
    for parser in parsers:
        if timestamp := parser(line):
            return timestamp
    return None

# --- Log Format Sniffing and Processing ---

def get_log_format(lines):
    """Sniffs the log content to determine its format."""
    if not lines:
        return 'unknown'
    # G-Data v2 has a unique tab-separated header
    if '\t' in lines[0] and 'Virus check' in lines[0]:
        return 'gdata_v2'
    # Add other format sniffers here if needed
    return 'line_based'

def process_gdata_v2(lines, start_dt, end_dt):
    """Handles G-Data logs with a single global timestamp."""
    try:
        header_parts = lines[0].split('\t')
        if len(header_parts) > 2:
            ts = datetime.datetime.strptime(header_parts[2], "%Y-%m-%d %H:%M:%S")
            if start_dt <= ts <= end_dt:
                # Return all relevant log lines (after header description)
                return [line.strip() for line in lines[9:] if line.strip()]
    except (ValueError, IndexError):
        return []
    return []

def process_line_based(lines, start_dt, end_dt):
    """Handles logs with a timestamp on each line."""
    lines_to_yield = []
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        ts = parse_line_for_timestamp(line)
        if ts and start_dt <= ts <= end_dt:
            lines_to_yield.append(line.strip())
    return lines_to_yield

def filter_log_lines(path: pathlib.Path, start_dt, end_dt):
    """Main router for filtering logs based on their format."""
    encodings = ['utf-8', 'utf-16', 'latin1', 'cp1251']
    for encoding in encodings:
        try:
            with path.open(encoding=encoding, errors='ignore') as f:
                lines = f.readlines()
            
            log_format = get_log_format(lines)

            if log_format == 'gdata_v2':
                return process_gdata_v2(lines, start_dt, end_dt)
            elif log_format == 'line_based':
                return process_line_based(lines, start_dt, end_dt)
            else:
                # If format is unknown, try line-based as a default
                return process_line_based(lines, start_dt, end_dt)
        except (UnicodeDecodeError, UnicodeError):
            continue
    print(f"Warning: Could not decode file {path} with any supported encodings.", file=sys.stderr)
    return []

# --- Core Application Logic ---

def get_log_files(log_pattern: str):
    # ... (this function remains the same)
    if '*' in log_pattern or '?' in log_pattern:
        files = glob.glob(log_pattern, recursive=True)
        if not files:
            print(f"No files found matching pattern: {log_pattern}", file=sys.stderr)
            sys.exit(1)
        return [pathlib.Path(f) for f in sorted(files)]
    else:
        log_path = pathlib.Path(log_pattern)
        if not log_path.exists():
            print(f"Log file not found: {log_path}", file=sys.stderr)
            sys.exit(1)
        return [log_path]

def create_chunks(lines):
    # ... (this function remains the same)
    chunks = []
    current_chunk = []
    current_length = 0
    for line in lines:
        if current_length + len(line) > MAX_CHARS_PER_CHUNK:
            chunks.append("\n".join(current_chunk))
            current_chunk = []
            current_length = 0
        current_chunk.append(line)
        current_length += len(line)
    if current_chunk:
        chunks.append("\n".join(current_chunk))
    return chunks

def call_llm(model: str, prompt: str, provider: str = "ollama", timeout: int = LLM_TIMEOUT):
    # ... (this function remains the same)
    if provider.lower() == "lmstudio":
        return call_llm_lmstudio(model, prompt, timeout)
    else:
        return call_llm_ollama(model, prompt, timeout)

def call_llm_ollama(model: str, prompt: str, timeout: int = LLM_TIMEOUT):
    # ... (this function remains the same)
    payload = {"model": model, "prompt": prompt, "system": SYSTEM_PROMPT, "stream": False}
    r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    r.raise_for_status()
    response_text = r.json().get("response", "")
    return parse_llm_response(response_text)

def call_llm_lmstudio(model: str, prompt: str, timeout: int = LLM_TIMEOUT):
    # ... (this function remains the same)
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
        "stream": False, "temperature": 0.1
    }
    try:
        r = requests.post(LMSTUDIO_URL, json=payload, timeout=timeout)
        r.raise_for_status()
        response_text = r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        return parse_llm_response(response_text)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            print(f"Error: 400 Bad Request. This often means the model '{model}' is not loaded or available in LM Studio.", file=sys.stderr)
        raise e

def parse_llm_response(response_text: str):
    # ... (this function remains the same)
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        content = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL)
        try:
            return json.loads(content.strip())
        except json.JSONDecodeError:
            json_match = re.search(r'\[\s*\{.*?\}\s*\]', content, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError: pass
        print(f"Warning: Could not parse LLM response as JSON. Response: {response_text[:500]}...", file=sys.stderr)
        return []

def main():
    parser = argparse.ArgumentParser(description="Parse AV log with LLM for malware detections.")
    parser.add_argument("--log", required=True, help="Path to log file or glob pattern (e.g., '*.log')")
    parser.add_argument("--start", required=True, help="Start datetime YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--end", required=True, help="End datetime YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--model", default="qwen:8b", help="Model name")
    parser.add_argument("--provider", default="ollama", choices=["ollama", "lmstudio"], help="LLM provider")
    args = parser.parse_args()

    start_dt = datetime.datetime.strptime(args.start, "%Y-%m-%d %H:%M:%S")
    end_dt = datetime.datetime.strptime(args.end, "%Y-%m-%d %H:%M:%S")

    log_files = get_log_files(args.log)
    
    all_relevant_lines = []
    file_count = 0
    for log_path in log_files:
        print(f"Filtering file: {log_path}", file=sys.stderr)
        lines = filter_log_lines(log_path, start_dt, end_dt)
        if lines:
            file_count += 1
            all_relevant_lines.append(f"=== Log File: {log_path.name} ===")
            all_relevant_lines.extend(lines)
            all_relevant_lines.append("=" * 20)

    if not all_relevant_lines:
        print("No relevant log entries found in the specified date range.", file=sys.stderr)
        print("[]")
        return

    print(f"Found {len(all_relevant_lines) - (2 * file_count)} relevant log entries.", file=sys.stderr)

    log_chunks = create_chunks(all_relevant_lines)
    print(f"Split logs into {len(log_chunks)} chunks for processing.", file=sys.stderr)

    final_results = []
    for i, chunk in enumerate(log_chunks):
        print(f"Querying LLM for chunk {i+1}/{len(log_chunks)}...", file=sys.stderr)
        try:
            result = call_llm(args.model, chunk, args.provider)
            if isinstance(result, list) and result:
                final_results.extend(result)
        except requests.exceptions.RequestException as e:
            print(f"Error calling LLM for chunk {i+1}: {e}", file=sys.stderr)
            continue

    print(json.dumps(final_results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()