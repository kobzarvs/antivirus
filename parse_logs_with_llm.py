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
MAX_CHARS_PER_CHUNK = 5000
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

### LOG FORMAT EXAMPLES ###
**Dr.Web format:**
```
2025-Jul-01 18:47:24.322968 [ 4300] [INF] [LOG] Starting service...
2025-Jul-01 18:47:24.465171 [ 5656] [INF] [service] [service_main] !Set SERVICE_RUNNING successfully...Start
```

**Microsoft Defender format:**
```
2025-06-30T16:46:39.281 DETECTION Virus:DOS/EICAR_Test_File file:C:\Users\Пользователь\Downloads\eicar.com.txt
2025-06-30T16:48:31.855 DETECTION Virus:DOS/EICAR_Test_File file:C:\Users\Пользователь\Downloads\eicar.com.txt
```

**Columnar format (database dump) first chunk:**
```
| quarId                               | path                                                                                                                                                                                                                   | threat                        |   status |   size |   quartime |
|:-------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------|---------:|-------:|-----------:|
| 3f4bf7b4-d635-4c6c-917e-fa2735aac905 | \\?\D:\DISTRIB\WinRAR v5.20 Beta 2\Keygen\Keygen.exe                                                                                                                                                                   | Application.KeyGen.GO         |        3 | 104960 | 1751403195 |
| d1727ba0-4712-4961-b9fd-eaf925ccbc73 | hklm\software\wow6432node\microsoft\internet explorer\main\default_search_url                                                                                                                                          |                               |        3 |    338 | 1751403196 |
| 963e4e68-acbb-49c1-8575-3f055192a648 | <System>=>HKEY_USERS\.DEFAULT\SOFTWARE\CLASSES\LOCAL SETTINGS\MRTCACHE\C:%5CPROGRAM FILES%5CWINDOWSAPPS%5CMICROSOFT.STOREPURCHASEAPP_11811.1001.18.0_X64__8WEKYB3D8BBWE%5CRESOURCES.PRI\1D5AD0BFA5DAB5A\D0332875\@{C:\P|                               |        1 |    156 | 1751403218 |
| b7ee48a6-0c13-441c-bed3-815ca63c1a6a | \\?\C:\Users\Пользователь\Downloads\eicar.com.txt                                                                                                                                                                      | EICAR-Test-File (not a virus) |        3 |     68 | 1751406485 |
```

**Columnar format (database dump) other chunks:**
```
| 3f4bf7b4-d635-4c6c-917e-fa2735aac905 | \\?\D:\DISTRIB\WinRAR v5.20 Beta 2\Keygen\Keygen.exe                                                                                                                                                                   | Application.KeyGen.GO         |        3 | 104960 | 1751403195 |
| d1727ba0-4712-4961-b9fd-eaf925ccbc73 | hklm\software\wow6432node\microsoft\internet explorer\main\default_search_url                                                                                                                                          |                               |        3 |    338 | 1751403196 |
| 963e4e68-acbb-49c1-8575-3f055192a648 | <System>=>HKEY_USERS\.DEFAULT\SOFTWARE\CLASSES\LOCAL SETTINGS\MRTCACHE\C:%5CPROGRAM FILES%5CWINDOWSAPPS%5CMICROSOFT.STOREPURCHASEAPP_11811.1001.18.0_X64__8WEKYB3D8BBWE%5CRESOURCES.PRI\1D5AD0BFA5DAB5A\D0332875\@{C:\P|                               |        1 |    156 | 1751403218 |
| b7ee48a6-0c13-441c-bed3-815ca63c1a6a | \\?\C:\Users\Пользователь\Downloads\eicar.com.txt                                                                                                                                                                      | EICAR-Test-File (not a virus) |        3 |     68 | 1751406485 |
```

**G DATA format 1:**
```
Start time: 2025-07-01 09:15:00
Virus found: Win32.Trojan.Agent
File: C:\Temp\suspicious.exe
```

**G DATA format 2:**
```
04	0000000002	2025-07-01 17:20:40	Virus check		3

64	0	0	Object: eicar_com.zip=>eicar.com
64	0	0		In archive: C:\Users\Пользователь\Downloads\eicarcom2.zip
64	0	0		Status: Virus detected
64	6	0		Virus: EICAR-Test-File (not a virus)
```

### OUTPUT FORMAT ###
- Your output MUST be a valid JSON array.
- Each object in the array represents a single detection and MUST contain exactly two keys: `signature` and `timestamp`.
- **signature**: Provide the clean name of the malware. You MUST strip all prefixes, such as `Virus:`, `Malware:`, `Threat:`, `Name=`, etc.
- **timestamp**: Format the event time strictly as `YYYY-MM-DD HH:MM:SS`.
- If no detection events are found, you MUST return an empty array: `[]`.
"""

# --- Universal Timestamp Parsing Pipeline ---

def parse_timestamp_gdata_header(line):
    """Parses the unique header of a G-Data v2 log."""
    try:
        header_parts = line.split('\t')
        if len(header_parts) > 2 and 'Virus check' in header_parts[3]:
            return datetime.datetime.strptime(header_parts[2], "%Y-%m-%d %H:%M:%S")
    except (ValueError, IndexError):
        return None
    return None

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

# --- Main File Filtering Logic ---

def get_log_lines(path: pathlib.Path):
    encodings = ['utf-8', 'utf-16', 'latin1', 'cp1251']
    for encoding in encodings:
        try:
            with path.open(encoding=encoding) as f:
                return f.readlines()
        except:
            continue
    return []

# --- Core Application Logic (unchanged) ---

def get_log_files(log_pattern: str):
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

def call_llm(model: str, prompt: str, start_date: str, end_date: str, timeout: int = LLM_TIMEOUT):
    CONTEXT = SYSTEM_PROMPT + f"""
    ### Filter Results by date range
    - from {start_date}
    - to {end_date}
    """
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": CONTEXT}, {"role": "user", "content": prompt}],
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

    log_files = get_log_files(args.log)
    
    for log_path in log_files:
        print(f"Filtering file: {log_path}", file=sys.stderr)
        lines = get_log_lines(log_path)
        log_chunks = create_chunks(lines)
        print(f"Split logs into {len(log_chunks)} chunks for processing.", file=sys.stderr)

        final_results = []
        for i, chunk in enumerate(log_chunks):
            print(f"Querying LLM for chunk {i+1}/{len(log_chunks)}...", file=sys.stderr)
            try:
                result = call_llm(args.model, chunk, args.start, args.end, LLM_TIMEOUT)
                if isinstance(result, list) and result:
                    final_results.extend(result)
            except requests.exceptions.RequestException as e:
                print(f"Error calling LLM for chunk {i+1}: {e}", file=sys.stderr)
                continue

        print(json.dumps(final_results, indent=2, ensure_ascii=False))
        print(f"Found: {len(final_results)} records")

if __name__ == "__main__":
    main()