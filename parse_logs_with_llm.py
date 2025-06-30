
"""
parse_logs_with_llm.py
------------------------------------
Parse Windows AV log files for malware detections in a given time range
using local LLM models via Ollama or LM Studio.

Usage:
    # Single file with Ollama (default)
    python parse_logs_with_llm.py --log defender_log.txt --start "2025-01-01 10:00:00" --end "2025-01-01 12:00:00"
    
    # Multiple files using glob pattern
    python parse_logs_with_llm.py --log "*.log" --start "2025-01-01 10:00:00" --end "2025-01-01 12:00:00"
    
    # Using LM Studio with pattern
    python parse_logs_with_llm.py --log "*_realistic_log.txt" --start "2025-06-30 14:00:00" --end "2025-06-30 17:00:00" --provider lmstudio --model "model-name"
"""

import argparse, datetime, json, re, sys, pathlib, requests, glob

OLLAMA_URL = "http://localhost:11434/api/generate"  # default Ollama port
LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"  # default LM Studio port

SYSTEM_PROMPT = """
You are a cybersecurity assistant. You receive raw antivirus log lines.
Extract every detected malware signature and the timestamp (YYYY-MM-DD HH:MM:SS)
when it was found.
Возвращай все возможные подозрительные записи включая помещенные в карантин, адаленные или просто детектед.
Ignore events like as updated, start, stop, restart, shutdown, pause!
Return only a JSON array where each element has keys:
- "signature": string (only clear signature without "Virus:")
- "timestamp": string (same format)
If none were found, return an empty JSON array.
"""

def call_llm_ollama(model: str, prompt: str, timeout: int = 60):
    payload = {
        "model": model,
        "prompt": prompt,
        "system": SYSTEM_PROMPT,
        "stream": False,
    }
    r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    r.raise_for_status()
    response_text = r.json().get("response", "")
    return parse_llm_response(response_text)

def call_llm_lmstudio(model: str, prompt: str, timeout: int = 60):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "stream": False,
        "temperature": 0.1
    }
    r = requests.post(LMSTUDIO_URL, json=payload, timeout=timeout)
    r.raise_for_status()
    response_text = r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
    return parse_llm_response(response_text)

def parse_llm_response(response_text: str):
    # Ensure the LLM returned valid JSON
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        # For LM Studio responses, extract JSON from content that may have thinking tags
        # First, try to find JSON array pattern
        import re
        
        # Remove thinking tags if present
        content = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL)
        
        # Try to parse cleaned content
        try:
            return json.loads(content.strip())
        except json.JSONDecodeError:
            # Extract JSON array more carefully
            json_match = re.search(r'\[\s*\{.*?\}\s*\]', content, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            # Last resort: try to find any JSON-like structure
            lines = content.split('\n')
            json_lines = []
            in_json = False
            for line in lines:
                if line.strip().startswith('['):
                    in_json = True
                if in_json:
                    json_lines.append(line)
                if line.strip().endswith(']') and in_json:
                    break
            
            if json_lines:
                json_text = '\n'.join(json_lines)
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    pass
        
        # If all else fails, return empty array
        print(f"Warning: Could not parse LLM response as JSON. Returning empty array.")
        print(f"Response was: {response_text[:500]}...")
        return []

def call_llm(model: str, prompt: str, provider: str = "ollama", timeout: int = 60):
    if provider.lower() == "lmstudio":
        return call_llm_lmstudio(model, prompt, timeout)
    else:
        return call_llm_ollama(model, prompt, timeout)

def filter_log_lines(path: pathlib.Path, start_dt, end_dt):
    fmt = "%Y-%m-%d %H:%M:%S"
    
    # Try different encodings
    encodings = ['utf-8', 'utf-16', 'utf-16-le', 'utf-16-be', 'cp1251', 'latin1']
    
    for encoding in encodings:
        try:
            with path.open(encoding=encoding) as f:
                for line in f:
                    if line.startswith("#"):  # skip comments
                        continue
                    try:
                        # Handle both formats: "YYYY-MM-DD HH:MM:SS" and "YYYY-MM-DDTHH:MM:SS.mmm"
                        line_parts = line.split()
                        if len(line_parts) >= 2:
                            if 'T' in line_parts[0]:  # ISO format with T
                                datetime_str = line_parts[0].replace('T', ' ').split('.')[0]
                            else:  # Standard format
                                datetime_str = " ".join(line_parts[:2])
                            
                            ts = datetime.datetime.strptime(datetime_str, fmt)
                            if start_dt <= ts <= end_dt:
                                yield line.strip()
                    except ValueError:
                        continue
            break  # If successful, stop trying other encodings
        except UnicodeDecodeError:
            continue  # Try next encoding
    else:
        raise ValueError(f"Could not decode file {path} with any of the supported encodings: {encodings}")

def get_log_files(log_pattern: str):
    """Get list of log files based on pattern (supports glob wildcards)"""
    if '*' in log_pattern or '?' in log_pattern:
        # Use glob pattern
        files = glob.glob(log_pattern)
        if not files:
            print(f"No files found matching pattern: {log_pattern}", file=sys.stderr)
            sys.exit(1)
        return [pathlib.Path(f) for f in sorted(files)]
    else:
        # Single file
        log_path = pathlib.Path(log_pattern)
        if not log_path.exists():
            print(f"Log file not found: {log_path}", file=sys.stderr)
            sys.exit(1)
        return [log_path]

def main():
    parser = argparse.ArgumentParser(description="Parse AV log with LLM")
    parser.add_argument("--log", required=True, help="Path to log file or glob pattern (e.g., '*.log')")
    parser.add_argument("--start", required=True, help="Start datetime YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--end", required=True, help="End datetime YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--model", default="qwen:8b", help="Model name")
    parser.add_argument("--provider", default="ollama", choices=["ollama", "lmstudio"], 
                        help="LLM provider: ollama or lmstudio")
    parser.add_argument("--batch", action="store_true", 
                        help="Process all files in single request (default: process each file separately)")
    args = parser.parse_args()

    start_dt = datetime.datetime.strptime(args.start, "%Y-%m-%d %H:%M:%S")
    end_dt = datetime.datetime.strptime(args.end, "%Y-%m-%d %H:%M:%S")

    log_files = get_log_files(args.log)
    
    if args.batch:
        # Original behavior: combine all files into one request
        all_relevant_lines = []
        for log_path in log_files:
            print(f"Processing file: {log_path}", file=sys.stderr)
            relevant_lines = list(filter_log_lines(log_path, start_dt, end_dt))
            if relevant_lines:
                if len(log_files) > 1:
                    all_relevant_lines.append(f"=== File: {log_path} ===")
                all_relevant_lines.extend(relevant_lines)
        
        if not all_relevant_lines:
            print("[]")
            return

        user_prompt = "\n".join(all_relevant_lines)
        result = call_llm(args.model, user_prompt, args.provider)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # New behavior: process each file separately
        all_results = []
        for log_path in log_files:
            print(f"Processing file: {log_path}", file=sys.stderr)
            relevant_lines = list(filter_log_lines(log_path, start_dt, end_dt))
            if relevant_lines:
                user_prompt = "\n".join(relevant_lines)
                print(f"Querying LLM for {log_path}...", file=sys.stderr)
                result = call_llm(args.model, user_prompt, args.provider)
                
                # Add file source to each detection
                if isinstance(result, list):
                    for detection in result:
                        if isinstance(detection, dict):
                            detection["source_file"] = str(log_path)
                    
                    # Output results immediately for this file
                    if result:
                        print(f"Results from {log_path}:", file=sys.stderr)
                        print(json.dumps(result, indent=2, ensure_ascii=False))
                        print("", file=sys.stderr)  # Empty line separator
                    else:
                        print(f"No detections found in {log_path}", file=sys.stderr)
                    
                    all_results.extend(result)
                else:
                    print(f"Warning: Unexpected result format from {log_path}", file=sys.stderr)
            else:
                print(f"No relevant log lines found in {log_path} for specified time range", file=sys.stderr)
        
        # Final summary
        print("=== FINAL SUMMARY ===", file=sys.stderr)
        print(json.dumps(all_results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
