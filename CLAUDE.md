# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Исследовательский проект по использованию больших языковых моделей (LLM) для разбора журналов работы антивирусных средств. Проект включает разработку Python-скрипта для взаимодействия с локальной LLM-моделью (Qwen3-8B или GLM-4-9B) через Ollama для анализа логов антивирусных программ и извлечения информации о вредоносном ПО.

## Key Components

- `parse_logs_with_llm.py` - Основной скрипт для анализа логов антивирусов с помощью LLM
- `task.md` - Техническое задание проекта
- `eicar.com.txt` - Тестовый файл EICAR для проверки антивирусов
- Логи различных антивирусных программ:
  - `defender_log.txt` - Microsoft Windows Defender
  - `bitdefender_log.txt` - Bitdefender Total Security
  - `drweb_log.txt` - Dr.Web Desktop Security Suite
  - `gdata_log.txt` - G DATA Total Security
  - `MPDetection-20250626-191211.log` - Реальные логи Microsoft Defender

## Development Commands

This is a Python-based tool. Standard Python development practices apply:

```bash
# Использование Ollama (по умолчанию)
python parse_logs_with_llm.py --log defender_log.txt --start "2025-01-01 10:00:00" --end "2025-01-01 12:00:00" --model qwen:8b

# Использование LM Studio
python parse_logs_with_llm.py --log defender_log.txt --start "2025-01-01 10:00:00" --end "2025-01-01 12:00:00" --provider lmstudio --model "model-name"

# Проверка качества кода
python -m flake8 parse_logs_with_llm.py
python -m black parse_logs_with_llm.py
python -m pylint parse_logs_with_llm.py
```

## Architecture

The tool works by:
1. Filtering log lines within specified time range
2. Sending filtered lines to local LLM instance (Ollama or LM Studio)
3. Using system prompt to extract malware signatures and timestamps
4. Returning structured JSON output

## Supported LLM Providers

### Ollama (default)
- URL: http://localhost:11434/api/generate
- Supports models: Qwen3-8B, GLM-4-9B, etc.
- Default model: qwen:8b

### LM Studio
- URL: http://localhost:1234/v1/chat/completions
- Compatible with OpenAI API format
- Supports various local models

## Dependencies

- Python 3.x with requests library
- One of the following LLM providers:
  - Ollama running locally on port 11434
  - LM Studio running locally on port 1234

## Log Format Support

The tool expects logs with timestamp format: `YYYY-MM-DD HH:MM:SS`
Comments starting with `#` are automatically skipped.