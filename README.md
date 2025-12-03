# ArmorCode Audit Log Integration for Splunk

A Python-based CLI tool that retrieves audit logs from ArmorCode and writes them to log files for ingestion by Splunk.

> ⚠️ **Disclaimer**: This is **not an officially supported ArmorCode tool**. It is provided as a community template to help you get started with shipping ArmorCode audit logs to Splunk. Use at your own discretion and modify as needed for your environment.

---

## Acknowledgments

This project was initiated by [Brayden Greenfield](https://www.linkedin.com/in/brayden-greenfield/) during his internship. Thank you, Brayden, for your contributions in building the foundation of this tool!

---

## Overview

This tool connects to the ArmorCode Audit Log API and retrieves audit events, writing them to date-stamped log files that Splunk can monitor and ingest. It supports:

- **Cross-platform logging**: `/var/log/armorcode` on Unix-based systems, `./logs` on Windows
- **Flexible time ranges**: Query the last N hours of audit data
- **Entity filtering**: Retrieve specific audit entity types (User, Team, API Key, etc.)
- **Multiple API key methods**: CLI argument, environment variable, or `.env` file
- **Log rotation**: Built-in rotation for the forwarder log (default: 5 files at 5MB each)
- **Initial sync**: `--init` flag for first-run bulk data collection

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Up Log Directory (Unix/Linux)

```bash
sudo ./install.sh
```

This creates `/var/log/armorcode` and sets ownership to the `splunk` user.

### 3. Run the Tool

```bash
# Using API key directly
python main.py --api-key "YOUR_API_KEY" --init

# Using environment variable
export ARMORCODE_API_KEY="YOUR_API_KEY"
python main.py --init

# Using .env file (prompts for key on first run)
python main.py --use-env --init
```

---

## Documentation

For detailed usage instructions, configuration options, and Splunk setup guidance, see:

📖 **[ArmorCode CLI Audit Tool Documentation](ArmorCode_CLI_Audit_Tool.md)**

---

## Supported Entity Types

The tool can retrieve audit logs for the following ArmorCode entities:

| Entity | Entity | Entity |
|--------|--------|--------|
| User | Team | Api Key |
| Product | Sub Product | Project |
| Report | Runbook | Assessments |
| Organization | Global Settings | Core Configuration |
| Custom Dashboard | Finding Views | Finding Sla Configurations |
| Finding Sla Tiers | User Session Track | Ticket Unified Template |

---

## Common Commands

```bash
# Initial run - fetches all historical audit data
python main.py --api-key "KEY" --init

# Fetch last 12 hours, return up to 100 entries per entity
python main.py --api-key "KEY" --time 12 --size 100

# Fetch only User and Team audit logs
python main.py --api-key "KEY" --list-nargs "User" "Team"

# Reset init state to re-fetch all data
python main.py --api-key "KEY" --remove
```

---

## Requirements

- Python 3.6+
- Dependencies listed in `requirements.txt`
- Splunk (with a monitor input configured for the log directory)

---

## License

This project is provided as-is without warranty. See individual files for any applicable licensing.