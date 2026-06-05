# CloudSift

Turn AWS ScoutSuite results into a clean HTML report. CloudSift pulls only the table data each finding needs, then auto-runs the commands to verify findings and capture professional screenshots for the report.

It cuts out the manual copy-pasting that AWS and cloud security assessments usually need, and saves a lot of time. An assessment plus report that used to take me 2 days now takes about 4 hours, at the same quality.

## Setup

```bash
# Clone
git clone https://github.com/SyedaliHOH/cloudsift.git
cd cloudsift

# Tool needs Python 3.8+ only (standard library, nothing to pip install)

# AWS CLI — configure aws credentials
aws configure

# termshot — for screenshots
go install github.com/homeport/termshot/cmd/termshot@latest

# Claude Code — for the false-positive check
npm install -g @anthropic-ai/claude-code
claude   # sign in once
```

## Usage

```bash
# Build the report + both scripts (defaults shown)
python3 cloudsift.py scoutsuite_results_aws-<id>.js

# Capture command screenshots  ->  ./screenshots/
./capture_screenshots.sh

# Flag false positives via Claude Code  ->  ./verification/
./verify_findings.sh
```

## What it does

* Reads a ScoutSuite `.js` results file plus `commands.json`
* Builds an **HTML report** of findings with their AWS CLI commands, copy buttons, and CSV export
* Generates **`capture_screenshots.sh`** — runs each command through `termshot`, one PNG per command, named by finding
* Generates **`verify_findings.sh`** — runs each command, pipes the output to Claude Code (`claude -p`), and flags each finding as true positive, false positive, or inconclusive
* Writes verdicts, reasoning, and raw evidence per finding

## Notes

* Commands run via `eval` from your own `commands.json` (trusted input)
* One `claude` call per finding, so cost scales with finding count
* Only assess accounts you're authorized to test
