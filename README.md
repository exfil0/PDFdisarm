# Advanced PDF Analysis & Disarm Tool

## Overview

This tool scans, analyzes, and optionally “disarms” PDF files. It provides:

- **PDF Structure Analysis**: Detects keywords, calculates entropy, and identifies malicious indicators such as embedded JavaScript and launch actions.
- **Concurrency**: Uses Python’s ThreadPoolExecutor to process multiple files in parallel.
- **Disarm Mode**: Generates a `<filename>.disarmed.pdf` that strips or obfuscates dangerous elements like `/JS`, `/JavaScript`, `/Launch`, etc.
- **Directory Recursion**: Gathers files from a given directory or directories, optionally recursing.
- **Plugin Architecture**: Supports loading custom plugins for scoring or additional checks.
- **Selection Expressions**: Allows filtering results (e.g., show only PDFs with certain suspicious counts).
- **Multiple Output Formats**: 
  - Human-readable console output
  - CSV format (one line per file)
  - JSON export function (PDFiD2JSON) available for custom usage

Use it at your own risk.

---

## Installation

1. **Requirements**:
   - Python 3.7+ (recommended)
   - Optional library: `pyzipper` for AES-encrypted ZIP support
   - Standard libraries: `argparse`, `concurrent.futures`, `urllib.request`, etc. (included in most Python installs)

2. **Clone or Download** this script:
   ```bash
   git clone https://github.com/exfil0/PDFdisarm.git
   ```
   *(If this is just an example—use your preferred distribution method.)*

3. **Make It Executable (Linux/Mac)**:
   ```bash
   chmod +x pdfscan.py
   ```

4. **(Optional) Install pyzipper**:
   ```bash
   pip install pyzipper
   ```

---

## Usage

### Basic Command

```bash
./pdfscan.py <file1.pdf> <file2.pdf> ...
```
- Analyzes each file and prints detailed results to the console.

### Wildcards and Directory Recursion

```bash
./pdfscan.py /path/to/pdfs -r
```
- Recursively scans all files under `/path/to/pdfs`.

### Disarm Mode

```bash
./pdfscan.py malicious.pdf --disarm
```
- Creates `malicious.disarmed.pdf` with potentially malicious elements neutralized.

### CSV Output

```bash
./pdfscan.py /path/to/pdfs -r --csv -o results.csv
```
- Outputs a single CSV with all scan results, one row per file.
- If `-o` is not specified, CSV goes to `stdout`.

### Selecting Files by Condition

```bash
./pdfscan.py *.pdf --select="pdf.js.count > 0"
```
- Only shows results for files where the JavaScript (`/JS`) count is greater than zero.

### Plugin Usage

```bash
./pdfscan.py suspicious.pdf --plugins=MyPlugin.py --csv
```
- Loads a custom plugin (`MyPlugin.py`) which can provide additional scoring or checks.

### Threading

```bash
./pdfscan.py /path/to/pdfs --threads 8
```
- Uses 8 worker threads to speed up scanning across many files.

---

## Command-Line Options

- **`files`** (positional):
  - One or more file paths, directory paths, or wildcard patterns.
- **`-r, --recursedir`**: Recurse into subdirectories when a directory is provided.
- **`-o, --output`**: Specify output file (CSV only).
- **`--all`**: Show all recognized PDF keywords (even non-standard ones).
- **`--extra`**: Collect extra data such as dates and entropy.
- **`--force`**: Force scanning even if the PDF header is missing.
- **`--disarm`**: Write a disarmed copy of each PDF as `<filename>.disarmed.pdf`.
- **`--select`**: Python expression to filter results, e.g. `pdf.js.count>0`.
- **`--nozero`**: Suppress printing zero counts in console output.
- **`--threads`**: Number of parallel worker threads (default=4).
- **`--scan`**: Legacy option, similar to scanning a directory.
- **`--plugins`**: Comma-separated list of plugin `.py` files to load.
- **`--pluginoptions`**: Additional string to pass to plugins.
- **`--csv`**: Output results to CSV (to file if `-o` is specified, else stdout).
- **`--minimumscore`**: Only show files or plugin results that meet or exceed this numeric score.
- **`--verbose`**: Print detailed tracebacks on errors.

---

## Example Workflows

1. **Single File Quick Scan**
   ```bash
   ./pdfscan.py mydocument.pdf
   ```
   Displays a detailed report (keywords, potential malicious actions) in the console.

2. **Multiple PDFs, CSV Output**
   ```bash
   ./pdfscan.py /opt/pdfs/*.pdf --csv -o results.csv
   ```
   Gathers results in `results.csv`, easy to import into Excel.

3. **Full Directory Disarm**
   ```bash
   ./pdfscan.py /opt/malware-pdfs -r --disarm
   ```
   Recursively generates `*.disarmed.pdf` copies.

---

## Plugin Notes

- **Plugin Classes** must subclass `cPluginParent`.
- The script automatically discovers plugin classes from the loaded files.
- Each plugin typically implements a `Score()` method returning a numeric score.

---

## Disclaimer

Authored and maintained by **Exfil0**.  
**No warranties** are provided. Use at your own risk.

Feel free to adapt and redistribute **with attribution** to Exfil0.

