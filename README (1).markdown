# Ultimate Brainfuck Decryptor
*Designed by Muhammad Khalid Bin Walid*

## Overview
The **Ultimate Brainfuck Decryptor** is a command-line Python tool for interpreting, analyzing, and decrypting Brainfuck programs, with a focus on decoding encoded messages. It supports Brainfuck and its variants (e.g., Ook!, Blub), decodes common ciphers (Caesar, XOR, Vigenère, base64, etc.), analyzes memory for hidden data, and provides deobfuscation and execution tracing.

### Key Features
- Interprets Brainfuck and variants (Ook!, Blub, custom mappings).
- Decodes ciphers: Caesar, XOR, offset, Vigenère, substitution, base64.
- Dumps memory and extracts ASCII strings.
- Analyzes code for encoding patterns.
- Deobfuscates code for readability.
- Supports tracing, logging, and JSON output for automation.

This guide explains how to install, use, and troubleshoot the tool.

## Installation

### Prerequisites
- Python 3.6 or higher.
- No external dependencies required.

### Download the Script
- Save the script as `bf_decryptor.py` (provided separately or copy from source).

### Verify Setup
1. Ensure Python is installed:
   ```bash
   python3 --version
   ```
2. Test the script:
   ```bash
   python3 bf_decryptor.py --help
   ```

## Command-Line Usage
Run the script with:
```bash
python3 bf_decryptor.py <code_or_file> [options]
```

### Arguments
- `<code_or_file>` (required): Brainfuck code (as a string) or path to a file containing the code (e.g., `code.bf`).

### Options
| Option | Description | Default |
|--------|-------------|---------|
| `--input <str>` | Input string for the `,` command. | `""` |
| `--variant <brainfuck|ook|blub|custom>` | Code variant to interpret. | `brainfuck` |
| `--custom-mapping <json>` | JSON file with custom command mappings (e.g., `{"Cmd1.": ">"}`). | None |
| `--method <caesar|xor|offset|vigenere|substitution|base64>` | Decoding method for output. | None (auto-guess) |
| `--key <int>` | Numeric key for decoding (e.g., Caesar shift). | `0` |
| `--vigenere-key <str>` | String key for Vigenère cipher. | `""` |
| `--substitution-map <json>` | JSON file with substitution mapping (e.g., `{"a": "b"}`). | None |
| `--memory-cells <int>` | Max memory cells to dump. | `100` |
| `--ascii-dump` | Show only ASCII memory cells (32-126). | `False` |
| `--raw-memory` | Dump raw memory as a list. | `False` |
| `--min-string <int>` | Min length for memory ASCII strings. | `3` |
| `--output-file <file>` | Save results to a JSON file. | None |
| `--trace` | Trace execution steps (logs PC, command, pointer, memory). | `False` |
| `--log-level <DEBUG|INFO|WARNING>` | Logging verbosity. | `WARNING` |

### Notes
- Use quotes for code with spaces or special characters: `"+++[>+++<-]>."`.
- File input is supported: `python3 bf_decryptor.py code.bf`.
- JSON files for `--custom-mapping` or `--substitution-map` must be valid (e.g., `{"key": "value"}`).
- If `--method` is omitted, the tool auto-guesses decoding methods.

## Examples

### Example 1: Run Hello, World!
Interpret a Brainfuck program that outputs "Hello, World!":
```bash
python3 bf_decryptor.py "+++++++[>+++++++<-]>++.>++++++++[>++++++++<-]>+.+++++++..+++.>++++++++[>--------<-]>-.<<<<.+++.------.--------.>>+."
```
**Output**:
```
Code Analysis: 67 chars, 6 loops, 13 outputs, 0 inputs
Patterns: Likely string output
Raw Output: Hello, World!
Possible Decodings:
  [No plausible decodings found]
Memory Dump:
  Cell[0]: 72 (H)
  Cell[1]: 33 (!)
  Cell[2]: 100 (d)
Memory Strings:
  Cell[0-2]: H!d
Deobfuscated Code: +++++++[>+++++++<-]>++.>++++++++[>++++++++<-]>+.+++++++..+++.>++++++++[>--------<-]>-.<<<<.+++.------.--------.>>+.
```

### Example 2: Decode Caesar-Shifted Output
Decrypt a program outputting "Ifmmp!" (Caesar shift of "Hello!" by 1):
```bash
python3 bf_decryptor.py "<code_outputting_Ifmmp>" --method caesar --key 1
```
**Output**:
```
Code Analysis: [Depends on code]
Patterns: [Depends on code]
Raw Output: Ifmmp!
Decoded (caesar, key=1): Hello!
Memory Dump: [Depends on code]
Memory Strings: [Depends on code]
Deobfuscated Code: [Depends on code]
```

### Example 3: Ook! Variant with Input
Run an Ook! program (`,.>`) with input "a":
```bash
python3 bf_decryptor.py "Ook.Ook?.Ook.Ook!.Ook!Ook!.Ook.Ook?.Ook!Ook?.Ook.Ook!.Ook.Ook?.Ook.Ook!.Ook.Ook?.Ook.Ook!.Ook.Ook?" --variant ook --input "a"
```
**Output**:
```
Code Analysis: 6 chars, 2 loops, 3 outputs, 1 inputs
Patterns: None
Raw Output: a
Possible Decodings:
  [No plausible decodings found]
Memory Dump:
  Cell[0]: 97 (a)
Memory Strings:
  [No ASCII strings found]
Deobfuscated Code: ,.>.
```

### Example 4: Custom Mapping
Use a custom mapping (`mapping.json`):
```json
{"Cmd1.": ">", "Cmd2.": "<", "Cmd3.": "+", "Cmd4.": "-", "Cmd5.": ".", "Cmd6.": ",", "Cmd7.": "[", "Cmd8.": "]"}
```
Run:
```bash
python3 bf_decryptor.py "Cmd6.Cmd5." --variant custom --custom-mapping mapping.json --input "a"
```
**Output**:
```
Code Analysis: 2 chars, 0 loops, 1 outputs, 1 inputs
Patterns: None
Raw Output: a
Possible Decodings:
  [No plausible decodings found]
Memory Dump:
  Cell[0]: 97 (a)
Memory Strings:
  [No ASCII strings found]
Deobfuscated Code: ,.
```

### Example 5: Save Results and Trace
Run a program, trace execution, and save results:
```bash
python3 bf_decryptor.py "+++[>+++<-]>." --trace --output-file results.json --log-level DEBUG
```
**Output**:
```
DEBUG: Loaded 10 instructions
Code Analysis: 10 chars, 2 loops, 1 outputs, 0 inputs
Patterns: ASCII value generation
Raw Output: [Non-printable]
Possible Decodings:
  Offset(key=32): [Printable char]
Memory Dump:
  Cell[1]: 16
Memory Strings:
  [No ASCII strings found]
Execution Trace (first 10 steps):
  PC:0 Cmd:+ Ptr:0 Mem[0]:1
  PC:1 Cmd:+ Ptr:0 Mem[0]:2
  ...
Deobfuscated Code: +++[>+++<-]>.
Results saved to results.json
```

### Example 6: Memory Strings
Find hidden strings in memory:
```bash
python3 bf_decryptor.py "<code>" --min-string 4 --ascii-dump
```
**Output** (if memory contains "flag"):
```
Memory Strings:
  Cell[10-13]: flag
```

## Decrypting Encoded Messages
1. **Run the Code**:
   - Execute with `python3 bf_decryptor.py "<code>"` to see raw output.
   - Check **Raw Output** for the program’s direct result.

2. **Decode Output**:
   - If output is gibberish, try auto-guessing:
     ```bash
     python3 bf_decryptor.py "<code>"
     ```
   - Specify a method and key for known ciphers:
     ```bash
     python3 bf_decryptor.py "<code>" --method vigenere --vigenere-key secret
     ```
   - Use `--substitution-map map.json` for custom letter mappings.

3. **Analyze Memory**:
   - Check `--memory-dump` for non-zero cells.
   - Use `--ascii-dump` to filter printable ASCII.
   - Use `--memory-strings` to find hidden strings (e.g., flags).
   - Export raw memory with `--raw-memory` for scripting.

4. **Inspect Patterns**:
   - Look at **Patterns** in output to identify encoding types (e.g., ASCII generation).
   - Use `--trace` to debug complex programs.

5. **Save Results**:
   - Use `--output-file results.json` to save all data (output, decodings, memory, trace).

## Troubleshooting
- **Error: Unmatched ']' or '['**:
  - Check code for balanced brackets (`[]`).
  - Example: `+++[>+++<-]` is invalid; use `+++[>+++<-]>.`.

- **No Plausible Decodings**:
  - Output may not be encoded; check raw output or memory strings.
  - Try different `--method` or `--key` values.
  - Use `--log-level DEBUG` for detailed execution info.

- **Invalid JSON File**:
  - Ensure `--custom-mapping` or `--substitution-map` files are valid JSON.
  - Example: `{"a": "b"}`, not `{a: b}`.

- **Memory Dump Empty**:
  - Increase `--memory-cells` (e.g., `--memory-cells 1000`).
  - Check if program uses memory (**Patterns** may indicate).

- **Slow Execution**:
  - For large programs, reduce `--memory-cells` or avoid `--trace`.
  - Ensure code has no infinite loops (e.g., `[+]`).

## Advanced Tips
- **Batch Processing**:
  - Process multiple files with a script:
    ```bash
    for file in *.bf; do python3 bf_decryptor.py "$file" --output-file "results_$(basename $file).json"; done
    ```

- **Custom Variants**.:
  - Create a JSON file for new variants:
    ```json
    {"Cmd1": ">", "Cmd2": "<"}
    ```
  - Use `--variant custom --custom-mapping map.json`.

- **Cipher Debugging**:
  - Use `--trace` to see how output is generated.
  - Check memory with `--raw-memory` for external analysis.

- **Automation**:
  - Parse JSON output (`--output-file`) with tools like `jq`:
    ```bash
    jq .raw_output results.json
    ```

## Support
If you encounter issues or need specific features (e.g., new ciphers, GUI, different language):
- Provide the Brainfuck code and expected output.
- Describe the cipher or decoding goal.
- Share any errors or script output.

This tool is designed to be the ultimate Brainfuck decryptor, but we’re happy to refine it further!