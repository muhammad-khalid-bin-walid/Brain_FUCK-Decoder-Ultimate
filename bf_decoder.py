import sys
import re
import argparse
import json
import base64
import logging
from collections import defaultdict
from pathlib import Path

class BrainfuckDecryptor:
    def __init__(self, memory_size=30000, log_level=logging.WARNING):
        self.memory_size = memory_size
        self.commands = {'>': 'move_right', '<': 'move_left', '+': 'inc', '-': 'dec',
                         '.': 'output', ',': 'input', '[': 'loop_start', ']': 'loop_end'}
        self.variants = {
            'ook': {'Ook.Ook.': '>', 'Ook.Ook!': '<', 'Ook!Ook.': '+', 'Ook!Ook!': '-',
                    'Ook.Ook?': '.', 'Ook?Ook.': ',', 'Ook!Ook?': '[', 'Ook?Ook!': ']'},
            'blub': {'Blub.': '>', 'Blub!': '<', 'BlubBlub.': '+', 'BlubBlub!': '-',
                     'Blub?.': '.', 'Blub?Blub.': ',', 'Blub!Blub?.': '[', 'Blub?Blub!': ']'},
            'pbrain': {'(': 'proc_start', ')': 'proc_end'}  # Minimal support for procedures
        }
        logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)
        self.reset()

    def reset(self):
        """Reset the Brainfuck environment."""
        self.memory = bytearray(self.memory_size)
        self.pointer = 0
        self.output = []
        self.input_buffer = []
        self.jump_table = {}
        self.code = []
        self.pc = 0
        self.trace = []

    def load_code(self, code, variant='brainfuck', custom_mapping=None):
        """Load and validate code, supporting variants and custom mappings."""
        if custom_mapping:
            self.variants['custom'] = custom_mapping
            variant = 'custom'
        if variant != 'brainfuck':
            code = self.translate_variant(code, variant)
        self.code = [c for c in code if c in self.commands]
        stack = []
        for i, cmd in enumerate(self.code):
            if cmd == '[':
                stack.append(i)
            elif cmd == ']':
                if not stack:
                    raise ValueError(f"Unmatched ']' at position {i}")
                start = stack.pop()
                self.jump_table[start] = i
                self.jump_table[i] = start
        if stack:
            raise ValueError(f"Unmatched '[' at position {stack[-1]}")
        self.logger.debug(f"Loaded {len(self.code)} instructions")

    def translate_variant(self, code, variant):
        """Translate variant to standard Brainfuck."""
        if variant not in self.variants:
            raise ValueError(f"Unsupported variant: {variant}")
        mapping = self.variants[variant]
        translated = ''
        i = 0
        while i < len(code):
            for pattern, cmd in mapping.items():
                if code[i:i+len(pattern)].lower() == pattern.lower():
                    translated += cmd
                    i += len(pattern)
                    break
            else:
                i += 1
        return translated

    def set_input(self, input_str):
        """Set input for , command."""
        self.input_buffer = list(input_str)
        self.logger.debug(f"Input buffer set: {input_str}")

    def run(self, trace=False):
        """Execute Brainfuck code and return output."""
        self.trace = [] if trace else None
        while 0 <= self.pc < len(self.code):
            cmd = self.code[self.pc]
            if trace:
                self.trace.append(f"PC:{self.pc} Cmd:{cmd} Ptr:{self.pointer} Mem[{self.pointer}]:{self.memory[self.pointer]}")
            if cmd == '>':
                self.pointer = (self.pointer + 1) % self.memory_size
            elif cmd == '<':
                self.pointer = (self.pointer - 1) % self.memory_size
            elif cmd == '+':
                self.memory[self.pointer] = (self.memory[self.pointer] + 1) % 256
            elif cmd == '-':
                self.memory[self.pointer] = (self.memory[self.pointer] - 1) % 256
            elif cmd == '.':
                self.output.append(chr(self.memory[self.pointer]))
            elif cmd == ',':
                self.memory[self.pointer] = ord(self.input_buffer.pop(0)) if self.input_buffer else 0
            elif cmd == '[' and self.memory[self.pointer] == 0:
                self.pc = self.jump_table[self.pc]
            elif cmd == ']' and self.memory[self.pointer] != 0:
                self.pc = self.jump_table[self.pc]
            self.pc += 1
        return ''.join(self.output)

    def memory_dump(self, max_cells=100, ascii_only=False, raw=False):
        """Return memory cells, optionally filtered or raw."""
        if raw:
            return list(self.memory[:min(self.memory_size, max_cells)])
        dump = []
        for i in range(min(self.memory_size, max_cells)):
            if self.memory[i] and (not ascii_only or 32 <= self.memory[i] <= 126):
                dump.append(f"Cell[{i}]: {self.memory[i]} ({chr(self.memory[i]) if 32 <= self.memory[i] <= 126 else ''})")
        return dump if dump else ["No non-zero cells"]

    def memory_strings(self, min_length=3):
        """Search memory for consecutive ASCII strings."""
        strings = []
        current = []
        start = None
        for i in range(self.memory_size):
            if 32 <= self.memory[i] <= 126:
                if not current:
                    start = i
                current.append(chr(self.memory[i]))
            else:
                if len(current) >= min_length:
                    strings.append(f"Cell[{start}-{i-1}]: {''.join(current)}")
                current = []
                start = None
        if len(current) >= min_length:
            strings.append(f"Cell[{start}-{i}]: {''.join(current)}")
        return strings if strings else ["No ASCII strings found"]

    def deobfuscate(self):
        """Simplify Brainfuck code."""
        code = ''.join(self.code)
        while True:
            new_code = code
            for op in ('><', '<>', '+-', '-+'):
                new_code = new_code.replace(op, '')
            new_code = re.sub(r'([><+-])\1+', lambda m: m.group(1) * min(len(m.group(0)), 256), new_code)
            if new_code == code:
                break
            code = new_code
        self.logger.debug(f"Deobfuscated to {len(new_code)} chars")
        return code

    def decode_output(self, output, method='caesar', key=0, vigenere_key='', substitution_map=None):
        """Decode output using specified method."""
        decoded = []
        if method == 'caesar':
            for c in output:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    decoded.append(chr((ord(c) - base - key) % 26 + base))
                else:
                    decoded.append(c)
        elif method == 'xor':
            decoded = [chr(ord(c) ^ key) for c in output]
        elif method == 'offset':
            decoded = [chr((ord(c) - key) % 256) for c in output]
        elif method == 'vigenere':
            vigenere_key = vigenere_key.lower()
            key_idx = 0
            for c in output:
                if c.isalpha():
                    shift = ord(vigenere_key[key_idx % len(vigenere_key)]) - ord('a')
                    base = ord('A') if c.isupper() else ord('a')
                    decoded.append(chr((ord(c) - base - shift) % 26 + base))
                    key_idx += 1
                else:
                    decoded.append(c)
        elif method == 'substitution':
            mapping = substitution_map or {chr(97+i): chr(97+(i+key)%26) for i in range(26)}
            decoded = [mapping.get(c.lower(), c) if c.isalpha() else c for c in output]
        elif method == 'base64':
            try:
                decoded = [base64.b64decode(output).decode()]
            except:
                decoded = ['[Invalid base64]']
        return ''.join(decoded)

    def guess_decoding(self, output):
        """Try common decoding methods and return likely results."""
        results = []
        common_words = ['the', 'and', 'hello', 'flag', 'key', 'secret']
        # Caesar
        for shift in range(1, 26):
            decoded = self.decode_output(output, 'caesar', shift)
            if any(word in decoded.lower() for word in common_words):
                results.append(f"Caesar(shift={shift}): {decoded}")
        # XOR
        for key in [42, 13, 7, 123, 255]:
            decoded = self.decode_output(output, 'xor', key)
            if all(32 <= ord(c) <= 126 for c in decoded[:10]):  # Check first 10 chars
                results.append(f"XOR(key={key}): {decoded}")
        # Offset
        for offset in [1, 5, 10, 32, 64]:
            decoded = self.decode_output(output, 'offset', offset)
            if all(32 <= ord(c) <= 126 for c in decoded[:10]):
                results.append(f"Offset(key={offset}): {decoded}")
        # Vigenère
        for vkey in ['key', 'code', 'secret', 'brainfuck']:
            decoded = self.decode_output(output, 'vigenere', vigenere_key=vkey)
            if any(word in decoded.lower() for word in common_words):
                results.append(f"Vigenère(key={vkey}): {decoded}")
        # Substitution
        for shift in [1, 3, 5]:
            decoded = self.decode_output(output, 'substitution', shift)
            if all(32 <= ord(c) <= 126 for c in decoded[:10]):
                results.append(f"Substitution(shift={shift}): {decoded}")
        # Base64
        try:
            decoded = base64.b64decode(output).decode()
            if all(32 <= ord(c) <= 126 for c in decoded):
                results.append(f"Base64: {decoded}")
        except:
            pass
        return results if results else ["No plausible decodings found"]

    def analyze(self):
        """Analyze code for encoding patterns."""
        stats = {
            'length': len(self.code),
            'loops': sum(1 for c in self.code if c in '[]'),
            'outputs': sum(1 for c in self.code if c == '.'),
            'inputs': sum(1 for c in self.code if c == ','),
            'patterns': []
        }
        code_str = ''.join(self.code)
        if '[-]' in code_str:
            stats['patterns'].append("Memory clearing loop")
        if re.search(r'\+\+\+\+\++\+\[', code_str):
            stats['patterns'].append("ASCII value generation")
        if stats['outputs'] > 10:
            stats['patterns'].append("Likely string output")
        if re.search(r'\[>\+{2,}<-\]', code_str):
            stats['patterns'].append("Possible multiplication for encoding")
        return stats

def main():
    parser = argparse.ArgumentParser(description="Ultimate Brainfuck Decryptor for Encoded Messages",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("code", help="Brainfuck code (or variant) or file path")
    parser.add_argument("--input", default="", help="Input string for , command")
    parser.add_argument("--variant", default="brainfuck", choices=["brainfuck", "ook", "blub", "custom"],
                        help="Code variant")
    parser.add_argument("--custom-mapping", help="JSON file with custom command mappings\n"
                        "e.g., {'cmd1': '>', 'cmd2': '<'}")
    parser.add_argument("--method", choices=["caesar", "xor", "offset", "vigenere", "substitution", "base64"],
                        help="Decoding method")
    parser.add_argument("--key", type=int, default=0, help="Numeric key for decoding")
    parser.add_argument("--vigenere-key", default="", help="Vigenère key (string)")
    parser.add_argument("--substitution-map", help="JSON file with substitution mapping\n"
                        "e.g., {'a': 'b', 'b': 'c'}")
    parser.add_argument("--memory-cells", type=int, default=100, help="Max memory cells to dump")
    parser.add_argument("--ascii-dump", action="store_true", help="Show only ASCII memory cells")
    parser.add_argument("--raw-memory", action="store_true", help="Dump raw memory as list")
    parser.add_argument("--min-string", type=int, default=3, help="Min length for memory strings")
    parser.add_argument("--output-file", help="Save results to file (JSON)")
    parser.add_argument("--trace", action="store_true", help="Trace execution steps")
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING"],
                        help="Logging level")
    args = parser.parse_args()

    try:
        # Load code
        code = args.code
        if Path(args.code).is_file():
            with open(args.code, 'r') as f:
                code = f.read()

        # Load custom mapping
        custom_mapping = None
        if args.custom_mapping:
            with open(args.custom_mapping, 'r') as f:
                custom_mapping = json.load(f)

        # Load substitution map
        substitution_map = None
        if args.substitution_map:
            with open(args.substitution_map, 'r') as f:
                substitution_map = json.load(f)

        # Initialize
        bf = BrainfuckDecryptor(log_level=getattr(logging, args.log_level))
        bf.load_code(code, args.variant, custom_mapping)

        # Analyze
        stats = bf.analyze()
        print(f"Code Analysis: {stats['length']} chars, {stats['loops']} loops, "
              f"{stats['outputs']} outputs, {stats['inputs']} inputs")
        if stats['patterns']:
            print(f"Patterns: {', '.join(stats['patterns'])}")

        # Run
        bf.set_input(args.input)
        raw_output = bf.run(args.trace)
        print(f"\nRaw Output: {raw_output or '[No output]'}")

        # Decode
        if args.method:
            decoded = bf.decode_output(raw_output, args.method, args.key, args.vigenere_key, substitution_map)
            print(f"Decoded ({args.method}, key={args.key or args.vigenere_key}): {decoded}")
        else:
            guesses = bf.guess_decoding(raw_output)
            print("\nPossible Decodings:")
            for guess in guesses:
                print(f"  {guess}")

        # Memory dump
        print("\nMemory Dump:")
        if args.raw_memory:
            print(bf.memory_dump(args.memory_cells, args.ascii_dump, raw=True))
        else:
            for line in bf.memory_dump(args.memory_cells, args.ascii_dump):
                print(f"  {line}")

        # Memory strings
        print("\nMemory Strings:")
        for line in bf.memory_strings(args.min_string):
            print(f"  {line}")

        # Trace
        if args.trace and bf.trace:
            print("\nExecution Trace (first 10 steps):")
            for line in bf.trace[:10]:
                print(f"  {line}")
            if len(bf.trace) > 10:
                print(f"  ... {len(bf.trace) - 10} more steps")

        # Deobfuscated code
        clean_code = bf.deobfuscate()
        print(f"\nDeobfuscated Code: {clean_code}")

        # Save results
        if args.output_file:
            results = {
                'raw_output': raw_output,
                'decodings': guesses if not args.method else [f"{args.method}: {decoded}"],
                'memory_dump': bf.memory_dump(args.memory_cells, args.ascii_dump, args.raw_memory),
                'memory_strings': bf.memory_strings(args.min_string),
                'trace': bf.trace if args.trace else [],
                'deobfuscated': clean_code,
                'analysis': stats
            }
            with open(args.output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to {args.output_file}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
