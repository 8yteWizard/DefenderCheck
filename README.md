> ⚠️ Based on the original DefenderCheck project by matterpreter: https://github.com/matterpreter/DefenderCheck

# DefenderCheck (Delphi 12 Edition)

Binary signature isolation tool using Microsoft Defender.

This is a native Delphi 12 console implementation of a binary bisection technique that can identify the exact byte region that triggers Microsoft Defender detection.

---

## Overview

DefenderCheck automates binary bisection against **MpCmdRun.exe** (Microsoft Defender CLI scanner).

If a file is detected as malicious, the tool:

1. Splits the file in half  
2. Scans the first portion  
3. Determines which region triggers detection  
4. Repeats recursively  
5. Identifies the precise byte boundary responsible  
6. Outputs a hex dump of the offending region  

This allows rapid detection analysis and signature research in controlled environments.

---

## Features

- Native Win32 / Win64 Delphi implementation
- Uses `CreateProcessW` (no external dependencies)
- Captures stdout via pipe redirection
- 30 second scan timeout
- Recursive binary narrowing
- Automatic `C:\Temp` creation
- Hex dump of last 256 suspicious bytes
- Optional debug mode

---

## Requirements

- Microsoft Defender installed (Fully removing via regkeys will cause false negatives)
- All settings can be disabled (Realtime protection, cloud submission etc can AND SHOULD all be disabled)
- `MpCmdRun.exe` available at:
```text
C:\Program Files\Windows Defender\MpCmdRun.exe
```

---

## Example Usage

```bash
DefenderCheck.exe payload.exe
```

```bash
DefenderCheck.exe payload.exe debug
```

---

## Example Output

```text
Target file size: 18432 bytes
Analyzing...

[!] Identified end of bad bytes at offset 0x4A3F
File matched signature: "Trojan:Win32/Example.A"

00004930   90 90 90 E8 34 12 00 00 48 65 6C 6C 6F 20 41 56   ....4...Hello AV
00004940   21 21 21 00 00 00 00 00                        !!!.....
```

---

## How It Works

The detection logic relies on Defender exit codes:

| Exit Code | Meaning          |
|------------|------------------|
| 0          | No threat found  |
| 2          | Threat found     |
| Other      | Error            |

The algorithm performs a controlled binary search:

```text
Detected → halve region
Clean → increase region by 50%
Repeat until boundary found
```

When only a 1-byte delta remains, the tool:

- Reports offset
- Extracts last 256 bytes
- Performs hex dump
- Prints signature name (if available)

---

## Project Structure

Core components:

- `RunProcessCapture` — CreateProcessW + stdout pipe capture
- `Scan` — Defender invocation + exit code mapping
- `HalfSplitter` — Recursive narrowing
- `Overshot` — Progressive expansion
- `HexDump` — Byte visualization

---

## Intended Use

- Detection research
- AV behavior analysis
- Binary testing and mutation analysis
- Lab environments

This tool is intended for defensive research and controlled environments only.

---

## Limitations

- Disk-based scanning (writes to `C:\Temp`)
- Not optimized for very large files (>100MB)
- Dependent on Defender CLI availability

---

> ⚠️ This readme (documentation) was generated with the assistance of AI.
> ⚠️ All code is human written.
