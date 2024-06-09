
# Metadata Hunter (MHTR)

`Metadata Hunter (MHTR)` is a robust _binary analysis framework_ designed for _reverse engineering_ and _security analysis_ purposes. It facilitates the identification and extraction of metadata from binary files, aiding in tasks such as _vulnerability analysis_, _software debugging_, and _malware analysis_.

## Features

-   **Cross-Platform**: MHTR is designed to work seamlessly across various operating systems, ensuring versatility and broad usability.
    
-   **Command-Line Interface (CLI)**: MHTR offers a CLI interface for convenient interaction, allowing users to specify targets, configure options, and generate reports.
    
-   **Multithreading**: To enhance performance, MHTR employs multithreading to parallelize metadata lookup operations across multiple targets.
    

## Metadata Lookup

MHTR provides a flexible framework for performing various types of metadata lookups within binary files, including offsets, patterns, and other identifying information. This feature allows for detailed inspection and analysis of binary content, facilitating tasks such as vulnerability detection and malware analysis. The metadata lookup types include:

-   **INSN_IMM**: Parses instruction and lists all the immediate values (imm), offsets, and displacements. Users can select any of them by specifying the `immIndex`.
    
```json
{
  "name": "Bar",
  "type": "INSN_IMM",
  "pattern": "42 00 ? B9",
  "disp": -2,
  "immIndex": 0,
  "scanRange": "FooFuncRange"
}

```
**PATTERN_VALIDATE**: Validates a pattern to ensure it is present and unique, then forwards the pattern itself to the report.
```json
{
  "name": "BarPattern",
  "type": "PATTERN_VALIDATE",
  "pattern": "42 00 ? B9",
  "disp": -2,
  "scanRange": "FooFuncRange"
}

```
**PATTERN_SINGLE_RESULT**: Validates a pattern to ensure it is present and unique, then forwards the relative position of the pattern to the report.
```json
{
  "name": "BarPatternResult",
  "type": "PATTERN_SINGLE_RESULT",
  "pattern": "42 00 ? B9",
  "disp": -2,
  "scanRange": "FooFuncRange"
}
```
**FAR_ADDR**: Resolves position-independent code (PIC) references, such as those found in ARM architectures, by emulating PC-relative Load Effective Address Operations such as `ADRP` + `LDR`in ARM.
```json
{
  "name": "Baz",
  "type": "FAR_ADDR",
  "pattern": "49 78 44 ? 4A ? 4B",
  "disp": -1,
  "scanRange": "FooFuncRange"
}
```
## Integrated Plugin/Add-ons System

Extend MHTR's functionality with an integrated plugin system, enabling users to add custom features and tools. This system allows for the development and integration of additional modules, enhancing the tool's capabilities and adapting to specific analysis needs.

## Usage

To use MHTR, follow these steps:

1.  Prepare a JSON file containing metadata targets.
2.  Invoke the MHCLI with the appropriate options, specifying the path to the JSON targets file and any other desired parameters.
3.  Monitor the progress and review the generated reports for metadata extraction results.

Here's an example of how to use the MHCLI:

```bash
MHCLI -j4 --targets metadata_targets.json --report output_report.txt --report-hpp output_report.hpp --report-hpprt output_report_rt.hpp
```

## License

MHTR is licensed under the MIT License. Feel free to use, modify, and distribute it according to the terms of the license.
