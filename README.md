# Metadata Hunter (MHTR)
`Metadata Hunter(MHTR)` is a robust *binary analysis framework* designed for *reverse engineering* and *security analysis* purposes. It facilitates the identification and extraction of metadata from binary files, aiding in tasks such as *vulnerability analysis*, *software debugging*, and *malware analysis*.

## Features
-   **Metadata Lookup**: MHTR provides a flexible framework for performing various types of metadata lookups within binary files, including offsets, patterns, and other identifying information.
    
-   **Command-Line Interface (CLI)**: MHTR offers a CLI interface for convenient interaction, allowing users to specify targets, configure options, and generate reports.
    
-   **Multithreading**: To enhance performance, MHTR employs multithreading to parallelize metadata lookup operations across multiple targets.

## Usage
To use MHTR, follow these steps:

1.  Prepare a JSON file containing metadata targets.
    
2.  Invoke the MHCLI with the appropriate options, specifying the path to the JSON targets file and any other desired parameters.
    
3.  Monitor the progress and review the generated reports for metadata extraction results.
    

Here's an example of how to use the MHCLI:
```bash
MHCLI -j4 --targets metadata_targets.json --report output_report.txt --report-hpp output_report.hpp
```
## License

MHTR is licensed under the MIT License. Feel free to use, modify, and distribute it according to the terms of the license.

