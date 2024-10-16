# Multidecoder

<a href="https://pypi.org/project/multidecoder/#history"><img src="https://img.shields.io/pypi/v/multidecoder.svg" alt="Latest Stable Release"></a>

Multidecoder is a python library and command line tool for extracting indicators of compromise (IOCs) from a file.
Multidecoder preserves the context of where and how an IOC is found to allow automated detection of patterns of obfuscation.
Multidecoder is currently in beta, and uses semantic versioning to indicate compatability between releases.

Indicators of compromise extracted by Multidecoder:
- network IOCS: urls, domains, emails, ip addressses
- executable filenames
- embedded PowerShell
- embedded PE files
- a customizable set of keywords

Deobfuscations and decodings supported:
- base64 encoding
- hexadecimal encoding
- string concatenation
- powershell escape characters

## Installing

Multidecoder can be installed from pypi using pip:
```
pip install -U multidecoder
```

Alternatly, it can also be installed from the repository:
```
pip install -U https://github.com/CybercentreCanada/Multidecoder/archive/main.zip
```

To test the latest development version, install from the dev branch:
```
pip install -U https://github.com/CybercenterCanada/Multidecoder/archive/dev.zip
```

## Command Line

After being installed Multidecoder can be run on a file from the command-line
```
> multidecoder file
```
which will output a list of indicators found.
Indicators are printed one per line, with a string representation of the context of the indicator followed by the indicator.

The raw json result can be output with the `--json` flag
```
> multidecoder --json file
```

if no filename is given multidecoder takes its standard input as the file to be scanned.

## Python library

Multidecoder can be used as a python library through the Multidecoder class,
which can scan data to give a dictionary tree similar to the command-line json output.
```
from multidecoder.multidecoder import Multidecoder

md = Multidecoder()
context_tree = md.scan(data)
```
