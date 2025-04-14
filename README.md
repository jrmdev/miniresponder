# Miniresponder

A stripped down fork of the great Responder.

Things removed:

- Sqlite db
- Configuration file
- Python2 support
- Coloured output
- Verbose output
- OSX / Windows support
- Logs
- Scripts
- All servers except SMB & HTTP(S)

**Why?**

The idea is to make it lighter, down to minimalistic functionality, easy to integrate into scripts and/or combine with external tools, and make it installable via pip.
Most of the servers were removed but SMB & HTTP should cover 90% of cases.
This is meant to complement Responder for those who want a simple alternative, not to replace it.

## Installation

To install from Pypi:

```bash
pip install miniresponder
miniresponder -h```


Or clone the repo and install in a virtualenv

```bash
git clone https://github.com/jrmdev/miniresponder && cd miniresponder
python3 -m venv env
. env/bin/activate
pip install .
miniresponder -h```
