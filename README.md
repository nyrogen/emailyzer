# 📧 emailyzer

## 📝 Summary

**emailyzer** is a tool for emails analysis.  

### Features

This program takes an `.eml` file as input and then analyzes is.

Notable features:

- Extracts information from headers
- Extracts all IPs, URLs and domains
- Extracts the body
- Extracts attachments

## 🛠️ Installation

### With Github

```bash
git clone https://github.com/nyrogen/emailyzer.git
cd emailyzer/
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🦆 Quickstart

To analyze an `.eml` file, run `python3 main.py <path_to_eml>`.

This will create a folder named as the `.eml` file.  
The full analysis, along the attachments and the body, will be inside this folder.

### Flags

You can set the verbosity with `-v` and `-m`.

## Credits

A special thank you goes out to [vasll](https://github.com/vasll) for helping me with the code and teaching me some programming tips and tricks.
