# Project Structure

```
template-injection/
│
├── ssti_exploit.py          # Main exploitation script
├── setup.sh                 # Automated setup script
├── requirements.txt         # Python dependencies
│
├── README.md                # Main documentation with Mermaid diagram
├── USAGE.md                 # Detailed usage guide
├── EXAMPLES.md              # Real-world exploitation examples
├── PROJECT_STRUCTURE.md     # This file
│
├── .gitignore              # Git ignore rules
│
├── assets/                 # Screenshots and images
│   ├── screenshot-01-config.png
│   ├── screenshot-02-exploitation.png
│   └── screenshot-03-results.png
│
└── venv/                   # Virtual environment (created by setup.sh)
    └── ...
```

## File Descriptions

### Core Files

**ssti_exploit.py**
- Main Python script for SSTI exploitation
- Features: automatic pattern detection, payload generation, RCE testing
- Built with: requests, rich (for UI)

**setup.sh**
- Bash script for automated environment setup
- Creates virtual environment, installs dependencies
- Usage: `bash setup.sh`

**requirements.txt**
- Python package dependencies
- requests: HTTP client
- rich: Terminal UI framework

### Documentation

**README.md**
- Main project documentation
- Includes Mermaid workflow diagram
- Features overview, installation, technical details
- Screenshots embedded

**USAGE.md**
- Detailed usage instructions
- Configuration examples
- Output interpretation guide
- Troubleshooting section

**EXAMPLES.md**
- Real-world exploitation scenarios
- CTF challenge examples
- Advanced techniques (bypasses, persistence)
- Lab environment setup

**PROJECT_STRUCTURE.md**
- This file - project organization
- File descriptions
- Quick reference

### Assets

**screenshot-01-config.png**
- Shows configuration phase
- Interactive prompts for target setup

**screenshot-02-exploitation.png**
- Shows exploitation phase
- Payload generation and execution

**screenshot-03-results.png**
- Shows results table
- Success/failure status per payload

## Quick Reference

### First Time Setup
```bash
cd ~/projets-git/jedha/scripts/template-injection
bash setup.sh
```

### Daily Usage
```bash
source venv/bin/activate
python3 ssti_exploit.py
```

### Documentation Navigation
- **New users**: Start with README.md
- **Usage help**: Check USAGE.md
- **Examples**: See EXAMPLES.md
- **Structure**: This file

## Generated Files

During execution, the script creates:

**payloads_output.txt**
- All generated payloads with curl commands
- Created in current directory
- Saved after Phase 3

## Dependencies

### System Requirements
- Python 3.7+
- pip
- Virtual environment support

### Python Packages
- requests>=2.31.0
- rich>=13.7.0

## Contributing

To add new features:
1. Modify `ssti_exploit.py`
2. Update relevant documentation
3. Test with `setup.sh` fresh install
4. Add examples to `EXAMPLES.md` if applicable

## Notes

- All screenshots in `assets/` renamed from original captures
- Virtual environment excluded from version control (.gitignore)
- Setup script tested on macOS and Linux
- Windows users: Use Git Bash or WSL

## Support

For issues or questions:
1. Check USAGE.md troubleshooting section
2. Review EXAMPLES.md for similar scenarios
3. Check terminal output for error messages
4. Verify dependencies with `pip list`

Last updated: 2025-11-25
