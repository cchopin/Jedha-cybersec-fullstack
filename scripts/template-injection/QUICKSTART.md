# Quick Start Guide

Get up and running in 60 seconds.

## Installation (One Command)

```bash
bash setup.sh
```

That's it! The script will:
- Create a virtual environment
- Install all dependencies
- Verify Python version

## Running the Tool

```bash
# Activate environment
source venv/bin/activate

# Run the tool
python3 ssti_exploit.py
```

## Minimal Example

When prompted, enter:

```
Target URL: http://target.com/endpoint
HTTP Method: POST
Vulnerable Parameter: name
[Press Enter for remaining options]
```

The tool will:
1. Auto-detect response patterns
2. Find exploitable Python classes
3. Generate payloads
4. Test for RCE
5. Display results

## What You Get

### Terminal Output
- Beautiful colored interface
- Real-time progress indicators
- Results table showing what works

### File Output
- `payloads_output.txt` - All payloads with curl commands

## Need More Help?

- **Installation issues?** → Check README.md
- **How to use?** → Check USAGE.md
- **Need examples?** → Check EXAMPLES.md
- **Understanding workflow?** → Check Mermaid diagram in README.md

## Testing Locally

Want to practice? Create a vulnerable app:

```bash
# Create test app
cat > test_app.py << 'EOF'
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    name = request.form.get('name', request.args.get('name', 'World'))
    return render_template_string(f'<h1>Hello {name}!</h1>')

app.run(debug=True, host='0.0.0.0', port=5000)
EOF

# Run it (in another terminal)
python3 test_app.py

# Test with our tool
python3 ssti_exploit.py
# URL: http://localhost:5000
# Method: POST
# Parameter: name
```

## Common First-Time Issues

### Virtual environment not activating
```bash
# Solution
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Module not found
```bash
# Make sure venv is activated
which python3  # Should show path inside venv/
pip install -r requirements.txt
```

### Permission denied on setup.sh
```bash
chmod +x setup.sh
bash setup.sh
```

## Next Steps

After your first successful run:
1. Review `payloads_output.txt` for all generated payloads
2. Try different targets in EXAMPLES.md
3. Read USAGE.md for advanced features
4. Customize payloads for specific commands

Happy hacking! (ethically, of course)
