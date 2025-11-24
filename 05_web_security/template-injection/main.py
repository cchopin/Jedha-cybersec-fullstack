from flask import Flask, render_template, render_template_string, request

app = Flask(__name__)


# A safe route using proper context passing
@app.route('/safe')
def safe_greeting():
    name = request.args.get('name', 'Guest')
    # Pass data safely into the template context
    return render_template('safe_template.html', user_name=name)


# An unsafe route vulnerable to SSTI
@app.route('/unsafe')
def unsafe_greeting():
    name = request.args.get('name', 'Guest')
    # WARNING: Directly embedding user input into the template string! Do not do that at home!
    template_string = f"<h2>Hello, {name}!</h2><p>Welcome to the vulnerable page.</p>"
    return render_template_string(template_string)


# Create a simple template file 'templates/safe_template.html'
# <html><body><h2>Hello, {{ user_name }}!</h2><p>Welcome to the safe page.</p></body></html>
# Make sure to create a 'templates' directory and put safe_template.html inside it.

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    import os

    if not os.path.exists('templates'):
        os.makedirs('templates')
    with open('templates/safe_template.html', 'w') as f:
        f.write('<html><body><h2>Hello, {{ user_name }}!</h2><p>Welcome to the safe page.</p></body></html>')

    app.run(debug=True, port=5000)
