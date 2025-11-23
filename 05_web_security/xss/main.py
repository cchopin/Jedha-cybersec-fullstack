#!/usr/bin/python3
from re import search

from flask import Flask, render_template, request, redirect, url_for, make_response
import connector

app = Flask(__name__)

connector.init_db()
app.teardown_appcontext(connector.close_db)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        name = request.form.get('name', '')
        message = request.form.get('message', '')
        if name and message:
            connector.add_comment(name, message)
        return redirect(url_for('home'))

    all_comments = connector.read_all('comments')
    response = make_response(render_template('index.html', comments=all_comments))

    # Content Security Policy header
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"

    return response

@app.route('/delete/<int:comment_id>', methods=['POST'])
def delete(comment_id):
    connector.delete_comment(comment_id)
    return redirect(url_for('home'))


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    results = []
    if query:
        results = connector.search_comment(query)
    return render_template('search.html', query=query, results=results)


if __name__ == '__main__':
    app.run(debug=True)