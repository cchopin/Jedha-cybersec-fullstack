from flask import Flask, render_template, request, redirect, url_for
import connector

app = Flask(__name__)

app.teardown_appcontext(connector.close_db)


@app.route('/', methods=['GET', 'POST'])
def home():
    all_posts = connector.read_all('POSTS')
    return render_template('index.html', posts=all_posts)


@app.route('/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    connector.delete_post(post_id)
    return redirect(url_for('home'))


@app.route('/post/<int:post_id>', methods=['GET'])
def post_detail(post_id):
    post = connector.read_one('POSTS', post_id)
    if post is None:
        return "Post not found", 404
    return render_template('post.html', title=post['title'], content=post['content'])


@app.route('/new', methods=['GET', 'POST'])
def new():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        connector.add_post(title, content)

        return redirect(url_for('home'))
    else:
        # Action pour GET (afficher le formulaire)
        return render_template('new.html')


if __name__ == '__main__':
    app.run(debug=True)
