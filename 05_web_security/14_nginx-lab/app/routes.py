from app import db
from app.models import Todo
from flask import Blueprint, flash, redirect, render_template, request, url_for

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    tasks = Todo.query.order_by(Todo.date_created).all()
    return render_template('index.html', tasks=tasks)

@main_bp.route('/add', methods=['POST'])
def add():
    task_content = request.form['content']
    if not task_content:
        flash('Task cannot be empty!', 'error')
    else:
        new_task = Todo(content=task_content)
        try:
            db.session.add(new_task)
            db.session.commit()
            flash('Task added successfully!', 'success')
        except Exception as e:
            flash(f'There was an issue adding your task: {e}', 'error')
            db.session.rollback()
    
    return redirect(url_for('main.index'))

@main_bp.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        flash('Task deleted successfully!', 'success')
    except Exception as e:
        flash(f'There was a problem deleting that task: {e}', 'error')
        db.session.rollback()
    
    return redirect(url_for('main.index'))

@main_bp.route('/complete/<int:id>')
def complete(id):
    task = Todo.query.get_or_404(id)
    
    try:
        task.completed = not task.completed
        db.session.commit()
        status = "completed" if task.completed else "uncompleted"
        flash(f'Task marked as {status}!', 'success')
    except Exception as e:
        flash(f'There was a problem updating that task: {e}', 'error')
        db.session.rollback()
    
    return redirect(url_for('main.index'))

@main_bp.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error=e), 404
