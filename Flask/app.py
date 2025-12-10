from flask import Flask, render_template, url_for, request, redirect, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
from datetime import time, datetime

app = Flask(__name__)

app.secret_key = secrets.token_hex(16)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:bakugan_76667@127.0.0.1:3306/flask'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройки для загрузки файлов
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

# Создаем папку для загрузок, если её нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Новое поле для админа
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    def __repr__(self):
        return f'<User {self.username}>'


class FoundItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    building = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    time_found = db.Column(db.Time, nullable=False)
    item_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    image_filename = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    moderated_at = db.Column(db.TIMESTAMP)  # Когда рассмотрено админом
    moderation_notes = db.Column(db.Text)  # Причина отклонения
    telegram_user = db.Column(db.String(50), nullable=False)

    user = db.relationship('User', backref=db.backref('found_items', lazy=True))


def init_db():
    with app.app_context():
        db.create_all()

        # Создаем администратора, если его нет
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            hashed_password = generate_password_hash('admin')
            admin_user = User(
                username='admin',
                email='admin@mail.ru',
                password=hashed_password,
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Администратор создан: admin / admin")

        print("Таблицы созданы")


def is_admin():
    """Проверка, является ли пользователь администратором"""
    if 'user_id' not in session:
        return False
    user = User.query.get(session['user_id'])
    return user and user.is_admin


@app.route('/')
@app.route('/main')
def main():
    # Получаем последние 6 одобренных находок для главной
    latest_items = FoundItem.query.filter_by(status='approved').order_by(FoundItem.created_at.desc()).limit(6).all()
    return render_template('main.html', latest_items=latest_items)


@app.route('/ads')
def ads():
    # Показываем только одобренные объявления
    items = FoundItem.query.filter_by(status='approved').order_by(FoundItem.created_at.desc()).all()
    return render_template('ads.html', items=items)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        try:
            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                flash('Пользователь с таким именем или email уже существует', 'error')
                return render_template('register.html')

            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['is_admin'] = new_user.is_admin

            flash('Регистрация прошла успешно! Вы автоматически вошли в систему.', 'success')
            return redirect(url_for('post'))

        except Exception as e:
            flash(f'Произошла ошибка при регистрации: {str(e)}', 'error')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin

            flash('Вы успешно вошли в систему!', 'success')

            # Если админ - перенаправляем в админку
            if user.is_admin:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('post'))
        else:
            flash('Неверный email или пароль', 'error')

    return render_template('login.html')


@app.route('/post', methods=['GET', 'POST'])
def post():
    if 'user_id' not in session:
        flash('Для добавления вещи необходимо авторизоваться', 'error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        building = request.form['building']
        location = request.form['location']
        time_found_str = request.form['time_found']
        item_type = request.form['item_type']
        description = request.form['description']
        telegram_user = request.form['telegram_user']

        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{secrets.token_hex(8)}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_filename = unique_filename
            elif file and file.filename != '':
                flash('Недопустимый формат файла. Разрешены: png, jpg, jpeg, gif', 'error')
                return render_template('post.html')

        try:
            hours, minutes = map(int, time_found_str.split(':'))
            time_found = time(hours, minutes)
        except ValueError:
            flash('Неверный формат времени', 'error')
            return render_template('post.html')

        new_item = FoundItem(
            user_id=session['user_id'],
            building=building,
            location=location,
            time_found=time_found,
            item_type=item_type,
            description=description,
            image_filename=image_filename,
            telegram_user=telegram_user,
            status='pending'  # По умолчанию на модерации
        )

        try:
            db.session.add(new_item)
            db.session.commit()
            flash('Вещь успешно добавлена и отправлена на модерацию!', 'success')
            return redirect(url_for('post'))
        except Exception as e:
            flash(f'Ошибка при добавлении вещи: {str(e)}', 'error')

    # Показываем все вещи пользователя с их статусами
    user_items = FoundItem.query.filter_by(user_id=session['user_id']).order_by(FoundItem.created_at.desc()).all()
    return render_template('post.html', items=user_items)


@app.route('/admin')
def admin_panel():
    if not is_admin():
        flash('Доступ запрещен. Только для администраторов.', 'error')
        return redirect(url_for('main'))

    # Получаем все заявки на модерацию
    pending_items = FoundItem.query.filter_by(status='pending').order_by(FoundItem.created_at.desc()).all()
    approved_count = FoundItem.query.filter_by(status='approved').count()
    rejected_count = FoundItem.query.filter_by(status='rejected').count()

    return render_template('admin.html',
                           pending_items=pending_items,
                           approved_count=approved_count,
                           rejected_count=rejected_count)

@app.context_processor
def inject_models():
    """Делает модели доступными во всех шаблонах"""
    return dict(FoundItem=FoundItem, User=User)


@app.route('/admin/approve/<int:item_id>')
def approve_item(item_id):
    if not is_admin():
        flash('Доступ запрещен.', 'error')
        return redirect(url_for('main'))

    item = FoundItem.query.get_or_404(item_id)
    item.status = 'approved'
    item.moderated_at = datetime.now()
    db.session.commit()

    flash('Объявление одобрено и опубликовано!', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/reject/<int:item_id>')
def reject_item(item_id):
    if not is_admin():
        flash('Доступ запрещен.', 'error')
        return redirect(url_for('main'))

    item = FoundItem.query.get_or_404(item_id)
    item.status = 'rejected'
    item.moderated_at = datetime.now()
    db.session.commit()

    flash('Объявление отклонено.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('main'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)