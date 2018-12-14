from flask import Flask,render_template,flash,redirect,url_for,request,session,logging
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps

#Articles = Articles()

app = Flask(__name__)


#Config MySQL db
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#Initialize MySQL db
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/articles')
def articles():
     # Create cursor
    cur = mysql.connection.cursor()
    # Get Articles
    result = cur.execute("SELECT * FROM articles")
    
    articles = cur.fetchall()

    if result > 0:
        return render_template('articles.html',articles=articles)
    else:
        msg = "No Articles found"
        return render_template('articles.html',msg=msg)
    # Close connection
    cur.close() 

@app.route('/article/<string:id>/')
def article(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get Article
    result = cur.execute("SELECT * FROM articles WHERE id = %s",(id))
    
    article = cur.fetchone()

    return render_template('article.html',article=article)

# User Registration form
class RegisterForm(Form):
    name = StringField('Name',[validators.Length(min=1,max=50)])
    username = StringField('Username',[validators.Length(min=3,max=25)])
    email = StringField('Email',[validators.Length(min=5,max=50)])
    password = PasswordField('Password',[
        validators.DataRequired(),
        validators.EqualTo('confirm',message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register',methods = ['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #create Cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name,email,username,password) VALUES(%s,%s,%s,%s)",(name,email,username,password))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('You are now registered and can log in','success')

        return redirect(url_for('login'))

    return render_template('register.html',form = form)

# Login route
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor 
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s",[username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_candidate,password):
                #Store user session
                session['logged_in'] = True
                session['username'] = username
                flash('You are now logged in','success')
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid login"
                return render_template('login.html',error=error)
            cur.close()
        else:
            error = "No such username"
            return render_template('login.html',error=error)
    
    return render_template('login.html')

#Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('Unauthorized,Please Login','danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out','success')
    return redirect(url_for('login'))

# User dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    cur = mysql.connection.cursor()
    # Get Articles
    result = cur.execute("SELECT * FROM articles")
    
    articles = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html',articles=articles)
    else:
        msg = "No Articles found"
        return render_template('dashboard.html',msg=msg)
    # Close connection
    cur.close() 

    return render_template('dashboard.html')

# Add Article form
class AddArticleForm(Form):
    title = StringField('Title',[validators.Length(min=5,max=200)])
    body = TextAreaField('Body',[validators.Length(min=30)])
    
# Add Article
@app.route('/add_article',methods = ['GET','POST'])
@is_logged_in
def add_article():
    form = AddArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Create Aursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("INSERT into articles(title,body,author) VALUES(%s,%s,%s)",(title,body,session['username']))
        # Commit
        mysql.connection.commit()
        #Close connection
        cur.close()

        flash('Article Created','success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html',form = form)

if __name__=='__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
