import os
from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from faker import Faker

from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, TextAreaField, TextField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user




basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'asdfasdfasdfasdf'

db = SQLAlchemy(app)

#Creates the database

login_manager = LoginManager(app)
login_manager.login_view = 'login'

#set up database models 
#will likely add relationships
# add roles

    
bid = db.Table('bids',
db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
db.Column('item_id', db.Integer, db.ForeignKey('items.id'))
)


#USERS
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(120))
    last_name = db.Column(db.String(120))
    first_name = db.Column(db.String(120))
    email = db.Column(db.String(120))
    items = db.relationship('Item', secondary='bids', backref=db.backref('user', lazy='dynamic'))
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

#ITEMS
class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    person_id(db.Integer, db.ForeignKey('user.id'))
    itemname = db.Column(db.String(64), nullable=False)
    item_price = db.Column(db.Integer, nullable=False )
    description = db.Column(db.String(164), nullable=False)
    users = db.relationship('User', secondary='bids', backref=db.backref('Item', lazy='dynamic'))
   ##idk if person id will work
    
    def __init__(self, itemname, item_price, description):
       self.itemname = itemname
       self.item_price = item_price
       self.description = description
      
    def __repr__(self):
        return '<Item {}>'.format(self.itemname)

#OFFERS




 
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Submit')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1,64)])
    username = StringField('Username', validators=[DataRequired(), Length(1,64)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(1,64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(1,64)])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Passwords Must Match')])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first() is not None: 
            raise ValidationError('Username already in use') 

class ItemForm(FlaskForm):
    itemname = TextField('Item Name', validators=[DataRequired(), Length(1,64)])
    item_price = IntegerField('Item Price', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit')



@login_manager.user_loader 
def load_user(id):
    return User.query.get(int(id)) 

#set up routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm() 
    print("before validation")
    if form.validate_on_submit(): 
        print("after validation")
        user = User(email=form.email.data, username=form.username.data, password=form.password.data) 
        db.session.add(user) 
        db.session.commit() 
        flash('You can now login.')
        return redirect(url_for('login')) 
    return render_template('register.html', form=form) 

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() 
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash("Logged in.")
            return redirect(url_for('index'))
        flash('Incorrect Information')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)


@app.route('/itempage', methods=['GET', 'POST'])
def itempage():
    itemForm = ItemForm() 
    if itemForm.validate_on_submit():
        items = Item(itemname=itemForm.itemname.data, item_price=itemForm.item_price.data, description=itemForm.description.data)
        db.session.add(items) 
        db.session.commit() 
        itemForm.itemname.data=''
        itemForm.item_price.data=''
        itemForm.description.data=''
        return redirect(url_for('itempage'))
    items = Item.query.all()
    return render_template('itempage.html', form=itemForm, items=items)
#logout
@app.route('/logout')
def logout():
    logout_user()
    flash("You've been logged out")
    return redirect(url_for('index'))  



#user actioneer
@app.route('/auctioneer')
@login_required
def auctioneer():
    if current_user.is_auctioneer:
        return render_template('auctioneer.html')
    flash("You're not an auctioneer!")
    return redirect(url_for('index'))

#user bidder
#Bidder page - displays the items a specific Bidder has bid on and whether they've been won or not.  
#If the user id provided isn't a bidder, show an error
@app.route('/bidder/<username>')
@login_required
def bidder(username):
    if current_user.is_bidder:
        return 'User %s' % escape(username)
    else: 
        error = 'You dont have permission to view this page'
    return redirect(url_for('index', error=error))

@app.route('/bids')
def bids():
    bid_data = Bid.query.all()
    return render_template('bids.html', bid_data=bid_data)

#Item Listing - displays a list of all items
@app.route('/items')
def all_items():
    item_data = Item.query.all()
    return render_template('items.html', item_data=item_data)

@app.route('/items/<item_id>')
def item(itemname):
    item_data = Item.query.get_or_404(int(id))
    return render_template('items.html', item_data=item_data)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)


#Item page - displays an item and all of the current bids on it.  If the auction is on-going, logged-in Bidders can add a bid.  If the auction is over, no more bids are allowed
#---->If the user is the Auctioneer of this specific item, display the contact information of the winner.








#ROUTES/pages
#Auctioneer page - displays the items a specific Auctioneer has created and whether they've been won or not, and the user information of each connected winner.
#---->Auctioneers must also be able to create new items, either on this page or on another page specifically for this purpose
#Admin page - displays a list of all users
#---->The admin must have the ability to modify existing user passwords and roles, either on this page or another page specifically for this purpose
#---->The admin must have the ability to create a new user with any role, either on this page or another page specifically for this purpose
#New User page - a page where someone can create a new Bidder account
#----->Generated html pages must be valid html





if __name__ == '__main__':
    app.run(debug=True)
