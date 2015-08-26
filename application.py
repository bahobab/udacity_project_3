from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from bookdb import Base, Category, Book, Publisher, Author, User, Review
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from datetime import datetime
from flask.ext.seasurf import SeaSurf
import bleach


app = Flask(__name__)
# create csrf object
csrf = SeaSurf(app)
# location where images are saved. Used for book cover and author image
IMG_COVER_SRC = '/static/img/bookcover/'
IMG_AUTHOR_SRC = '/static/img/author/'
DEFAULT_COVER_IMG = 'faces.jpg'
DEFAULT_AUTHOR_IMG = 'faces.jpg'

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

#APPLICATION_NAME = "Art Book Exchange"
#def generate_csrf_token():
#    """Helper function to generate CSRF token then return it"""
#    if '_csrf_token' not in login_session:
#        login_session['_csrf_token'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
#    return login_session['_csrf_token']
#
#app.jinja_env.globals['csrf_token'] = generate_csrf_token

engine = create_engine('sqlite:///artbookdb')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """ for login """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, csrf=state)

# Server-side calls
@csrf.exempt
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """ for facebook connection """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
#    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.2/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    #url = 'https://graph.facebook.com/v2.2/me?%s' % token
    url = 'https://graph.facebook.com/v2.2/me?%s&fields=id,name,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    for i in data:
        print data[i]
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

@app.route('/fbdisconnect')
def fbdisconnect():
    """ for faceboock diconnection """
    try:
        facebook_id = login_session['facebook_id']
        # The access token must me included to successfully logout
        access_token = login_session['access_token']
        url = 'https://graph.facebook.com/%s&%s/permissions' % (facebook_id,access_token)

        h = httplib2.Http()
        result = h.request(url, 'DELETE')[1]
        return "you have been logged out"
    except:
        return "you may be offline. You cannot be logged out at this time"

@csrf.exempt
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ for gmail connection"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# --------- Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    print login_session
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
#            login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('home'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showLogin'))

# ----------------- Making API calls
@app.route('/feed/<class_name>/ATOM')
def feedATOM(class_name):
    authors = session.query(Author).all()
    publishers = session.query(Publisher).all()
    books = session.query(Book).all()
    class_name = class_name.upper()
    if class_name == 'AUTHORS':
        return render_template('feedtemplate.html', class_name = class_name, items = authors)
    elif class_name == 'PUBLISHERS':
        return render_template('feedtemplate.html', class_name = class_name, items = publishers)
    elif class_name == 'BOOKS':
        return render_template('feedtemplate.html', class_name = class_name, items = books)

@app.route('/authors/JSON')
def authorsJSON():
    """ API for authers """
    authors = session.query(Author).all()
    return jsonify(Authors = [i.serialize for i in authors])

@app.route('/publishers/JSON')
def publishersJSON():
    """ API for publishers """
    publishers = session.query(Publisher).all()
    return jsonify(Publishers = [i.serialize for i in publishers])

@app.route('/categories/JSON')
def categoriesJSON():
    """ API for categories """
    categories = session.query(Category).all()
    return jsonify(Categories = [i.serialize for i in categories])

@app.route('/books/JSON')
def booksJSON():
    """ API for books """
    books = session.query(Book).all()
    return jsonify(Books = [i.serialize for i in books])

@app.route('/categories/<int:category_id>/books/JSON')
def categoryBookJSON(category_id):
    """ API for book by category """
    try:
        category = session.query(Category).filter_by(id = category_id).one()
        books = session.query(Book).filter_by(category_id = category.id).all()
        return jsonify(categoryBooks = [i.serialize for i in books])
    except:
        return redirect(url_for('notFound'))

@app.route('/authors/<int:author_id>/books/JSON')
def authorBookJSON(author_id):
    """ API for book by category """
    try:
        author = session.query(Author).filter_by(id = author_id).one()
        books = session.query(Book).filter_by(author_id = author.id).all()
        return jsonify(authorBooks = [i.serialize for i in books])
    except:
        return redirect(url_for('notFound'))

@app.route('/publishers/<int:publisher_id>/books/JSON')
def publisherBookJSON(publisher_id):
    """ API for book by category """
    try:
        publisher = session.query(Publisher).filter_by(id = publisher_id).one()
        books = session.query(Book).filter_by(publisher_id = publisher.id).all()
        return jsonify(PublisherBooks = [i.serialize for i in books])
    except:
        return redirect(url_for('notFound'))

# ---------------- end API ------------------------

# ----------------- begin controller/view ------------------
@app.route('/notFound/')
def pageNotFound():
    """for 404 errors"""
    return render_template('404-notfound.html')

@app.route('/')
@app.route('/home/')
def home():
    """ access to home page """
    return render_template('home.html')

@app.route('/contact/')
def contact():
    """ Contact page """
    return render_template('contact.html')

@app.route('/categories/')
def categories():
    """ PUBLIC: List All Book Categories"""
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('categoriesp.html', categories = categories)
    return render_template('categories.html', categories = categories)

@app.route('/categories/new/', methods = ['POST','GET'])
def newCategory():
    """ LOGIN required to create a new book category
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
            if request.form['name']:
                try:
                    category_id = getID(bleach.clean(request.form['name']), 'Category')
                    newCategory = session.query(Category).filter_by(id = category_id).one()
                    if newCategory:
                        flash('New Category %s Successfully Added...' %newCategory.name)
                except:
                    flash('Failed To Add New Category')
            else:
                flash('Failed: Please Fill Out Category Name Field')
            return redirect(url_for('categories'))
    return render_template('newcategory.html')

@app.route('/categories/<int:category_id>/edit/', methods = ['POST','GET'])
def editCategory(category_id):
    """ LOGIN required to edit existing book category """
    if 'username' not in login_session:
        return redirect('/login')
    categoryToEdit = session.query(Category).filter_by(id = category_id).one()
    if login_session['user_id'] == categoryToEdit.user.id:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
                if request.form['name']:
                    try:
                        categoryToEdit.name = bleach.clean(request.form['name'])
                        session.add(categoryToEdit)
                        session.commit()
                        flash('Category %s Successfully Edited...' %categoryToEdit.name)
                    except:
                        flash('Failed To Edit Category %s...' %newCategory.name)
                    return redirect(url_for('categories'))
        else:
            return render_template('editcategory.html', category = categoryToEdit)
    else:
        flash('You Do Not Have The Rights To Edit This Category')
        return redirect(url_for('categories'))

@app.route('/categories/<int:category_id>/delete/', methods = ['POST', 'GET'])
def deleteCategory(category_id):
    """ LOGIN required to delete a book category
    create a delete function for each class. category.delete()??
    """
    if "username" not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(id = category_id).one()
    if login_session['user_id'] == categoryToDelete.user.id:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
                if isFreeToDelete(categoryToDelete, 'Category'):
                    try:
                        session.delete(categoryToDelete)
                        session.commit()
                        flash('Category %s Successfully Deleted...' %categoryToDelete.name)
                    except:
                        flash('Failed To Delete Category %s...' %newCategory.name)
                else:
                    flash('There Still Are Books Depending On %s... Cannot Be Deleted!' %categoryToDelete.name)
                return redirect(url_for('categories'))
        else:
            return render_template('deleteCategory.html', category = categoryToDelete)
    else:
        flash('You Do Not Have The Rights To Delete This Category')
        return redirect(url_for('categories'))

@app.route('/books/')
def allBooks():
    """PUBLIC: Show all Books """
    books = session.query(Book).all()
    if "username" not in login_session:
        return render_template('allbooksp.html', books = books)
    return render_template('allbooks.html', books = books, user_id = login_session['user_id'])

@app.route('/books/categories/<int:category_id>/')
def booksByCategory(category_id):
    """ PUBLIC: Show all Books in by category
        LOGIN required to have new, edit and delete options """
    category = session.query(Category).filter_by(id = category_id).one()
    books = session.query(Book).filter_by(category_id = category_id).all()
    if "username" not in login_session:
        return render_template('booksbycategoryp.html', books = books, category = category)
    return render_template('booksbycategory.html', books = books, category = category)

@app.route('/books/publishers/<int:publisher_id>/')
def booksByPublisher(publisher_id):
    """ PUBLIC: Show all Books in by publisher
        LOGIN required to have new, edit and delete options """
    publisher = session.query(Publisher).filter_by(id = publisher_id).one()
    books = session.query(Book).filter_by(publisher_id = publisher_id).all()
    if "username" not in login_session:
        return render_template('booksbypublisherp.html', books = books, publisher = publisher)
    return render_template('booksbypublisher.html', books = books, publisher = publisher)

@app.route('/books/authors/<int:author_id>/', methods = ['GET'])
def booksByAuthor(author_id):
    """ PUBLIC: Show all Books in by author
        LOGIN required to have new, edit and delete options """
    author = session.query(Author).filter_by(id = author_id).one()
    booksByAuthor = session.query(Book).filter_by(author_id = author_id).all()
    if 'username' not in login_session:
        return render_template('booksbyauthorp.html', author = author, books = booksByAuthor)
    return render_template('booksbyauthor.html', author = author, books = booksByAuthor)
#
@app.route('/books/new/<class_name>/<int:class_id>/', methods = ['POST','GET'])
def newBook(class_name, class_id):
    """ LOGIN requred to add a new book """
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    authors = session.query(Author).all()
    publishers = session.query(Publisher).all()
    # These arrays are passed to the new book template to provide autocomplete
    categoryNames = []
    authorNames = []
    publisherNames = []
    for category in categories:
        categoryNames.append(str(category.name))
    for author in authors:
        authorNames.append(str(author.name))
    for publisher in publishers:
        publisherNames.append(str(publisher.name))
    # Get an obbject by the class id
    if class_name == 'Author':
        class_object = session.query(Author).filter_by(id = class_id).one()
    if class_name == 'Category':
        class_object = session.query(Category).filter_by(id = class_id).one()
    if class_name == 'Publisher':
        class_object = session.query(Publisher).filter_by(id = class_id).one()

    if request.method == 'POST':
        if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
#            try:
            # get the object id from the name
            # leading white space introduced by auto-complete, strip them
            fieldName = bleach.clean(request.form['category'])
            category_id = getID(fieldName.strip(), 'Category')
            fieldName = bleach.clean(request.form['author'])
            author_id = getID(fieldName.strip(), 'Author')
            fieldName = bleach.clean(request.form['publisher'])
            publisher_id = getID(fieldName.strip(),'Publisher')
            imageURL = bleach.clean(request.form['imageURL'])
            if imageURL:
                if '\\' in imageURL:
#                   string contains a Windows style path
                    print '>>>>>>>>>>>', imageURL
                    imgPath = imageURL.split('\\')
                    imageURL = imgPath[-1]
                    print '#########', imageURL
                else:
                    imageURL = IMG_COVER_SRC + imageURL
            else:
                imageURL = IMG_COVER_SRC + DEFAULT_COVER_IMG
            try:
                newBook = Book(
                    title = request.form['title'],
                    category_id = int(category_id),
                    author_id = int(author_id),
                    publisher_id = int(publisher_id),
                    isbn = bleach.clean(request.form['isbn']),
                    datepub = bleach.clean(request.form['datePub']),
                    language = bleach.clean(request.form['language']),
                    edition = bleach.clean(request.form['edition']),
                    condition = bleach.clean(request.form['condition']),
                    binding = bleach.clean(request.form['binding']),
                    imageURL = imageURL,
                    available = bleach.clean(request.form['available']),
                    summary = bleach.clean(request.form['summary']),
                    user_id = login_session['user_id'])
#                print bleach.clean(request.form['imageURL'])
                        # use try
                session.add(newBook)
                session.commit()
                flash('New Book %s Successfully Added' %newBook.title)
                if class_name == 'Category':
                    return redirect(url_for('booksByCategory', category_id = category_id))
                elif class_name == 'Author':
                    return redirect(url_for('booksByAuthor', author_id = author_id))
                elif class_name == 'Publisher':
                    return redirect(url_for('booksByPublisher', publisher_id = publisher_id))
            except:
                flash('FAILED: New Book %s Could Not Be Added' %newBook.title)
                if class_name == 'Category':
                    return redirect(url_for('booksByCategory', category_id = category_id))
                elif class_name == 'Author':
                    return redirect(url_for('booksByAuthor', author_id = author_id))
                elif class_name == 'Publisher':
                    return redirect(url_for('booksByPublisher', publisher_id = publisher_id))
    else:
        return render_template('newbook.html', class_object = class_object,
                               class_name = class_name,
                               categoryNames = categoryNames,
                               authorNames = authorNames,
                               publisherNames = publisherNames)

@app.route('/books/<int:book_id>/<class_name>/edit/', methods = ['POST','GET'])
def editBook(book_id, class_name):
    """ LOGIN required to edit a book
    """
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    authors = session.query(Author).all()
    publishers = session.query(Publisher).all()
    categoryNames = []
    authorNames = []
    publisherNames = []
    for category in categories:
        categoryNames.append(str(category.name))
    for author in authors:
        authorNames.append(str(author.name))
    for publisher in publishers:
        publisherNames.append(str(publisher.name))
    bookToEdit = session.query(Book).filter_by(id = book_id).one()

    if bookToEdit.user_id == login_session['user_id']:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None),
                           request.form.get('_csrf_token'))):
                try:
                    if request.form['title']:
                        bookToEdit.title = bleach.clean(request.form['title'])
                    if request.form['isbn']:
                        bookToEdit.isbn = bleach.clean(request.form['isbn'])
                    if request.form['datePub']:
                        bookToEdit.datepub = bleach.clean(request.form['datePub'])
                    if request.form['language']:
                        bookToEdit.language = bleach.clean(request.form['language'])
                    if request.form['edition']:
                        bookToEdit.edition = bleach.clean(request.form['edition'])
                    if request.form['condition']:
                        bookToEdit.condition = bleach.clean(request.form['condition'])
                    if request.form['binding']:
                        bookToEdit.binding = bleach.clean(request.form['binding'])
                    if request.form['available']:
                        bookToEdit.available = bleach.clean(request.form['available'])
                    if request.form['imageURL']:
#                        print '>>>>>>>>>>', bleach.clean(request.form['imageURL'])
                        imageURL = bleach.clean(request.form['imageURL'])
                        if '\\' in imageURL:
                            imgPath = imageURL.split('\\')
                            imageURL = imgPath[-1]
                        bookToEdit.imageURL = IMG_COVER_SRC + imageURL
                    if request.form['summary']:
                        bookToEdit.summary = bleach.clean(request.form['summary'])
                    if request.form['category']:
                        fieldName = bleach.clean(request.form['category'])
                        bookToEdit.category_id = getID(fieldName.strip(), 'Category')
                    if request.form['author']:
                        fieldName = bleach.clean(request.form['author'])
                        bookToEdit.author_id = getID(fieldName.strip(), 'Author')
                    if request.form['publisher']:
                        fieldName = bleach.clean(request.form['publisher'])
                        bookToEdit.publisher_id = getID(fieldName.strip(),'Publisher')
                    session.add(bookToEdit)
                    session.commit()
                    flash('Book %s Successfully Edited' %bookToEdit.title)
                    if class_name == 'Category':
                        return redirect(url_for('booksByCategory',
                                                category_id = bookToEdit.category_id))
                    elif class_name == 'Author':
                        return redirect(url_for('booksByAuthor',
                                                author_id = bookToEdit.author_id))
                    elif class_name == 'Publisher':
                        return redirect(url_for('booksByPublisher',
                                                publisher_id = bookToEdit.publisher_id))
                    elif class_name == 'All':
                        return redirect(url_for('allBooks'))
                except:
                    flash('Book %s Could not Be Edited' %bookToEdit.title)
                    if class_name == 'Category':
                        return redirect(url_for('booksByCategory',
                                                category_id = bookToEdit.category_id))
                    elif class_name == 'Author':
                        return redirect(url_for('booksByAuthor',
                                                author_id = bookToEdit.author_id))
                    elif class_name == 'Publisher':
                        return redirect(url_for('booksByPublisher',
                                                publisher_id = bookToEdit.publisher_id))
                    elif class_name == 'All':
                        return redirect(url_for('allBooks'))
        else:
            return render_template('editbook.html',
                               class_name = class_name,
                               book = bookToEdit,
                               categoryNames = categoryNames,
                               authorNames = authorNames,
                               publisherNames = publisherNames)
    else:
        flash('You Do Not Have The Permission To Edit This Book')
        if class_name == 'Category':
            return redirect(url_for('booksByCategory',
                                    category_id = bookToEdit.category_id))
        elif class_name == 'Author':
            return redirect(url_for('booksByAuthor',
                                    author_id = bookToEdit.author_id))
        elif class_name == 'Publisher':
            return redirect(url_for('booksByPublisher',
                                    publisher_id = bookToEdit.publisher_id))
        elif class_name == 'All':
            return redirect(url_for('allBooks'))

@app.route('/books/<int:book_id>/<class_name>/delete/', methods = ['POST', 'GET'])
def deleteBook(book_id, class_name):
    """ LOGIN required to delete a book """
    if 'username' not in login_session:
        return redirect('/login')
    bookToDelete = session.query(Book).filter_by(id = book_id).one()
    category_id = bookToDelete.category_id
    author_id = bookToDelete.author_id
    publisher_id = bookToDelete.publisher_id
    if bookToDelete.user_id == login_session['user_id']:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None),
                           request.form.get('_csrf_token'))):
                try:
                    deleteBookReviews(bookToDelete)
                    session.delete(bookToDelete)
                    session.commit()
                    flash('%s Successfuly Deleted...' %bookToDelete.title)
                    # delete all reviews for this book
                    if class_name == 'Category':
                        return redirect(url_for('booksByCategory', category_id = category_id))
                    elif class_name == 'Author':
                        return redirect(url_for('booksByAuthor', author_id = author_id))
                    elif class_name == 'Publisher':
                        return redirect(url_for('booksByPublisher',
                                                publisher_id = publisher_id))
                    elif class_name == 'All':
                        return redirect(url_for('allBooks'))
                except:
                    flash('FAILED: %s Could Not Be Deleted...' %bookToDelete.title)
                    if class_name == 'Category':
                        return redirect(url_for('booksByCategory', category_id = category_id))
                    elif class_name == 'Author':
                        return redirect(url_for('booksByAuthor', author_id = author_id))
                    elif class_name == 'Publisher':
                        return redirect(url_for('booksByPublisher',
                                                publisher_id = publisher_id))
                    elif class_name == 'All':
                        return redirect(url_for('allBooks'))
        else:
            return render_template('deletebook.html',
                                   book = bookToDelete,
                                   class_name = class_name)
    else:
        flash('You Do Not Have The Right To Delete This Book')
        if class_name == 'Category':
            return redirect(url_for('booksByCategory', category_id = category_id))
        elif class_name == 'Author':
            return redirect(url_for('booksByAuthor', author_id = author_id))
        elif class_name == 'Publisher':
            return redirect(url_for('booksByPublisher',
                                    publisher_id = publisher_id))
        elif class_name == 'All':
            return redirect(url_for('allBooks'))
@app.route('/books/delete/<int:user_id>/all/', methods = ['POST', 'GET'])
def deleteAllMyBooks(user_id):
    """ Delete all the books by a user all at once"""
    if 'username' not in login_session:
        return redirect('/login')
    user = session.query(User).filter_by(id = user_id).one()
    if request.method == 'POST':
        if user_id != login_session['user_id']:
            flash('You Do Not Have The Rights To Perform This Operation')
        else:
            if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
                try:
                    n = 0
                    for book in session.query(Book).filter_by(user_id = user_id).all():
                        session.delete(book)
                        # delete reviews for this book
                        deleteBookReviews(book)
                        n += 1
                    session.commit()
                    flash('All Your Books Were Successfully Deleted')
                except:
                    flash('No Books Were Deleted')
                return redirect(url_for('allBooks'))
    return render_template('deleteallmybooks.html', user = user)

@app.route('/review/book/<int:book_id>/, <class_name>/', methods = ['POST', 'GET'])
def reviewBook(book_id, class_name):
    """Any logged in user can add reviews to any book"""
    bookToReview = session.query(Book).filter_by(id = book_id).one()
    reviews = session.query(Review).filter_by(book_id = bookToReview.id).all()
    if 'username' not in login_session:
        return render_template('reviewbookp.html',
                               book = bookToReview,
                               reviews = reviews,
                               class_name = class_name)
    if request.method == 'POST':
        if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
            if request.form['review']:
                try:
                    newReview = Review(
                        text = bleach.clean(request.form['review']),
                        date = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        user_id = login_session['user_id'],
                        book_id = bookToReview.id)
                    session.add(newReview)
                    session.commit()
                    flash('Your Review Was Successfully Posted...')
                except:
                    flash('FAILED: Your Review Could Not Be Posted...')
                return redirect(url_for('reviewBook',
                                        book_id = bookToReview.id,
                                        class_name = class_name))
    return render_template('reviewbook.html',
                           book = bookToReview,
                           reviews = reviews,
                           class_name = class_name,
                           user_id = login_session['user_id'])

@app.route('/review/book/<int:book_id>/<int:review_id>/<class_name>/', methods = ['POST', 'GET'])
def deleteBookReview(book_id, review_id, class_name):
    """ Delete a single book review by a user
    Only a logged in user can delete her/his own review
    """
    if 'username' not in login_session:
        return redirect('/login')
    bookToReview = session.query(Book).filter_by(id = book_id).one()
    reviewToDelete = session.query(Review).filter_by(id = review_id).one()
    if login_session['user_id'] == reviewToDelete.user.id:
        try:
            session.delete(reviewToDelete)
            session.commit()
            flash('Review Successfully Removed')
        except:
            flash('FAILED: Review Could Not Be Removed')
    else:
        flash('You do not have the right to delete this review')
    return redirect(url_for('reviewBook', book_id = bookToReview.id, class_name = class_name))

@app.route('/publishers/')
def publishers():
    """ PUBLIC: list of publishers
    Login required to access new, edit, delete options """
    publishers = session.query(Publisher).all()
    if 'username' not in login_session:
        return render_template('publishersp.html', publishers = publishers)
    return render_template('publishers.html', publishers = publishers)

@app.route('/publishers/new', methods = ['POST', 'GET'])
def newPublisher():
    """ LOGIN required to add a new publisher
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
            if request.form['name']:
                # use helper function to check if publisher already exists
                publisher_id = getID(bleach.clean(request.form['name']), 'Publisher')
                try:
                    newPublisher = session.query(Publisher).filter_by(id = publisher_id).one()
                    newPublisher.address = bleach.clean(request.form['address'])
                    session.add(newPublisher)
                    session.commit()
                    flash("New Publisher %s Successfully Added..." %newPublisher.name)
                except:
                    flash('Failed: New Publisher %s Could Not Be Added...' %newPublisher.name)
            else:
                flash('Failed: Please Fill Out Publisher Name Field')
            return redirect(url_for('publishers'))
    return render_template('newPublisher.html')

@app.route('/publishers/<int:publisher_id>/edit/', methods = ['POST', 'GET'])
def editPublisher(publisher_id):
    """ LOGIN required to edit a publisher """
    if 'username' not in login_session:
        return rdirect('/login')
    publisherToEdit = session.query(Publisher).filter_by(id = publisher_id).one()
    if publisherToEdit.user_id == login_session['user_id']:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
                if request.form['name']:
                    publisherToEdit.name = bleach.clean(request.form['name'])
                if request.form['address']:
                    publisherToEdit.address = bleach.clean(request.form['address'])
                try:
                    session.add(publisherToEdit)
                    session.commit()
                    flash('Publisher %s Successfully Edited...' %publisherToEdit.name)
                except:
                    flash('FAILED: Publisher %s Could Not Be Edited...' %publisherToEdit.name)
                return redirect(url_for('publishers'))
        else:
            return render_template('editpublisher.html', publisher = publisherToEdit)
    else:
        flash('You Do Not Have The Rights To Edit This Publisher')
        return redirect(url_for('publishers'))

@app.route('/publishers/<int:publisher_id>/delete/', methods = ['POST','GET'])
def deletePublisher(publisher_id):
    """ LOGIN required to delete a publisher """
    if 'username' not in login_session:
        return rdirect('/login')
    publisherToDelete = session.query(Publisher).filter_by(id = publisher_id).one()
    if publisherToDelete.user_id == login_session['user_id']:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None),
                           request.form.get('_csrf_token'))):
                if isFreeToDelete(publisherToDelete, "Publisher"):
                    #if no books depend on this publisher, then it can be deleted
                    try:
                        session.delete(publisherToDelete)
                        session.commit()
                        flash('Publisher %s Successfully Deleted...' %publisherToDelete.name)
                    except:
                        flash('FAILED: Publisher %s Could Not Be Deleted...' %publisherToDelete.name)
                else:
                    flash('There Still Are Books Depending On %s... Cannot Be Deleted!' %publisherToDelete.name)
                return redirect('publishers')
        else:
            return render_template('deletepublisher.html', publisher = publisherToDelete)
    else:
        flash('You Do Not Have the Rights To Delete This Publisher')
        return redirect('publishers')

@app.route('/authors/')
def authors():
    """ PUBLIC: list all the authors
        Login required to access new, edit delete options"""
    authors = session.query(Author).all()
    if 'username' not in login_session:
        return render_template('authorsp.html', authors = authors)
    return render_template('authors.html', authors = authors)

@app.route('/authors/new/', methods = ['POST','GET'])
def newAuthor():
    """ LOGIN required to add a new author
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
            if request.form['name']:
                author_id = getID(bleach.clean(request.form['name']), 'Author')
                newAuthor = session.query(Author).filter_by(id = author_id).one()
                newAuthor.active = bleach.clean(request.form['active'])
                if request.form['imageURL']:
                    newAuthor.imageURL = bleach.clean(request.form['imageURL'])
                else:
                    newAuthor.imageURL = IMG_AUTHOR_SRC + DEFAULT_AUTHOR_IMG
                try:
                    session.add(newAuthor)
                    session.commit()
                    flash('New Author %s Successfully Added...' %newAuthor.name)
                except:
                    flash('FAILED: New Author %s Created. Some Fields Could Not Be Added...' %newAuthor.name)
            else:
                flash('Failed: Please Fill Out Author Name Field')
            return redirect(url_for('authors'))
    return render_template('newAuthor.html')

@app.route('/authors/<int:author_id>/edit/', methods = ['POST', 'GET'])
def editAuthor(author_id):
    """ LOGIN rewuired to edit an authour """
    if 'username' not in login_session:
        return redirect('/login')
    authorToEdit = session.query(Author).filter_by(id = author_id).one()
    if authorToEdit.user_id == login_session['user_id']:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None), request.form.get('_csrf_token'))):
                if request.form['name']:
                    authorToEdit.name = bleach.clean(request.form['name'])
                if request.form['active']:
                    authorToEdit.active = bleach.clean(request.form['active'])
                if request.form['imageURL']:
                    authorToEdit.imageURL = bleach.clean(request.form['imageURL'])
                try:
                    session.add(authorToEdit)
                    session.commit()
                    flash('Author %s Successfully Edited...' %authorToEdit.name)
                except:
                    flash('FAILED: Author %s Could Not Be Edited...' %authorToEdit.name)
                return redirect('authors')
        else:
            return render_template('editauthor.html', author = authorToEdit)
    else:
        flash('You Do Not Have The Rights To Edit This Author')
        return redirect('authors')

@app.route('/authors/<int:author_id>/delete/', methods = ['POST','GET'])
def deleteAuthor(author_id):
    """ LOGIN required to delete an authour """
    if 'username' not in login_session:
        return redirect('/login')
    authorToDelete = session.query(Author).filter_by(id = author_id).one()
    if authorToDelete.user_id == login_session['user_id']:
        if request.method == 'POST':
            if (check_csrf(login_session.pop('_csrf_token', None),
                           request.form.get('_csrf_token'))):
                if isFreeToDelete(authorToDelete, "Author"):
                    try:
                        session.delete(authorToDelete)
                        session.commit()
                        flash('Author %s Successfully Deleted...' %authorToDelete.name)
                    except:
                        flash('FAILED: Author %s Could Not Be Deleted...' %authorToDelete.name)
                else:
                    flash('There Still Are Books Depending On %s...Cannot Be Deleted!' %authorToDelete.name)
                return redirect('authors')
        else:
            return render_template('deleteauthor.html', author = authorToDelete)
    else:
        flash('You Do Not Have The Rights To Delete This Author')
        return redirect('authors')

# -------- end routes --------------

# --------- helper function for deleting an item ---------
def check_csrf(csrf_token, form_csrf_token):
    """Helper function to check for valid CSRF token
    Called after each if request.method == 'POST'
    """
    if not csrf_token or csrf_token != form_csrf_token:
            abort(403)
    else:
        return True

def isFreeToDelete(class_object, class_name):
    """ Check if there are no books by author or publisher
    or category before deleting this author or publisher or category
    Input: author or publisher object, class name (Publisher or Author)
    Return: True no more books by publisher or author. Or False otherwise
    """
    if class_name == 'Author':
        try:
            booskByAuthor = session.query(Book).filter_by(author_id = class_object.id).one()
            # there's at least one book by this author
            return False
        except:
            return True
    elif class_name == 'Publisher':
        try:
            booskByPublisher = session.query(Book).filter_by(publisher_id = class_object.id).one()
            # there's at least one book by this publisher
            return False
        except:
            return True
    elif class_name == 'Category':
        try:
            booskByCategory = session.query(Book).filter_by(category_id = class_object.id).one()
            # there's at least one book by this category
            return False
        except:
            return True

# ------------ User Helper Functions
def createUser(login_session):
    """ Helper function to create a user after login for first time
        input: login_session
        return: id of the newly created user
    """
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

# ------------- login helper functions
def getUserInfo(user_id):
    """ Helper function to get the user name from local user table
        input: user id
        return: user object
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    """ Helper function to the user id
        input: email address of the login user
        return: user object
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# ------------------- newBook Form processing helper funtions ------------------
def getID(itemName, itemClass):
    """ try to fetch item object by name, return object id if found
    if not found then call addItem function to create it
    """
    if itemClass == 'Category':
        try:
            item = session.query(Category).filter_by(name = itemName).one()
#            print '>>>> found %s' %item.name
            return item.id
        except:
            return addItem(itemName, itemClass)
    elif itemClass == 'Author':
        try:
            item = session.query(Author).filter_by(name = itemName).one()
#            print '>>>> found %s' %item.name
            return item.id
        except:
            return addItem(itemName, itemClass)
    elif itemClass == 'Publisher':
        try:
            item = session.query(Publisher).filter_by(name = itemName).one()
#            print '>>>> found %s' %item.name
            return item.id
        except:
            return addItem(itemName, itemClass)
    else:
        return None

def addItem(itemName, itemClass):
    """add item object then return object id
    CLEANUP: REMOVE DEBUGING CODE
    """
    if itemClass == 'Category':
        newCategory = Category(name = itemName, user_id = login_session['user_id'])
        session.add(newCategory)
        session.commit()
        category = session.query(Category).filter_by(name = itemName).one()
#        print '>>not found..created...', category.name
        return category.id
    if itemClass == 'Author':
        newAuthor = Author(name = itemName, user_id = login_session['user_id'])
        session.add(newAuthor)
        session.commit()
        author = session.query(Author).filter_by(name = itemName).one()
#        print '>>not found..created...', author.name
        return author.id
    if itemClass == 'Publisher':
        newPublisher = Publisher(name = itemName, user_id = login_session['user_id'])
        session.add(newPublisher)
        session.commit()
        publisher = session.query(Publisher).filter_by(name = itemName).one()
#        print '>>not found..created...', publisher.name
        return publisher.id

def deleteBookReviews(book):
    """delete all reviews for a given book
    input: book_id
    return:
    """
    n = 0
    try:
        reviews = session.query(Review).filter_by(book_id = book.id).all()
        for review in reviews:
            session.delete(review)
            n += 1
        session.commit()
#        print 'deleted reviews for book ', n, book.title
        return n
    except:
#        print 'no review for book %s' %book.title
#        n = 0
        return n

# ---------- end helper functions ------------

# ----------- MAIN --------------
if __name__ == '__main__':
    app.secret_key = '64GALE3CE5SIGH5KFCTDMD3TJFV2S4W6'
    #app.debug = True
    app.run( host = '0.0.0.0', port = 5000)
