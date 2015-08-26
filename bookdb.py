import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column( Integer, primary_key = True )
    name = Column( String(50), nullable = False )
    email = Column( String(250), nullable = False )
    picture = Column( String(250))
    phone = Column( String(10) )
    address = Column( String(500) )

class Category(Base):
    """ book category """
    __tablename__ = 'category'
    id = Column( Integer, primary_key = True )
    name = Column( String(50), nullable = False )
    user_id = Column( Integer, ForeignKey('user.id'), nullable = False)
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'name': self.name
        }

class Author(Base):
    """ Book author """
    __tablename__ = 'author'
    id = Column( Integer, primary_key = True )
    name = Column( String(150), nullable = False )
    active = Column( Integer)
    imageURL = Column( String(250))
    user_id = Column( Integer, ForeignKey('user.id'), nullable = False)
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'name': self.name,
            'active': self.active
        }

class Publisher(Base):
    """ Book publisher """
    __tablename__ = 'publisher'
    id = Column( Integer, primary_key = True)
    name = Column( String(150), nullable = False)
    address = Column( String(150))
    user_id = Column( Integer, ForeignKey('user.id'), nullable = False)
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'name': self.name,
            'address': self.address
        }

class Book(Base):
    """ Book item """
    __tablename__ = 'book'
    id = Column( Integer, primary_key = True )
    title = Column( String(250), nullable = False)
    isbn = Column( String(250))
    datepub = Column( String(250) )
    language = Column( String(250))
    edition = Column( String(250))
    condition = Column( String(250))
    binding = Column( String(250))
    available = Column( Integer )
    summary = Column( String(500))
    imageURL = Column( String(500), default='/static/img/faces.jpg')
    category_id = Column( Integer, ForeignKey('category.id'), nullable = False)
    category = relationship(Category)
    author_id = Column( Integer, ForeignKey('author.id'), nullable = False)
    author = relationship(Author)
    publisher_id = Column( Integer, ForeignKey('publisher.id'), nullable = False)
    publisher = relationship(Publisher)
    user_id = Column( Integer, ForeignKey('user.id'), nullable = False)
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'title': self.title,
            'isbn': self.isbn,
            'datepub': self.datepub,
            'laguage': self.language,
            'edition': self.edition,
            'biding': self.binding,
            'condition': self.condition,
            'imageurl': self.imageURL,
            'author' : self.author.name,
            'publisher': self.publisher.name,
            'category': self.category.name,
            'summary': self.summary
            }

class Review(Base):
    """ Book Reviews """
    __tablename__ = 'review'
    id = Column( Integer, primary_key = True)
    text = Column(String(1000), nullable = False)
    date = Column( String(250))
    book_id = Column( Integer, ForeignKey('book.id'), nullable = False)
    book = relationship(Book)
    user_id = Column( Integer, ForeignKey('user.id'), nullable = False)
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'book': self.book.name,
            'author': self.user.name,
            'date': self.date,
            'review': self.text
            }

engine = create_engine('sqlite:///artbookdb')
Base.metadata.create_all(engine)
