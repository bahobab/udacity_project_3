A/ Installation of Project 3: Catalog
=====================================

To run this project you need to install the vagrant virtual machine (VM) for project 3: Catalog

Run the following commands:

1/To bring the VM run:

vagrant up

2/Once the VM is on run:

vagrant ssh

this will connect you to the linux environment.
(The best way is to follow the installation procudure given in the Project description)

3/Then run:

cd /vagrant

4/Copy the contents of catalog project to the local catalog folder 

5/ Additional Modules required to run the project:
-------------------
- for CSRF
$sudo pip install flask-seasurf

- for HTML sanitization
$sudo pip install bleach

- for datetime run
$sudo pip install datetime

6/Finally, to run the application:

$python application.py

Note: Debuging has been turned off.
To enable uncomment the line:
app.debug = True 

7/To use the application visit:

http://localhost:5000

B/ Objective of the website for Project 3: Catalog
==================================================
To showcase and share experience about art books.
The books are listed by their categories, authors, and publishers

1/ Third Party Authorization
Facebook and Google oAuth login services are implemented

2/ API EndPoints:
There JSON pages to generate JSON-format data for each category,
- http://localhost:5000/categories/JSON
- http://localhost:5000/authors/JSON
- http://localhost:5000/publishers/JSON

items by category
- http://localhost:5000/categories/<int:category_id/books/JSON
- http://localhost:5000/authors/<int:author_id/books/JSON
- http://localhost:5000/publishers/<int:publisher_id/books/JSON

and all the items
- http://localhost:5000/books/JSON

The implementation of the objectives of project 3: Catalog are described bellow:

Access to the website by visiting:
- http://localhost:5000)

3/ CRUD operations

There are two(2) types of user accessibility for the website:
- logged-on user
- non-logged-on user

Uppon opening the site the user is presented with two(2) login possibilities:
- Google, or
- Facebook

The login button is located on the top right side of the site

C/ A successful login provides the user with the capabilities of CRUD operations
================================================================================
- Create/Edit/Delete categories:
. book category
. book author
. book publisher

- Create/Edit/Delete book Items from the categories:
. book items by category
. book items by author category
. book items by publisher category

. Create/Delete review Items from book Items

For a each category entry and each item there is a drop-down menu for Books, Edit, Delete the entry.
The Book menu entry shows the list of the books in that category and a book item has a menu entry to see the details and reviews for the book, Edit or Delete the book.

A book item can be created from each of the three(3) categories (category, author, publisher)
Even if there are no categories already created they can be created when creating a book item

Deleting categories:
--------------------
A category can only be deleted by a logged on user who created it AND ONLY if there's no books depending on it.
A book item and a review item can only be created while logged on and by the creator of the item: the user who created it

One deviation from the class example is that a logged on user can browse the books created by any other user. In addition, a category created by one user can be used by any other user. This avoids duplicates. After all, the purpose of the site is to share book experience.
Thus as a book category may contain many different books, so can an authorwrite many books and a publisher publish many books.

Deleting an item:
-----------------
Only a logged on user can delete a book or a review he/she created.
When a book is deleted all the related reviews are deleted with it without regard to who created the review.

C/ Not logged on user
=====================
The user who has not loggon into the site has a limited capability to browse the list of categories (book categories, authors, publishers), and the book items in each category.
This user can also read the reviews on each book item with NO modification capability.

Extra Credits:
==============
1/ XML, RSS or ATOM Feed:
I did a lot of research to implement these options but I was not successful.
My ATOM implementation is not...working as it should.

2/ CSRF is implemented using the seasurf Python extention for all forms sending a post method to the controller.
Each of these forms has a hidden field:
<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">

3/ Inclusion of images on the pages for the items
For the books I opted for images that will be stored locally on the server's file system.
Typically, the book cover images are stored in the /static/img/bookcover directory

For the authors I used the same technique as in project 1 (Movie Trailer) where the images are accessed on the web via their URL stored in the database.
This means that the authors' pictures will be seen only if online

Personal Extras:
======
1/ Responsive website with mobile first philosopy using Bootstrap and Modernizr css files

2/ Form auto-complete (new book and edit book forms)
I tried the auto-complete techniques from Bootstrap without success.
So I passed arraray parameters to the newbook.html and editbook.html views and used them as data-source attribute for the input fields.
Then I called them in a JQuery code. Hoever, they end up there as strings instead of arrays.
So I chopped them into array to feed the auto-complete code in JavaScript

<script >
    var attrString = $('#author').attr('data-source');
    try{
    attrString = attrString.replace(/\[/g, "");
    attrString = attrString.replace(/\]/g, "");
    attrString = attrString.replace(/\'/g, "");
    var arrayAuthors = attrString.split(",");
    }
    catch(e){}

//console.log(arrayAuthors);
    $('#author').typeahead({
       source: arrayAuthors
    });
</script>

PS:
It took me longer to complete the project because of the design i chose for the implementation. I wanted the user to be able to come back to where she/he was after completing a task. So from categories, authors and publishers the user can access create, edit and delete books and come back to where they left off.

I also added a feature allowing the users to delete all their book items.
However, implementing this feature for the categories, authors and publishers would have taken me longer since i'd have to check wether there are still books depending on them.

The application may contain some flaws, especially regarding the front-end design but I feel great about it and I learned a great deal through the implementation of the project (I was ready to submit when I found out that the book cover images names loaded from IE includes the Windows full path name, whereas Firefox just includes the file name... So I have to modify the code!!! Hopefully it'll work with Chrome).

I hope you'll have fun running it.

Thanks for your time and thanks to the Udacity team.

Konan