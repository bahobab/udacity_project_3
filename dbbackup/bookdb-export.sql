BEGIN TRANSACTION;
CREATE TABLE review (
	id INTEGER NOT NULL, 
	text VARCHAR(1000) NOT NULL, 
	date VARCHAR(250), 
	book_id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(book_id) REFERENCES book (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
);
INSERT INTO `review` VALUES (2,'Kool','2015-08-26 03:56:40',2,2);
INSERT INTO `review` VALUES (3,'I highly recommend you experiment with his methods of painting and drawing','2015-08-26 16:54:00',11,1);
INSERT INTO `review` VALUES (4,'John has a straightforward approach to painting the portrait','2015-08-26 18:21:32',4,2);
INSERT INTO `review` VALUES (5,'This is really for creative people','2015-08-26 18:24:55',8,1);
COMMIT;
