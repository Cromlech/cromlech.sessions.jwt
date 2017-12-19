cromlech.sessions.jwt
#####################

This packaged provides HTTP server side sessions using JWT and Cookies.

JWT is  way of encrypting a json file, so that it can be used for secure communications. 

cromlech.sessions.jwt uses that encrypted information to keep a person logged in, even though HTTP is a stateless protocol. 

In the old days, we used a session cookie to identify a person, and kept the critical information in the local database.  But this did not scale well.  What if the next request hit a different server?   What if you have a zope server and a chat server,  the login information would have to be transferred over. What if you have a micro services architecture?  So by encrypting the login credentials, and storing them in a cookie, along with time to live information everything works much better.

You can read the detailed documentation [here](./src/cromlech/sessions/jwt/test_session.txt).   

In general Cromlech has great detailed documentation, but it is all hidden in the 
doc tests.  So always look for it there. 



