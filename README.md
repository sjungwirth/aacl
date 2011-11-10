# AACL

AACL is (yet) Another ACL library for Kohana 3.
Ported to Jelly ORM 3.1.

Based on [banks AACL](http://github.com/banks/aacl#readme)
and [ckald Jelly port](https://github.com/ckald/aacl-jelly#readme)

### Auth integration: Users and Roles

AACL uses [kohana auth](http://github.com/kohanan/auth) and, optionally, [jelly-auth](http://github.com/raeldc/jelly-auth).

1.	Users and roles have a many-to-many mapping
2.	Roles are non-hierarchical and no role is given special treatment
3.	The only exception to 2. is the 'login' role which all active users must have.
	In reality you may choose to special case this in a UI and represent it as an 'active account' checkbox rather
	than requiring end-users to understand that it is different from other roles.

### ORMs

"AACL ships with a Sprig based Rule model and Sprig based class for easily turning Sprig models into Access Controlled Resources."

ckald modified AACL classes to deal with Jelly ORM.

emmtou adapted this port to work with [creatoro jelly port to kohana 3.1](https://github.com/creatoro/jelly)
and released :

-  version 0.1 : last static version
-  version 0.2 : first non-static version