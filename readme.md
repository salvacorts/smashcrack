[![logo.png](https://s17.postimg.org/5b2g8mg73/logo.png)](https://postimg.org/image/dgki6s4fv/)

**SmashCrack** is a web framework to encrypt text, identify encryption algorithms and attemp to crack encrypted text.

It is based on Python and CGI, and it uses differents [open source projects](#openSource) to achieve it goals.

I started this project on highschool so although I'm not very prout of this code, it works really good.

###### **TODOs**

- Port this project to Django
- Upload the project to a reliable server 
- Review source code and rewrite it in a more professional way using Google's python style guide

### Get encrypted hashes from plain text

[![create.gif](https://s14.postimg.org/pdeanv6kx/create.gif)](https://postimg.org/image/w3urxatql/)

### Identify differents encryption algorithms

[![id.gif](https://s14.postimg.org/9gfir5e6p/image.gif)](https://postimg.org/image/57asozax9/)

### Crack encrypted passwords

[![crack.png](https://s12.postimg.org/czdfc8jsd/crack.png)](https://postimg.org/image/kfcoy17hl/)

------

##### Dependencies:

```sh
sudo pip install hashlib
sudo apt install python-mysqldb # Ubuntu, Debian based systems
sudo yum install MySQL-python	# Red Hat based systems
sudo pacman -S mysql-python		# Arch Linux based systems
```

This proyect was tested on Ubuntu over Lighttpd with the following configuration file:

```json
server.document-root        = "/var/www/web/public_html/"
server.upload-dirs          = ( "/var/cache/lighttpd/uploads" )
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/var/run/lighttpd.pid"
server.username             = "www-data"
server.groupname            = "www-data"
server.port                 = 80

index-file.names            = ( "index.html" )
server.error-handler-404    = "/404.html" 

compress.filetype           = ( "application/javascript", "text/css", "text/html", "text/plain" )

##
## mimetype mapping
##
mimetype.assign = (
  ".png"  => "image/png",
  ".jpg"  => "image/jpeg",
  ".jpeg" => "image/jpeg",
  ".html" => "text/html",
  ".txt"  => "text/plain",
  ".py" => "text/x-python",
  ".pyc" => "application/x-python-code",
  ".pyo" => "application/x-python-code",
)

server.modules += ( "mod_cgi" )
$HTTP["url"] =~ "^/scripts/" {
        cgi.assign = ( ".py" => "/usr/bin/python2" )
}
```

------

#####Third party source: <a id="openSource"></a>

[HashID](https://github.com/psypanda/hashID)

[Findmyhash](https://code.google.com/archive/p/findmyhash/)

-----
#####Author:

- ***Salva Corts***
- [***@salvacorts***](https://twitter.com/SalvaCorts)
- ***salvacortsit@gmail.com***
