import os

def installPKG():
	packages = ["python", "lighttpd", "python-mysqldb"]

	for package in packages:
		os.system("apt-get install -y "+package)

	# install pip and httplib2
	os.system("easy_install pip")
	os.system("pip install httplib2")

def confLIGHTTPD():

	f = "/etc/lighttpd/lighttpd.conf"
	backup = "/etc/lighttpd/lighttpd.conf.bak"

	conf = """
server.port		= 8080
server.username		= "www-data"
server.groupname	= "www-data"
server.document-root	= "/var/www/smashcrack/web/public_html"
server.errorlog		= "/var/www/smashcrack/web/private_html/error.log"
dir-listing.activate	= "disable"

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

	"""
	
	# backup original lighttpd.conf
	os.system("mv "+f+" "+backup)

	# Write new conf
	f.write(conf)


