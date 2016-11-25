#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#from passlib.hash import nthash
from xml.dom.minidom import parse
import hashlib,binascii
import cgi, cgitb
import MySQLdb
import random
import xml.dom.minidom
template = """
    <!--

      _________                     .__    _________                       __
     /   _____/ _____ _____    _____|  |__ \_   ___ \____________    ____ |  | __
     \_____  \ /     \\__  \  /  ___/  |  \/    \  \/\_  __ \__  \ _/ ___\|  |/ /
     /        \  Y Y  \/ __ \_\___ \|   Y  \     \____|  | \// __ \\  \___|    <
    /_______  /__|_|  (____  /____  >___|  /\______  /|__|  (____  /\___  >__|_ \
            \/      \/     \/     \/     \/        \/            \/     \/     \/


    Coded with <3 by @SalvaCorts
    -->
    <html>
        <head>
        <link rel="shortcut icon" href="/images/lock.png" />
        <link rel="stylesheet" type="text/css" href="/stylesheet.css">
        <link href='http://fonts.googleapis.com/css?family=Nova+Flat' rel='stylesheet' type='text/css'>
        <link href='http://fonts.googleapis.com/css?family=Raleway' rel='stylesheet' type='text/css'>
        <script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.6.2/jquery.min.js"></script>
        </head>
        <body>
            <title>Smash Crack</title>
            <div id="header" class="container">
            <div id="column-footer">
                <a href="/index.html" style="padding: 0px;">
                    <img src="/images/loguito.png"></img>
                </a>
            </div>
            <div id="column-footer">
                <nav style="visibility: visible; animation-name: fadeIn;" class="hidden-xs col-sm-10 text-right wow fadeIn" id="menu">
                    <ul>
                        <li>
                            <a href="#about"><b>About</b></a>
                        </li>
                        <li>
                            <a href="#blog-container"><b>Blog</b></a>
                        </li>
                        <li>
                            <a href="#contact"><b>Contact</b></a>
                        </li>
                        <li>
                            <a href="/disclaimer.txt"><b>Disclaimer</b></a>
                        </li>
                        <li>
                            <a href="/hackers.txt"><b>Hackers</b></a>
                        </li>
                    </ul>
                </nav>
            </div>
        </div>
            <div id="search" class="container">
                <p></p>
                <div id="input" class="container">
                    <form method="get" action="/scripts/search.py">
                        <input class="field" type="text" name="hash" placeholder=" Crack Your Hash">
                        <select class="selecter" name="encryption">
                            <option value="md5" selected>MD5</option>
                            <option value="md4">MD4</option>
                            <option value="sha1">SHA1</option>
                            <option value="sha224">SHA224</option>
                            <option value="sha256">sha256</option>
                            <option value="sha384">sha384</option>
                            <option value="sha512">sha512</option>
                            <option value="ntlm">NTLM</option>
                        <input id="btn" class="button" type="submit" value="Crack!" onclick="$('#loading').show();$('#preset-done img').hide()">
                    </form>
                </div>
                <p></p>
                <div id="input" class="container">
                    <form method="get" action="/scripts/hashid.py">
                        <input class="field-special" type="text" name="hash" placeholder=" Identify Your Hash">
                        <input id="btn" class="button" type="submit" value="Identify!" onclick="$('#loading').show();$('#preset-done img').hide()">
                    </form>
                </div>
                <p></p>
                <div id="input" class="container">
                    <form method="get" action="/scripts/hashcreator.py">
                        <input class="field" type="text" name="word" placeholder=" Create Your Hash">
                        <select class="selecter" name="encryption">
                            <option value="md5" selected>MD5</option>
                            <option value="md4">MD4</option>
                            <option value="sha1">SHA1</option>
                            <option value="sha224">SHA224</option>
                            <option value="sha256">sha256</option>
                            <option value="sha384">sha384</option>
                            <option value="sha512">sha512</option>
                            <option value="ntlm">NTLM</option>
                        <input id="btn" class="button" type="submit" value="Create!" onclick="$('#loading').show();$('#preset-done img').hide()">
                    </form>
                </div>
                <div id="loading" style="display:none;">
                    <img src="/images/loading2.gif" alt=""></img>
                    <p>Working! It can take a while...<p>
                </div>
                <!--<div id="arrow"><img src="/images/arrow.png"></img></div>-->
                <div id="preset-done" class="container">
                    %s
                </div>
            </div>
        <div id="contactForm">
        <div id="contact">
            <div class="content">
                            <div id="wrap">
                                <div class="box1">
                                    <h2>Contact us</h2>
                                  <form class="form" action="mailto:smashcrack@gmail.com" method="post">
                                    <p class="name">
                                      <input type="text" name="name" id="name" placeholder="Name"/>
                                    </p>
                                    <p class="email">
                                      <input type="text" name="email" id="email" placeholder="E-mail"/>
                                    </p>
                                    <p class="web">
                                      <input type="text" name="web" id="web" placeholder="Website"/>
                                    </p>
                                    <p class="text">
                                      <textarea name="text" placeholder="Your message here"></textarea>
                                    </p>
                                    <p class="submit">
                                      <input type="submit" value="send" />
                                    </p>
                                  </form>
                                </div>
                            </div>
                        </div>
        </div>
        </div>
        <div id="footer">
            <div id="column-footer" class="container">
                <div id="info">
                    <a href="/humans.txt">About us</a>
                    <a href="/disclaimer.txt">Disclaimer</a>
                    <a href="/hackers.txt">Hackers</a>
                </div>
            </div>
            <div id="column-footer" class="container">
                    <div id="share-buttons">
                        <a href="http://www.facebook.com/sharer.php?u=http://www.smashcrack.ml" target="_blank"><img src="/images/facebook.png" alt="Facebook" /></a>
                        <a href="http://twitter.com/share?url==http://www.smashcrack.ml&text=SmashCrack&hashtags=OnlinePasswordCracker" target="_blank"><img src="/images/twitter.png" alt="Twitter" /></a>
                        <a href="https://plus.google.com/share?url==http://www.smashcrack.ml" target="_blank"><img src="/images/google.png" alt="Google" /></a>
                    </div>
            </div>
        </div>
        <a href="#" class="scrollToTop"><img src="/images/go-top.png"></img></a>
        <script src="http://ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js">Top</script>
        <script src="/js/go-top.js"></script>
    </body>
</html>
    """
payForm = "<h3> PAY </h3>"
donateForm = "<h3> DONATE </h3>"
form = cgi.FieldStorage()
word = form.getfirst("word", "")
word = cgi.escape(word)
word = str(word)
#word = "ruben" # JUST 4 DEBUG
## Ofuscate SQLi ##
word = word.replace("+", "")
word = word.replace("'", "")
word = word.replace('"', "")
word = word.replace('(', "")
word = word.replace(')', "")
word = word.replace('*', "")
word = word.replace('=', "")
## Ofuscate SQLi ##
encryption = form.getfirst("encryption", "")
encryption = cgi.escape(encryption)
encryption = str(encryption)
#encryption = "md5" # JUST 4 DEBUG
## Ofuscate SQLi ##
encryption = encryption.replace("+", "")
encryption = encryption.replace("'", "")
encryption = encryption.replace('"', "")
encryption = encryption.replace('(', "")
encryption = encryption.replace(')', "")
encryption = encryption.replace('*', "")
encryption = encryption.replace('-', "")
encryption = encryption.replace('_', "")
encryption = encryption.replace('=', "")
## Ofuscate SQLi ##


def md5():
    md5 = hashlib.md5(str(word).replace('\n', '')).hexdigest()                                # MD5 Hash
    hash = str(md5)
    return hash
def md4():
    md4 = hashlib.new("md4", str(word.replace('\n', '')).encode("utf-8")).hexdigest()         # MD4 Hash
    hash = md4
    return hash
def sha1():
    sha1 = hashlib.sha1(str(word).replace('\n', '')).hexdigest()                              # SHA1 Hash
    hash = sha1
    return hash
def sha224():
    sha224 = hashlib.sha224(str(word).replace('\n', '')).hexdigest()                          # SHA224 Hash
    hash = sha224
    return hash
def sha256():
    sha256 = hashlib.sha256(str(word).replace('\n', '')).hexdigest()                          # SHA256 Hash
    hash = sha256
    return hash
def sha384():
    sha384 = hashlib.sha384(str(word).replace('\n', '')).hexdigest()                          # SHA384 Hash
    hash = sha384
    return hash

def sha512():
    sha512 = hashlib.sha512(str(word).replace('\n', '')).hexdigest()                          # SHA512 Hash
    hash = sha512
    return hash
def ntlm():
    ntlm = hashlib.new('md4', str(word).replace('\n', '').encode('utf-16le')).digest()        # NTLM Hash
    ntlm = binascii.hexlify(ntlm)                                                             # NTLM Hash
    hash = ntlm
    return hash
"""def lm():
    lm =  nthash.encrypt(str(word).replace('\n', ''))                                         # LM Hash
    hash = lm
    return hash"""

crypt = {
    "md5": md5,
    "md4": md4,
    "sha1": sha1,
    "sha224": sha224,
    "sha256": sha256,
    "sha384": sha384,
    "sha512": sha512,
    "ntlm": ntlm,
    #"lm": lm,
}


#sql = "INSERT INTO SMASH VALUES ('"+word+"','"+crypt["md5"]()+"','"+crypt["md4"]()+"','"+crypt["sha1"]()+"','"+crypt["sha224"]()+"','"+crypt["sha256"]()+"','"+crypt["sha384"]()+"','"+crypt["sha512"]()+"','"+crypt["ntlm"]()+"');"
#sql = str("""insert INTO """+ encryption + """ VALUES ('"""+word+"""','"""+crypt[encryption]()+"""');""")
if (word == ""):
    print("Content-Type: text/html")
    print
    print(template % ("""
    <div id="pass-noValue">
        <div id="noValue">
                <h2> No Word Secified</h2>
        </div>
    </div>
    <div id="arrow-index">
                <a href="#contact">
                    <img src="/images/arrow.png"></img>
                </a>
            </div>
    """))

else:

    try:
        DOMTree = xml.dom.minidom.parse("../../private_html/free.xml")
        data = DOMTree.documentElement
        dbs = data.getElementsByTagName("database")
        db = random.choice(dbs) # choose a random pro db, maybe, it could be better to remove it
        ip = db.getElementsByTagName("ip")[0].childNodes[0].data
        name = db.getElementsByTagName("name")[0].childNodes[0].data
        user = db.getElementsByTagName("user")[0].childNodes[0].data
        password = db.getElementsByTagName("pass")[0].childNodes[0].data
        Database = MySQLdb.connect(ip,user,password,name)
        cursor = Database.cursor()
        cursor.execute(sql)
        Database.commit()
        Database.close() # These lines log hashed words to DBS

        print("Content-Type: text/html")
        print
        print(template % ("""
        <div id="pass-Matched">
            <div id="Matched">
                    <h2>"""+encryption.upper()+""" Hash for """+word+""" is:</h2>
                    <h3 style="color: #40d47e;">"""+crypt[encryption]()+"""</h3>
            </div>
        </div>
        <div id="arrow-index">
                <a href="#contact">
                    <img src="/images/arrow.png"></img>
                </a>
            </div>
        """))

    except:

        print("Content-Type: text/html")
        print
        print(template % ("""
        <div id="pass-Matched">
            <div id="Matched">
                    <h2>"""+encryption.upper()+""" Hash for """+word+""" is:</h2>
                    <h3 style="color: #40d47e;">"""+crypt[encryption]()+"""</h3>
            </div>
        </div>
        <div id="arrow-index">
                <a href="#contact">
                    <img src="/images/arrow.png"></img>
                </a>
            </div>
        """))
