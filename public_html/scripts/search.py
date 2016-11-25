#!/usr/bin/python2
# -*- coding: utf-8 -*-
import cgi, cgitb
import MySQLdb
import xml.dom.minidom
import hashlib,binascii
import urllib2
import getopt
import random
#from passlib.hash import lmhash
from xml.dom.minidom import parse
from os import path
from urllib import urlencode
from re import search, findall
from random import seed, randint
from base64 import decodestring, encodestring
from cookielib import LWPCookieJar
from httplib2 import Http

##### Add pass to DB from Find Me #####
def addDB ( value ):
    word = value
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
        lm =  lmhash.encrypt(str(word).replace('\n', ''))                                         # LM Hash
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
    sql = "INSERT INTO SMASH VALUES ('"+word+"','"+crypt["md5"]()+"','"+crypt["md4"]()+"','"+crypt["sha1"]()+"','"+crypt["sha224"]()+"','"+crypt["sha256"]()+"','"+crypt["sha384"]()+"','"+crypt["sha512"]()+"','"+crypt["ntlm"]()+"');"
    try:
        DOMTree = xml.dom.minidom.parse("../../private_html/pro.xml")
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
        Database.close()
    except:
        pass

    return

##### Find Me #####

########################################################################################################
### CONSTANTS
########################################################################################################

MD4 = "md4"
MD5     = "md5"
SHA1    = "sha1"
SHA224  = "sha224"
SHA256  = "sha256"
SHA384  = "sha384"
SHA512  = "sha512"
RIPEMD  = "rmd160"
LM  = "lm"
NTLM    = "ntlm"
MYSQL   = "mysql"
CISCO7  = "cisco7"
JUNIPER = "juniper"
GOST    = "gost"
WHIRLPOOL = "whirlpool"
LDAP_MD5 = "ldap_md5"
LDAP_SHA1 = "ldap_sha1"


USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Crazy Browser 1.0.5)",
    "curl/7.7.2 (powerpc-apple-darwin6.0) libcurl 7.7.2 (OpenSSL 0.9.6b)",
    "Mozilla/5.0 (X11; U; Linux amd64; en-US; rv:5.0) Gecko/20110619 Firefox/5.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101213 Firefox/4.0b8pre",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)",
    "Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
    "Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
    "Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.861.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.872.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ]



########################################################################################################
### CRACKERS DEFINITION
########################################################################################################


class SCHWETT:

    name =      "schwett"
    url =       "http://schwett.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://schwett.com/md5/index.php?md5value=%s&md5c=Hash+Match" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r"<h3><font color='red'>No Match Found</font></h3><br />", html)
        if match:
            return None
        else:
            return "The hash is broken, please contact with La X marca el lugar and send it the hash value to add the correct regexp."



class NETMD5CRACK:

    name =      "netmd5crack"
    url =       "http://www.netmd5crack.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://www.netmd5crack.com/cgi-bin/Crack.py?InputHash=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        regexp = r'<tr><td class="border">%s</td><td class="border">[^<]*</td></tr></table>' % (hashvalue)
        match = search (regexp, html)

        if match:
            match2 = search ( "Sorry, we don't have that hash in our database", match.group() )
            if match2:
                return None
            else:
                return match.group().split('border')[2].split('<')[0][2:]


class BENRAMSEY:

    name =      "benramsey"
    url =       "http://tools.benramsey.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://tools.benramsey.com/md5/md5.php?hash=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<string><!\[CDATA\[[^\]]*\]\]></string>', html)

        if match:
            return match.group().split(']')[0][17:]
        else:
            return None



class GROMWEB:

    name =      "gromweb"
    url =       "http://md5.gromweb.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.gromweb.com/query/%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        if response:
            return response.read()

        return response




class HASHCRACKING:

    name =      "hashcracking"
    url =       "http://md5.hashcracking.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.hashcracking.com/search.php?md5=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'\sis.*', html)

        if match:
            return match.group()[4:]

        return None



class VICTOROV:

    name =      "hashcracking"
    url =       "http://victorov.su"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://victorov.su/md5/?md5e=&md5d=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r': <b>[^<]*</b><br><form action="">', html)

        if match:
            return match.group().split('b>')[1][:-2]

        return None


class THEKAINE:

    name =      "thekaine"
    url =       "http://md5.thekaine.de"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.thekaine.de/?hash=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<td colspan="2"><br><br><b>[^<]*</b></td><td></td>', html)

        if match:

            match2 = search (r'not found', match.group() )

            if match2:
                return None
            else:
                return match.group().split('b>')[1][:-2]



class TMTO:

    name =      "tmto"
    url =       "http://www.tmto.org"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://www.tmto.org/api/latest/?hash=%s&auth=true" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'text="[^"]+"', html)

        if match:
            return decodestring(match.group().split('"')[1])
        else:
            return None


class MD5_DB:

    name =      "md5-db"
    url =       "http://md5-db.de"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5-db.de/%s.html" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        if not response:
            return None

        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<strong>Es wurden 1 m.gliche Begriffe gefunden, die den Hash \w* verwenden:</strong><ul><li>[^<]*</li>', html)

        if match:
            return match.group().split('li>')[1][:-2]
        else:
            return None




class MY_ADDR:

    name =      "my-addr"
    url =       "http://md5.my-addr.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php"

        # Build the parameters
        params = { "md5" : hashvalue,
               "x" : 21,
               "y" : 8 }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", html)

        if match:
            return match.group().split('span')[2][3:-6]
        else:
            return None




class MD5PASS:

    name =      "md5pass"
    url =       "http://md5pass.info"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = self.url

        # Build the parameters
        params = { "hash" : hashvalue,
               "get_pass" : "Get Pass" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r"Password - <b>[^<]*</b>", html)

        if match:
            return match.group().split('b>')[1][:-2]
        else:
            return None



class MD5DECRYPTION:

    name =      "md5decryption"
    url =       "http://md5decryption.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = self.url

        # Build the parameters
        params = { "hash" : hashvalue,
               "submit" : "Decrypt It!" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r"Decrypted Text: </b>[^<]*</font>", html)

        if match:
            return match.group().split('b>')[1][:-7]
        else:
            return None



class MD5CRACK:

    name =      "md5crack"
    url =       "http://md5crack.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5crack.com/crackmd5.php"

        # Build the parameters
        params = { "term" : hashvalue,
               "crackbtn" : "Crack that hash baby!" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'Found: md5\("[^"]+"\)', html)

        if match:
            return match.group().split('"')[1]
        else:
            return None


class MD5ONLINE:

    name =      "md5online"
    url =       "http://md5online.net"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = self.url

        # Build the parameters
        params = { "pass" : hashvalue,
               "option" : "hash2text",
               "send" : "Submit" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<center><p>md5 :<b>\w*</b> <br>pass : <b>[^<]*</b></p></table>', html)

        if match:
            return match.group().split('b>')[3][:-2]
        else:
            return None




class MD5_DECRYPTER:

    name =      "md5-decrypter"
    url =       "http://md5-decrypter.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = self.url

        # Build the parameters
        params = { "data[Row][cripted]" : hashvalue }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = findall (r'<b class="res">[^<]*</b>', html)

        if match:
            return match[1].split('>')[1][:-3]
        else:
            return None



class AUTHSECUMD5:

    name =      "authsecu"
    url =       "http://www.authsecu.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://www.authsecu.com/decrypter-dechiffrer-cracker-hash-md5/script-hash-md5.php"

        # Build the parameters
        params = { "valeur_bouton" : "dechiffrage",
               "champ1" : "",
               "champ2" : hashvalue,
               "dechiffrer.x" : "78",
               "dechiffrer.y" : "7" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = findall (r'<td><p class="chapitre---texte-du-tableau-de-niveau-1">[^<]*</p></td>', html)

        if len(match) > 2:
            return match[1].split('>')[2][:-3]
        else:
            return None



class HASHCRACK:

    name =      "hashcrack"
    url =       "http://hashcrack.com"
    supported_algorithm = [MD5, SHA1, MYSQL, LM, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://hashcrack.com/indx.php"

        hash2 = None
        if alg in [LM, NTLM] and ':' in hashvalue:
            if alg == LM:
                hash2 = hashvalue.split(':')[0]
            else:
                hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # Delete the possible starting '*'
        if alg == MYSQL and hash2[0] == '*':
            hash2 = hash2[1:]

        # Build the parameters
        params = { "auth" : "8272hgt",
               "hash" : hash2,
               "string" : "",
               "Submit" : "Submit" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<div align=center>"[^"]*" resolves to</div><br><div align=center> <span class=hervorheb2>[^<]*</span></div></TD>', html)

        if match:
            return match.group().split('hervorheb2>')[1][:-18]
        else:
            return None



class OPHCRACK:

    name =      "ophcrack"
    url =       "http://www.objectif-securite.ch"
    supported_algorithm = [LM, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Check if hashvalue has the character ':'
        if ':' not in hashvalue:
            return None

        # Ophcrack doesn't crack NTLM hashes. It needs a valid LM hash and this one is an empty hash.
        if hashvalue.split(':')[0] == "aad3b435b51404eeaad3b435b51404ee":
            return None

        # Build the URL and the headers
        url = "http://www.objectif-securite.ch/en/products.php?hash=%s" % (hashvalue.replace(':', '%3A'))

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<table><tr><td>Hash:</td><td>[^<]*</td></tr><tr><td><b>Password:</b></td><td><b>[^<]*</b></td>', html)

        if match:
            return match.group().split('b>')[3][:-2]
        else:
            return None



class C0LLISION:

    name =      "c0llision"
    url =       "http://www.c0llision.net"
    supported_algorithm = [MD5, LM, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Check if hashvalue has the character ':'
        if alg in [LM, NTLM] and ':' not in hashvalue:
            return None

        # Look for "hash[_csrf_token]" parameter
        response = do_HTTP_request ( "http://www.c0llision.net/webcrack.php" )
        html = None
        if response:
            html = response.read()
        else:
            return None
        match = search (r'<input type="hidden" name="hash._csrf_token." value="[^"]*" id="hash__csrf_token" />', html)
        token = None
        if match:
            token = match.group().split('"')[5]

        # Build the URL
        url = "http://www.c0llision.net/webcrack/request"

        # Build the parameters
        params = { "hash[_input_]" : hashvalue,
               "hash[_csrf_token]" : token }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = None
        if alg in [LM, NTLM]:
            html = html.replace('\n', '')
            result = ""

            match = search (r'<table class="pre">.*?</table>', html)
            if match:
                try:
                    doc = parseDoc ( match.group() )
                except:
                    print "INFO: You need libxml2 to use this plugin."
                    return None
                lines = doc.xpathEval("//tr")
                for l in lines:
                    doc = parseDoc ( str(l) )
                    cols = doc.xpathEval("//td")

                    if len(cols) < 4:
                        return None

                    if cols[2].content:
                        result = " > %s (%s) = %s\n" % ( cols[1].content, cols[2].content, cols[3].content )

                #return ( result and "\n" + result or None )
                return ( result and result.split()[-1] or None )

        else:
            match = search (r'<td class="plaintext">[^<]*</td>', html)

            if match:
                return match.group().split('>')[1][:-4]

        return None



class REDNOIZE:

    name =      "rednoize"
    url =       "http://md5.rednoize.com"
    supported_algorithm = [MD5, SHA1]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = ""
        if alg == MD5:
            url = "http://md5.rednoize.com/?p&s=md5&q=%s&_=" % (hashvalue)
        else:
            url = "http://md5.rednoize.com/?p&s=sha1&q=%s&_=" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        return html




class CMD5:

    name =      "cmd5"
    url =       "http://www.cmd5.org"
    supported_algorithm = [MD5, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Look for hidden parameters
        response = do_HTTP_request ( "http://www.cmd5.org/" )
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="[^"]*" />', html)
        viewstate = None
        if match:
            viewstate = match.group().split('"')[7]

        match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField1" id="ctl00_ContentPlaceHolder1_HiddenField1" value="[^"]*" />', html)
        ContentPlaceHolder1 = ""
        if match:
            ContentPlaceHolder1 = match.group().split('"')[7]

        match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField2" id="ctl00_ContentPlaceHolder1_HiddenField2" value="[^"]*" />', html)
        ContentPlaceHolder2 = ""
        if match:
            ContentPlaceHolder2 = match.group().split('"')[7]

        # Build the URL
        url = "http://www.cmd5.org/"

        hash2 = ""
        if alg == MD5:
            hash2 = hashvalue
        else:
            if ':' in hashvalue:
                hash2 = hashvalue.split(':')[1]

        # Build the parameters
        params = { "__EVENTTARGET" : "",
               "__EVENTARGUMENT" : "",
               "__VIEWSTATE" : viewstate,
               "ctl00$ContentPlaceHolder1$TextBoxq" : hash2,
               "ctl00$ContentPlaceHolder1$InputHashType" : alg,
               "ctl00$ContentPlaceHolder1$Button1" : "decrypt",
               "ctl00$ContentPlaceHolder1$HiddenField1" : ContentPlaceHolder1,
               "ctl00$ContentPlaceHolder1$HiddenField2" : ContentPlaceHolder2 }

        header = { "Referer" : "http://www.cmd5.org/" }

        # Make the request
        response = do_HTTP_request ( url, params, header )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<span id="ctl00_ContentPlaceHolder1_LabelResult">[^<]*</span>', html)

        if match:
            return match.group().split('>')[1][:-6]
        else:
            return None



class AUTHSECUCISCO7:

    name =      "authsecu"
    url =       "http://www.authsecu.com"
    supported_algorithm = [CISCO7]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL and the headers
        url = "http://www.authsecu.com/decrypter-dechiffrer-cracker-password-cisco-7/script-password-cisco-7-launcher.php"

        # Build the parameters
        params = { "valeur_bouton" : "dechiffrage",
               "champ1" : hashvalue,
               "dechiffrer.x" : 43,
               "dechiffrer.y" : 16 }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = findall (r'<td><p class="chapitre---texte-du-tableau-de-niveau-1">[^<]*</p></td>', html)

        if match:
            return match[1].split('>')[2][:-3]
        else:
            return None




class CACIN:

    name =      "cacin"
    url =       "http://cacin.net"
    supported_algorithm = [CISCO7]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL and the headers
        url = "http://cacin.net/cgi-bin/decrypt-cisco.pl?cisco_hash=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<tr>Cisco password 7: [^<]*</tr><br><tr><th><br>Decrypted password: .*', html)

        if match:
            return match.group().split(':')[2][1:]
        else:
            return None


class IBEAST:

    name =      "ibeast"
    url =       "http://www.ibeast.com"
    supported_algorithm = [CISCO7]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL and the headers
        url = "http://www.ibeast.com/content/tools/CiscoPassword/decrypt.php?txtPassword=%s&submit1=Enviar+consulta" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<font size="\+2">Your Password is [^<]*<br>', html)

        if match:
            return match.group().split('is ')[1][:-4]
        else:
            return None



class PASSWORD_DECRYPT:

    name =      "password-decrypt"
    url =       "http://password-decrypt.com"
    supported_algorithm = [CISCO7, JUNIPER]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL and the parameters
        url = ""
        params = None
        if alg == CISCO7:
            url = "http://password-decrypt.com/cisco.cgi"
            params = { "submit" : "Submit",
                "cisco_password" : hashvalue,
                "submit" : "Submit" }
        else:
            url = "http://password-decrypt.com/juniper.cgi"
            params = { "submit" : "Submit",
                "juniper_password" : hashvalue,
                "submit" : "Submit" }


        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'Decrypted Password:&nbsp;<B>[^<]*</B> </p>', html)

        if match:
            return match.group().split('B>')[1][:-2]
        else:
            return None


class HASHCHECKER:

    name =      "hashchecker"
    url =       "http://www.hashchecker.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL and the headers
        url = "http://www.hashchecker.com/index.php"

        # Build the parameters
        params = { "search_field" : hashvalue,
               "Submit" : "search" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<td><li>Your md5 hash is :<br><li>[^\s]* is <b>[^<]*</b> used charlist :2</td>', html)

        if match:
            return match.group().split('b>')[1][:-2]
        else:
            return None



class MD5HASHCRACKER:

    name =      "md5hashcracker"
    url =       "http://md5hashcracker.appspot.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5hashcracker.appspot.com/crack"

        # Build the parameters
        params = { "query" : hashvalue,
               "submit" : "Crack" }

        # Make the firt request
        response = do_HTTP_request ( url, params )

        # Build the second URL
        url = "http://md5hashcracker.appspot.com/status"

        # Make the second request
        response = do_HTTP_request ( url )

        # Analyze the response
        if response:
            html = response.read()
        else:
            return None
        match = search (r'<td id="cra[^"]*">not cracked</td>', html)

        if not match:
            match = search (r'<td id="cra[^"]*">cracked</td>', html)
            regexp = r'<td id="pla_' + match.group().split('"')[1][4:] + '">[^<]*</td>'
            match2 = search (regexp, html)
            if match2:
                return match2.group().split('>')[1][:-4]

        else:
            return None



class PASSCRACKING:

    name =      "passcracking"
    url =       "http://passcracking.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://passcracking.com/index.php"

        # Build the parameters
        boundary = "-----------------------------" + str(randint(1000000000000000000000000000,9999999999999999999999999999))
        params = [ '--' + boundary,
               'Content-Disposition: form-data; name="admin"',
               '',
               'false',

               '--' + boundary,
               'Content-Disposition: form-data; name="admin2"',
               '',
               '77.php',

               '--' + boundary,
               'Content-Disposition: form-data; name="datafromuser"',
               '',
               '%s' % (hashvalue) ,

               '--' + boundary + '--', '' ]
        body = '\r\n'.join(params)

        # Build the headers
        headers = { "Content-Type" : "multipart/form-data; boundary=%s" % (boundary),
                    "Content-length" : len(body) }


        # Make the request
        request = urllib2.Request ( url )
        request.add_header ( "Content-Type", "multipart/form-data; boundary=%s" % (boundary) )
        request.add_header ( "Content-length", len(body) )
        request.add_data(body)
        try:
            response = urllib2.urlopen(request)
        except:
            return None

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<td>md5 Database</td><td>[^<]*</td><td bgcolor=.FF0000>[^<]*</td>', html)

        if match:
            return match.group().split('>')[5][:-4]
        else:
            return None


class ASKCHECK:

    name =      "askcheck"
    url =       "http://askcheck.com"
    supported_algorithm = [MD4, MD5, SHA1, SHA256]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://askcheck.com/reverse?reverse=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'Reverse value of [^\s]* hash <a[^<]*</a> is <a[^>]*>[^<]*</a>', html)

        if match:
            return match.group().split('>')[3][:-3]
        else:
            return None



class FOX21:

    name =      "fox21"
    url =       "http://cracker.fox21.at"
    supported_algorithm = [MD5, LM, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        hash2 = None
        if alg in [LM, NTLM] and ':' in hashvalue:
            if alg == LM:
                hash2 = hashvalue.split(':')[0]
            else:
                hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue


        # Build the URL
        url = "http://cracker.fox21.at/api.php?a=check&h=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        xml = None
        if response:
            try:
                doc = parseDoc ( response.read() )
            except:
                print "INFO: You need libxml2 to use this plugin."
                return None
        else:
            return None

        result = doc.xpathEval("//hash/@plaintext")

        if result:
            return result[0].content
        else:
            return None


class NICENAMECREW:

    name =      "nicenamecrew"
    url =       "http://crackfoo.nicenamecrew.com"
    supported_algorithm = [MD5, SHA1, LM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        hash2 = None
        if alg in [LM] and ':' in hashvalue:
            hash2 = hashvalue.split(':')[0]
        else:
            hash2 = hashvalue

        # Build the URL
        url = "http://crackfoo.nicenamecrew.com/?t=%s" % (alg)

        # Build the parameters
        params = { "q" : hash2,
               "sa" : "Crack" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'The decrypted version of [^\s]* is:<br><strong>[^<]*</strong>', html)

        if match:
            return match.group().split('strong>')[1][:-2].strip()
        else:
            return None


class MD5_LOOKUP:

    name =      "md5-lookup"
    url =       "http://md5-lookup.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None


class SHA1_LOOKUP:

    name =      "sha1-lookup"
    url =       "http://sha1-lookup.com"
    supported_algorithm = [SHA1]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://sha1-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None


class SHA256_LOOKUP:

    name =      "sha256-lookup"
    url =       "http://sha-256.sha1-lookup.com"
    supported_algorithm = [SHA256]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://sha-256.sha1-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None



class RIPEMD160_LOOKUP:

    name =      "ripemd-lookup"
    url =       "http://www.ripemd-lookup.com"
    supported_algorithm = [RIPEMD]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://www.ripemd-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None



class MD5_COM_CN:

    name =      "md5.com.cn"
    url =       "http://md5.com.cn"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.com.cn/md5reverse"

        # Build the parameters
        params = { "md" : hashvalue,
               "submit" : "MD5 Crack" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<b style="color:red;">[^<]*</b><br/><span', html)

        if match:
            return match.group().split('>')[1][:-3]
        else:
            return None





class DIGITALSUN:

    name =      "digitalsun.pl"
    url =       "http://md5.digitalsun.pl"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.digitalsun.pl/"

        # Build the parameters
        params = { "hash" : hashvalue }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<b>[^<]*</b> == [^<]*<br>\s*<br>', html)

        if match:
            return match.group().split('b>')[1][:-2]
        else:
            return None



class DRASEN:

    name =      "drasen.net"
    url =       "http://md5.drasen.net"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.drasen.net/search.php?query=%s" % (hashvalue)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'Hash: [^<]*<br />Plain: [^<]*<br />', html)

        if match:
            return match.group().split('<br />')[1][7:]
        else:
            return None




class MYINFOSEC:

    name =      "myinfosec"
    url =       "http://md5.myinfosec.net"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.myinfosec.net/md5.php"

        # Build the parameters
        params = { "md5hash" : hashvalue }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<center></center>[^<]*<font color=green>[^<]*</font><br></center>', html)

        if match:
            return match.group().split('>')[3][:-6]
        else:
            return None



class MD5_NET:

    name =      "md5.net"
    url =       "http://md5.net"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://www.md5.net/cracker.php"

        # Build the parameters
        params = { "hash" : hashvalue }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<input type="text" id="hash" size="32" value="[^"]*"/>', html)

        if match:
            return match.group().split('"')[7]
        else:
            return None




class NOISETTE:

    name =      "noisette.ch"
    url =       "http://md5.noisette.ch"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5.noisette.ch/index.php"

        # Build the parameters
        params = { "hash" : hashvalue }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<p>String to hash : <input name="text" value="[^"]+"/>', html)

        if match:
            return match.group().split('"')[3]
        else:
            return None




class MD5HOOD:

    name =      "md5hood"
    url =       "http://md5hood.com"
    supported_algorithm = [MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://md5hood.com/index.php/cracker/crack"

        # Build the parameters
        params = { "md5" : hashvalue,
               "submit" : "Go" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<div class="result_true">[^<]*</div>', html)

        if match:
            return match.group().split('>')[1][:-5]
        else:
            return None



class STRINGFUNCTION:

    name =      "stringfunction"
    url =       "http://www.stringfunction.com"
    supported_algorithm = [MD5, SHA1]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = ""
        if alg == MD5:
            url = "http://www.stringfunction.com/md5-decrypter.html"
        else:
            url = "http://www.stringfunction.com/sha1-decrypter.html"

        # Build the parameters
        params = { "string" : hashvalue,
               "submit" : "Decrypt",
               "result" : "" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<textarea class="textarea-input-tool-b" rows="10" cols="50" name="result"[^>]*>[^<]+</textarea>', html)

        if match:
            return match.group().split('>')[1][:-10]
        else:
            return None





class XANADREL:

    name =      "99k.org"
    url =       "http://xanadrel.99k.org"
    supported_algorithm = [MD4, MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://xanadrel.99k.org/hashes/index.php?k=search"

        # Build the parameters
        params = { "hash" : hashvalue,
               "search" : "ok" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<p>Hash : [^<]*<br />Type : [^<]*<br />Plain : "[^"]*"<br />', html)

        if match:
            return match.group().split('"')[1]
        else:
            return None


class BOKEHMAN:

    name =      "bokehman"
    url =       "http://bokehman.com"
    supported_algorithm = [MD4, MD5]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False



    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        # Build the URL
        url = "http://bokehman.com/cracker/"

        # Build the parameters from the main page
        response = do_HTTP_request ( url )
        html = None
        if response:
            html = response.read()
        else:
            return None
        match = search (r'<input type="hidden" name="PHPSESSID" id="PHPSESSID" value="[^"]*" />', html)
        phpsessnid = ""
        if match:
            phpsessnid = match.group().split('"')[7]
        else:
            return None
        match = search (r'<input type="hidden" name="key" id="key" value="[^"]*" />', html)
        key = ""
        if match:
            key = match.group().split('"')[7]
        else:
            return None

        params = { "md5" : hashvalue,
               "PHPSESSID" : phpsessnid,
               "key" : key,
               "crack" : "Try to crack it" }

        # Make the request
        response = do_HTTP_request ( url, params )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<tr><td>[^<]*</td><td>[^<]*</td><td>[^s]*seconds</td></tr>', html)

        if match:
            return match.group().split('td>')[1][:-2]
        else:
            return None



class GOOG_LI:

    name =      "goog.li"
    url =       "http://goog.li"
    supported_algorithm = [MD5, MYSQL, SHA1, SHA224, SHA384, SHA256, SHA512, RIPEMD, NTLM, GOST, WHIRLPOOL, LDAP_MD5, LDAP_SHA1]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        hash2 = None
        if alg in [NTLM] and ':' in hashvalue:
            hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # Confirm the initial '*' character
        if alg == MYSQL and hash2[0] != '*':
            hash2 = '*' + hash2

        # Build the URL
        url = "http://goog.li/?q=%s" % (hash2)

        # Make the request
        response = do_HTTP_request ( url )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<br />cleartext[^:]*: [^<]*<br />', html)

        if match:
            return match.group().split(':')[1].strip()[:-6]
        else:
            return None



class WHREPORITORY:

    name =      "Windows Hashes Repository"
    url =       "http://nediam.com.mx"
    supported_algorithm = [LM, NTLM]

    def isSupported (self, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        if alg in self.supported_algorithm:
            return True
        else:
            return False


    def crack (self, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not self.isSupported (alg):
            return None

        hash2 = None
        if ':' in hashvalue:
            if alg == LM:
                hash2 = hashvalue.split(':')[0]
            else:
                hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # Build the URL, parameters and headers
        url = ""
        params = None
        headers = None
        if alg == LM:
            url = "http://nediam.com.mx/winhashes/search_lm_hash.php"
            params = { "lm" : hash2,
                "btn_go" : "Search" }
            headers = { "Referer" : "http://nediam.com.mx/winhashes/search_lm_hash.php" }
        else:
            url = "http://nediam.com.mx/winhashes/search_nt_hash.php"
            params = { "nt" : hash2,
                "btn_go" : "Search" }
            headers = { "Referer" : "http://nediam.com.mx/winhashes/search_nt_hash.php" }

        # Make the request
        response = do_HTTP_request ( url, params, headers )

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search (r'<tr><td align="right">PASSWORD</td><td>[^<]*</td></tr>', html)

        if match:
            return match.group().split(':')[1]
        else:
            return None



CRAKERS = [     SCHWETT,
        NETMD5CRACK,
        BENRAMSEY,
        GROMWEB,
        HASHCRACKING,
        VICTOROV,
        THEKAINE,
        TMTO,
        REDNOIZE,
        MD5_DB,
        MY_ADDR,
        MD5PASS,
        #MD5DECRYPTION,
        MD5CRACK,
        MD5ONLINE,
        MD5_DECRYPTER,
        AUTHSECUMD5,
        HASHCRACK,
        OPHCRACK,
        C0LLISION,
        AUTHSECUCISCO7,
        CACIN,
        IBEAST,
        PASSWORD_DECRYPT,
        HASHCHECKER,
        MD5HASHCRACKER,
        PASSCRACKING,
        ASKCHECK,
        FOX21,
        NICENAMECREW,
        MD5_LOOKUP,
        SHA1_LOOKUP,
        SHA256_LOOKUP,
        RIPEMD160_LOOKUP,
        MD5_COM_CN,
        DIGITALSUN,
        DRASEN,
        MYINFOSEC,
        #MD5_NET,
        NOISETTE,
        MD5HOOD,
        STRINGFUNCTION,
        XANADREL,
        BOKEHMAN,
        GOOG_LI,
        WHREPORITORY ]



########################################################################################################
### GENERAL METHODS
########################################################################################################

def configureCookieProcessor (cookiefile='/tmp/searchmyhash.cookie'):
    '''Set a Cookie Handler to accept cookies from the different Web sites.

    @param cookiefile Path of the cookie store.'''

    cookieHandler = LWPCookieJar()
    if cookieHandler is not None:
        if path.isfile (cookiefile):
            cookieHandler.load (cookiefile)

        opener = urllib2.build_opener ( urllib2.HTTPCookieProcessor(cookieHandler) )
        urllib2.install_opener (opener)



def do_HTTP_request (url, params={}, httpheaders={}):
    '''
    Send a GET or POST HTTP Request.
    @return: HTTP Response
    '''

    data = {}
    request = None

    # If there is parameters, they are been encoded
    if params:
        data = urlencode(params)

        request = urllib2.Request ( url, data, headers=httpheaders )
    else:
        request = urllib2.Request ( url, headers=httpheaders )

    # Send the request
    try:
        response = urllib2.urlopen (request)
    except:
        return ""

    return response



def crackHash (algorithm, hashvalue=None, hashfile=None):
    """Crack a hash or all the hashes of a file.

    @param alg Algorithm of the hash (MD5, SHA1...).
    @param hashvalue Hash value to be cracked.
    @param hashfile Path of the hash file.
    @return If the hash has been cracked or not."""

    global CRAKERS

    # Cracked hashes will be stored here
    crackedhashes = []

    # Is the hash cracked?
    cracked = False

    # Only one of the two possible inputs can be setted.
    if (not hashvalue and not hashfile) or (hashvalue and hashfile):
        return False

    # hashestocrack depends on the input value
    hashestocrack = None
    if hashvalue:
        hashestocrack = [ hashvalue ]
    else:
        try:
            hashestocrack = open (hashfile, "r")
        except:
            print "\nIt is not possible to read input file (%s)\n" % (hashfile)
            return cracked


    # Try to crack all the hashes...
    for activehash in hashestocrack:
        hashresults = []

        # Standarize the hash
        activehash = activehash.strip()
        if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
            activehash = activehash.lower()

        # Initial message
        #print "\nCracking hash: %s\n" % (activehash)

        # Each loop starts for a different start point to try to avoid IP filtered
        begin = randint(0, len(CRAKERS)-1)

        for i in range(len(CRAKERS)):

            # Select the cracker
            cr = CRAKERS[ (i+begin)%len(CRAKERS) ]()

            # Check if the cracker support the algorithm
            if not cr.isSupported ( algorithm ):
                continue

            # Analyze the hash
            # ERASE!
            print "Analyzing with %s (%s)..." % (cr.name, cr.url)

            # Crack the hash
            result = None
            try:
                result = cr.crack ( activehash, algorithm )
            # If it was some trouble, exit
            except:
                # ERASE!
                #print "\nSomething was wrong. Please, contact with us to report the bug:\n\nbloglaxmarcaellugar@gmail.com\n"
                if hashfile:
                    try:
                        hashestocrack.close()
                    except:
                        pass
                return False

            # If there is any result...
            cracked = 0
            if result:

                # If it is a hashlib supported algorithm...
                if algorithm in [MD4, MD5, SHA1,  SHA224, SHA384, SHA256, SHA512, RIPEMD]:
                    # Hash value is calculated to compare with cracker result
                    h = hashlib.new (algorithm)
                    h.update (result)

                    # If the calculated hash is the same to cracker result, the result is correct (finish!)
                    if h.hexdigest() == activehash:
                        hashresults.append (result)
                        cracked = 2

                # If it is a half-supported hashlib algorithm
                elif algorithm in [LDAP_MD5, LDAP_SHA1]:
                    alg = algorithm.split('_')[1]
                    ahash =  decodestring ( activehash.split('}')[1] )

                    # Hash value is calculated to compare with cracker result
                    h = hashlib.new (alg)
                    h.update (result)

                    # If the calculated hash is the same to cracker result, the result is correct (finish!)
                    if h.digest() == ahash:
                        hashresults.append (result)
                        cracked = 2

                # If it is a NTLM hash
                elif algorithm == NTLM or (algorithm == LM and ':' in activehash):
                    # NTLM Hash value is calculated to compare with cracker result
                    candidate = hashlib.new('md4', result.split()[-1].encode('utf-16le')).hexdigest()

                    # It's a LM:NTLM combination or a single NTLM hash
                    if (':' in activehash and candidate == activehash.split(':')[1]) or (':' not in activehash and candidate == activehash):
                        hashresults.append (result)
                        cracked = 2

                # If it is another algorithm, we search in all the crackers
                else:
                    hashresults.append (result)
                    cracked = 1

            # Had the hash cracked?
            if cracked:
                continue

            else:
                continue

        if hashresults:

            # With some hash types, it is possible to have more than one result,
            # Repited results are deleted and a single string is constructed.
            resultlist = []
            for r in hashresults:
                #if r.split()[-1] not in resultlist:
                    #resultlist.append (r.split()[-1])
                if r not in resultlist:
                    resultlist.append (r)

            finalresult = ""
            if len(resultlist) > 1:
                finalresult = ', '.join (resultlist)
            else:
                finalresult = resultlist[0]

            # Valid results are stored
            crackedhashes.append ( (activehash, finalresult) )


    # Loop is finished. File can need to be closed
    if hashfile:
        try:
            hashestocrack.close ()
        except:
            pass

    # Show a resume of all the cracked hashes
    if (crackedhashes and "\n".join ("%s -> %s" % (hashvalue, result.strip()) for hashvalue, result in crackedhashes) or "NO HASH WAS CRACKED.") != "NO HASH WAS CRACKED.":
        value = crackedhashes and "\n".join ("%s" % (result.strip()) for hashvalue, result in crackedhashes) or "NO HASH WAS CRACKED."

        #####addDB(value) # Like in hashcreator, add the pass to the db
        DOMTree = xml.dom.minidom.parse("../../private_html/free.xml")
        data = DOMTree.documentElement
        dbs = data.getElementsByTagName("database")

        for db in dbs:
            ip = db.getElementsByTagName("ip")[0]
            ip = ip.childNodes[0].data
            name = db.getElementsByTagName("name")[0]
            name = name.childNodes[0].data
            user = db.getElementsByTagName("user")[0]
            user = user.childNodes[0].data
            password = db.getElementsByTagName("pass")[0]
            password = password.childNodes[0].data

            try:
					#Database = MySQLdb.connect(ip,user,password,name)
					#cursor = Database.cursor()
					#cursor.execute(sqlAdd)
					#sqlAdd = str("""insert INTO """+ encryption + """ VALUES ('"""+ value +"""','""" + Hash + """');""")
					#cursor.execute(sqlAdd)
					print("Content-Type: text/html")
					print
					print(template % ("""
		       	<div id=pass-Matched>
		           <div id='matched'>
		               <h2>Your Password is:</h2>
		               <div id='password-matched'>"""+value+"""</div> """+donateForm+"""
		           </div>
		       	</div>"""))
					break

            except:
             	print("Content-Type: text/html")
             	print
             	print(template % ("""
             	<div id=pass-Matched>
                 <div id='matched'>
                     <h2>Your Password is:</h2>
                     <div id='password-matched'>"""+value+"""</div> """+donateForm+"""
                 </div>
             	</div>"""))

    else:
        print("Content-Type: text/html")
        print
        print(template % ("""
        <div id=pass-notMatched>
            <div id='notMatched'>
                <div id='password-notmatched'>
                    <!--<img src="/images/fail.jpg" alt="Not Matched :(" title="Not Matched :("></img>-->
                    <p>Not Matched :(</p>
                </div>
            </div>
        </div>
        <div id="arrow-index">
                <a href="#about">
                    <img src="/images/arrow.png"></img>
                </a>
            </div>
        """))

    return cracked




########################################################################################################
### MAIN CODE
########################################################################################################

def findme():
    algorithm = encryption
    hashvalue = Hash
    configureCookieProcessor()
    seed()
    cracked = 0
    cracked = crackHash(algorithm, hashvalue)


def checkPro():
    DOMTree = xml.dom.minidom.parse("../../private_html/pro.xml")
    data = DOMTree.documentElement
    dbs = data.getElementsByTagName("database")
    value = ""
    for db in dbs:
        ip = db.getElementsByTagName("ip")[0]
        ip = ip.childNodes[0].data
        name = db.getElementsByTagName("name")[0]
        name = name.childNodes[0].data
        user = db.getElementsByTagName("user")[0]
        user = user.childNodes[0].data
        password = db.getElementsByTagName("pass")[0]
        password = password.childNodes[0].data
        value = ""
        try:
            Database = MySQLdb.connect(ip,user,password,name)
            cursor = Database.cursor()
            cursor.execute(sql)
            value = cursor.fetchall()
            value = str(value).replace("(", "").replace(")", "").replace(",","").replace("'","") # Make a clear string
            if (value != ""):
                print("Content-Type: text/html")
                print
                print(template % ("""
                <div id=pass-Matched>
                    <div id='matched'>
                        <h2>Your Password is:</h2>
                        <div id='password-matched'>"""+value[0:2]+"""******</div> """+payForm+"""
                    </div>
                </div>"""))
                break
            else:
                continue
        except:
            value = ""
            continue
    if (value == ""):
        findme()

def checkFree():
    DOMTree = xml.dom.minidom.parse("../../private_html/free.xml")
    data = DOMTree.documentElement
    dbs = data.getElementsByTagName("database")
    value = ""
    for db in dbs:
        ip = db.getElementsByTagName("ip")[0]
        ip = ip.childNodes[0].data
        name = db.getElementsByTagName("name")[0]
        name = name.childNodes[0].data
        user = db.getElementsByTagName("user")[0]
        user = user.childNodes[0].data
        password = db.getElementsByTagName("pass")[0]
        password = password.childNodes[0].data
        value = ""
        try:
            Database = MySQLdb.connect(ip,user,password,name)
            cursor = Database.cursor()
            cursor.execute(sql)
            value = cursor.fetchall()
            value = str(value).replace("(", "").replace(")", "").replace(",","").replace("'","") # Make a clear string
            if (value != ""):
                print("Content-Type: text/html")
                print
                print(template % ("""
                <div id=pass-Matched>
                    <div id='matched'>
                        <h2>Your Password is:</h2>
                        <div id='password-matched'>"""+value+"""*****</div> """+donateForm+"""
                    </div>
                </div>"""))
                break
            else:
                continue
        except:
            value = ""
            continue

    if (value == ""):
        checkPro()

def main():
    if (Hash == ""):
        print("Content-Type: text/html")
        print
        print(template % ("""
        <div id="pass-noValue">
            <div id="noValue">
                    <h2> No Hash specified</h2>
            </div>
        </div>
        <div id="arrow-index">
                <a href="#contact">
                    <img src="/images/arrow.png"></img>
                </a>
            </div>
        """))
    else:
        #checkFree()
        findme()

if __name__ == "__main__":
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
                <!--<div id="arrow"><img src="/arrow.png"></img></div>-->
                <div id="preset-done" class="container">
                    %s
                </div>
            </div>
            <div id="about" class="container">
                <h2>About</h2>
                <iframe width="853" height="480" src="https://www.youtube.com/embed/fzrfrXhE-w4?rel=0&amp;controls=0&amp;showinfo=0" frameborder="0" allowfullscreen></iframe>
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
    Hash = form.getfirst("hash", "")
    Hash = cgi.escape(Hash)
    #Hash = "5f4dcc3b5aa765d61d8327deb882cf99" # JUST 4 DEBUG "PASSWORD"
    ## Ofuscate SQLi ##
    Hash = Hash.replace("+", "")
    Hash = Hash.replace("'", "")
    Hash = Hash.replace('"', "")
    Hash = Hash.replace('(', "")
    Hash = Hash.replace(')', "")
    Hash = Hash.replace('*', "")
    Hash = Hash.replace('-', "")
    Hash = Hash.replace('_', "")
    Hash = Hash.replace('=', "")
    ## Ofuscate SQLi ##
    encryption = form.getfirst("encryption", "")
    encryption = cgi.escape(encryption)
    encryption = encryption.lower()
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

    sql = "SELECT word FROM "+str(encryption)+" WHERE hash='"+str(Hash)+"' LIMIT 1;" # SQL Query

    main()
