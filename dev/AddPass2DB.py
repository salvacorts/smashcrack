#!/usr/bin/env python2
from passlib.hash import lmhash
import hashlib,binascii
import MySQLdb
import os
#################################################################### DATABASE CONF
DB_HOST = "127.0.0.1"                                               # DB address
DB_USER = "root"                                                    # DB User
DB_PASSWORD = "aluminosis"                                          # User's password
DB_NAME = "smashcrack"                                              # Database name
DB_TABLE = "SMASH"                                                  # Table in the Database
#################################################################### DATABASE CONF
db = MySQLdb.connect(DB_HOST,DB_USER,DB_PASSWORD,DB_NAME) # DB connection
cursor = db.cursor()
dic = raw_input("[+] Dictionary Path --> ") # Ask for Diccitionary file
file = open(dic, "r")
failed = open("error.txt", "w")
lines = file.readlines()
numLines = os.popen("wc -l "+dic).read().split(" ")[0]
i = 0
for line in lines:
    i += 1
    ########################################################################################### HASHES
    word = str(line).replace('\n', '')                                                        # Password in raw
    md5 = hashlib.md5(str(line).replace('\n', '')).hexdigest()                                # MD5 Hash
    md4 = hashlib.new("md4", str(line.replace('\n', '')).encode("utf-8")).hexdigest()         # MD4 Hash
    sha1 = hashlib.sha1(str(line).replace('\n', '')).hexdigest()                              # SHA1 Hash
    sha224 = hashlib.sha224(str(line).replace('\n', '')).hexdigest()                          # SHA224 Hash
    sha256 = hashlib.sha256(str(line).replace('\n', '')).hexdigest()                          # SHA256 Hash
    sha384 = hashlib.sha384(str(line).replace('\n', '')).hexdigest()                          # SHA384 Hash
    sha512 = hashlib.sha512(str(line).replace('\n', '')).hexdigest()                          # SHA512 Hash
    ntlm = hashlib.new('md4', str(line).replace('\n', '').encode('utf-16le')).digest()        # NTLM Hash
    ntlm = binascii.hexlify(ntlm)                                                             # NTLM Hash
    lm =  lmhash.encrypt(str(line).replace('\n', ''))                                         # LM Hash
    ########################################################################################### HASHES
    sql = "INSERT INTO "+DB_TABLE+" VALUES ('"+word+"','"+md5+"','"+md4+"','"+sha1+"','"+sha224+"','"+sha256+"','"+sha384+"','"+sha512+"','"+ntlm+"','"+lm+"');" # SQL
    try:
        cursor.execute(sql)
        db.commit()
        print("OK! "+str(i)+"/"+str(numLines))
    except:
        db.rollback()
	try:
		failed.write(word)
        	print("Fail! (saved...) "+str(i)+"/"+str(numLines))
	except:
		print("Fail! "+str(i)+"/"+str(numLines))
	
db.close()
file.close
failed.close()
exit()
