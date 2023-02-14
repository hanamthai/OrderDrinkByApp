import bcrypt
import time
password = "super secret password"
# password = password.encode('utf-8')
print(password)
# Hash a password for the first time, with a randomly-generated salt
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hash)

# Check that an unhashed password matches one that has previously been
print(hashed)
if bcrypt.checkpw(password, hashed):
    print("It Matches!")
else:
    print("It Does not Match :(")
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
time.sleep(2.4)


if bcrypt.checkpw(password, hashed):
    print("It Matches!")
else:
    print("It Does not Match :(")
