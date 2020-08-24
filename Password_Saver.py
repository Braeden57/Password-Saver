from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import secrets
import sys
import time

print()
print('Password Saver')
print('Version - [2.7]')
# pylint: disable=unused-variable
# pylint: enable=too-many-lines


'''
Default Data Layout
userData = {
    'testUser': {
        'username': 'testuser',
        'password': 'testpass',
        'savePass': {
            'for1': 'savepass1',
            'for2': 'savepass2'
        }
    }
}
'''


class User:
    def __init__(self, username, password, savePassDict):
        self.userName = username
        self.password = password
        self.savePassDict = savePassDict


backend = default_backend()
iterations = 100_000
gPassword = '9609c233f5c309419fa6393a1b959c13'


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))


def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )


def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def register():
    append_file1 = open('Users.txt', 'a')
    append_file2 = open('UsersSP.txt', 'a')
    append_file3 = open('WSPF.txt', 'a')
    f = open('Users.txt', 'r')
    users = {}
    for line in f:
        k, v = line.strip().split(':')
        users[k.strip()] = v.strip()

    f.close()

    print()
    print("<Account setup>")
    print("Type cancel at anytime to cancel.")
    username_create = False
    while not username_create:
        # Sets username, password, and the wanted password to be saved.
        print("   Your username must be 5 characters or longer.")
        userName = input("   Please set your username > ")

        if userName == "":
            print("This cannot be blank.")
            print()

        elif userName in users:
            print('Username is taken, please choose a different name.')
            print()

        elif len(userName) < 5:
            print("Username is too short. Please try again.")
            print()

        elif userName == "cancel":
            print("< Canceling >")
            username_create = True
            time.sleep(1)
            home()

        else:
            username_create = True
            pw_maker = False
            while not pw_maker:
                print("   Minimum of 8 characters")
                userPass: str = input("   Please set your password > ")
                print()

                if len(userPass) >= 8:

                    a = 0
                    for x in range(0, 3):
                        a = a + 1
                        b = ('Creating Account' + "." * a)
                        sys.stdout.write('\r' + b)
                        time.sleep(0.5)
                    append_file1.write('\n')
                    append_file1.write(userName + ":" + str(hashlib.md5(userPass.encode()).hexdigest()))
                    append_file1.close()
                    time.sleep(1)
                    print()
                    print("Account has been created")
                    print()
                    savePassLoop = False
                    savePassD = {}
                    while not savePassLoop:
                        print('When done just hit the enter key')
                        savePass = input("   What password would you like to save in this account > ")
                        if len(savePass) == 0:
                            savePassLoop = True
                        elif len(savePass) > 0:
                            wfor = input('  What is this password for > ')
                            append_file2.write('\n')
                            append_file2.write(userName + ":" + str(password_encrypt(savePass.encode(), gPassword).decode()))
                            append_file3.write('\n')
                            append_file3.write(f'{wfor}:{str(password_encrypt(savePass.encode(), gPassword).decode())}')
                            savePassD[wfor] = str(password_encrypt(savePass.encode(), gPassword).decode())
                    append_file2.close()
                    append_file3.close()
                    print()

                    user = User(userName, hashlib.md5(userPass.encode()).hexdigest(), savePassD)
                    logged_in(user)

                elif len(userPass) == 0:
                    print("Password cant be blank.")

                elif len(userPass) < 8:
                    print("That password is too short, please try again.")

                elif userPass == "cancel":
                    print("< Canceling >")
                    pw_maker = True
                    time.sleep(1)
                    home()


def login():
    f = open('Users.txt', 'r')
    users = {}
    for line in f:
        k, v = line.strip().split(':')
        users[k.strip()] = v.strip()
    f.close()
    j = open('UsersSP.txt', 'r')
    usersSP = {}
    for line in j:
        k, v = line.strip().split(':')
        usersSP[k.strip()] = v.strip()
    j.close()
    l = open('WSPF.txt', 'r')
    wspf = {}
    for line in l:
        k, v = line.strip().split(':')
        wspf[k.strip()] = v.strip()
    l.close()
    userData = {}
    for user in users:
        savePassL = {}
        for USER in usersSP:
            if USER == user:
                SavePass = usersSP[USER]
                for r in wspf:
                    if password_decrypt(wspf[r].encode(), gPassword).decode() == password_decrypt(SavePass.encode(), gPassword).decode():
                        pw = usersSP[USER]
                        savePassL[r] = pw
                        data = {'username': user, 'password': users[user], 'savePassDict': savePassL}
                        userData[user] = data
                        
    username_check = False
    password_check = False

    adminName = '9581b8785e452a9d9672ddfb2277b2af'
    adminPass = '9609c233f5c309419fa6393a1b959c13'

    print('Type cancel at anytime to cancel.')
    print()

    while not username_check:
        # Takes users input for username
        inputName = input('What is your Username > ')
        inputName = str(inputName)

        # Checks if username is correct
        if inputName in userData:
            username_check = True
            while not password_check:

                # Takes users input for pw
                inputPass = input(f"Please enter password for {inputName} > ")

                if hashlib.md5(inputPass.encode()).hexdigest() == userData[inputName]['password']:
                    user = User(inputName, inputPass, userData[inputName]['savePassDict'])
                    password_check = True
                    logged_in(user)

                elif inputPass == "cancel":
                    print("< Canceling >")
                    password_check = True
                    time.sleep(1)
                    home()

                elif hashlib.md5(inputPass.encode()).hexdigest() != userData[inputName]['password']:
                    print("That is the incorrect password. Please try again.")

        elif hashlib.md5(inputName.encode()).hexdigest() == adminName:
            username_check = True
            while not password_check:

                # Takes users input for pw
                inputAdminPass = input("Please enter password for the Admin > ")
                inputAdminPass = str(inputAdminPass)

                if hashlib.md5(inputAdminPass.encode()).hexdigest() == adminPass:
                    password_check = True
                    admin()

                elif inputAdminPass == "cancel":
                    print("< Canceling >")
                    password_check = True
                    time.sleep(1)
                    home()

        elif inputName == "cancel":
            print("< Canceling >")
            username_check = True
            time.sleep(1)
            home()

        # Tells user if username is incorrect
        else:
            print("That is an invalid username, please try again.")


def admin():

    print()
    print(" < Welcome Braeden >")
    print()

    login_op = False
    while not login_op:
        print(" Options:")
        print(" < logout | user.list.show | user.info.show >")

        userSelect = input(" > ")
        userSelect = str(userSelect)
        print()

        if userSelect == "logout":
            print(" <Logging out> from <Admin>")
            print("Logout successful")
            login_op = True

        elif userSelect == "user.list.show":
            pass

        elif userSelect == "user.info.show":
            pass

        elif userSelect == "":
            print("You cannot leave this blank.")

        else:
            print("That is an invalid option. Please try again.")


def logged_in(user):
    append_file2 = open('UsersSP.txt', 'a')
    append_file3 = open('WSPF.txt', 'a')
    login_op = False

    while not login_op:
        print()
        print(" Options:")
        print(" < logout | my.info | reset.password | change.savedPassword >")
        print(' < add.pass >')

        user_select = input(" > ")
        user_select = str(user_select)

        if user_select == "logout":
            print(f" <Logging out> from < {user.userName} >")
            time.sleep(1)
            print("Logout successful")
            login_op = True
            home()

        elif user_select == "my.info":
            # Gives them the saved pw in the account
            for r in user.savePassDict:
                print(f'{r}: {password_decrypt(user.savePassDict[r].encode(), gPassword).decode()}')

        elif user_select == "reset.password":
            print("Type cancel at anytime to cancel.")

            password_check = False
            while not password_check:
                password = input("Please enter your current password to activate > ")
                if password == "":
                    print("You cant leave this blank.")

                elif password == "cancel":
                    print("< Canceling >")
                    password_check = True
                    time.sleep(1)

                else:
                    if hashlib.md5(password.encode()).hexdigest() == user.password:
                        password_check = True
                        pw_maker = False
                        while not pw_maker:
                            print("   Minimum of 8 characters")
                            newSavedPass = input("Please set your new password > ")

                            if len(newSavedPass) >= 8:
                                user.password = hashlib.md5(newSavedPass.encode()).hexdigest()

                                fin = open("Users.txt", "rt")
                                data = fin.read()
                                data = data.replace(str(hashlib.md5(password.encode()).hexdigest()), str(hashlib.md5(newSavedPass.encode()).hexdigest()))
                                fin.close()

                                fin = open("Users.txt", "wt")
                                fin.write(data)
                                fin.close()

                                f = open('Users.txt', 'r')
                                users = {}
                                for line in f:
                                    k, v = line.strip().split(':')
                                    users[k.strip()] = v.strip()

                                f.close()

                                print("Your new password has been set")
                                pw_maker = True

                            elif len(newSavedPass) == 0:
                                print("Password cant be blank.")

                            elif len(newSavedPass) < 8:
                                print("That password is too short, please try again.")
                                print()

                            elif newSavedPass == "cancel":
                                print("< Canceling >")
                                pw_maker = True
                                time.sleep(1)

                    elif hashlib.md5(password.encode()).hexdigest() != user.password:
                        print("That is the incorrect password. Please try again.")

        elif user_select == 'change.savedPassword':
            print("Type cancel at anytime to cancel.")

            password_check = False
            while not password_check:
                password = input("Please enter your current password to activate > ")
                if password == "":
                    print("You cant leave this blank.")

                elif password == "cancel":
                    print("< Canceling >")
                    password_check = True
                    time.sleep(1)

                else:
                    if password == user.password:
                        password_check = True
                        pw_maker = False
                        while not pw_maker:
                            newSavedPass = input("Please set your new password to save > ")

                            if len(newSavedPass) == 0:
                                print("Password cant be blank.")

                            elif newSavedPass == "cancel":
                                print("< Canceling >")
                                pw_maker = True
                                time.sleep(1)

                            else:
                                user.savePass = password_encrypt(newSavedPass.encode(), gPassword).decode()
                                fin = open("UsersSP.txt", "rt")
                                data = fin.read()
                                data = data.replace(user.savePass, str(password_encrypt(newSavedPass.encode(), gPassword).decode()))
                                fin.close()

                                fin = open("UsersSP.txt", "wt")
                                fin.write(data)
                                fin.close()

                                print("Your new saved password is set")
                                pw_maker = True

                    elif password != user.password:
                        print("That is the incorrect password. Please try again.")
        
        elif user_select == 'add.pass':
            newPass = input('   What password would you like to save in this account > ')
            if len(newPass) == 0:
                print('New Password can\'t be blank')
            elif len(newPass) > 0:
                wfor = input('   What is this password for > ')
                append_file2.write('\n')
                append_file2.write(user.userName + ":" + str(password_encrypt(newPass.encode(), gPassword).decode()))
                append_file3.write('\n')
                append_file3.write(f'{wfor}:{str(password_encrypt(newPass.encode(), gPassword).decode())}')
                newSavePassDict = user.savePassDict
                newSavePassDict[wfor] = str(password_encrypt(newPass.encode(), gPassword).decode())
                append_file2.close()
                append_file3.close()
                print()
                user = User(user.userName, user.password, newSavePassDict)
                logged_in(user)

        elif user_select == "":
            print("You cannot leave this blank.")

        else:
            print("That is an invalid option. Please try again.")
            print()
        
        #remove.pass in >dev<
        '''
        elif user_select == 'remove.pass':
            removePass = input('What password would you like to remove > ')
            if removePass in user.savePassDict:
                print(f'Are you sure you want to delete this password?')
                print(' <y|n>')
                choice = input(' > ')
                if choice == 'y':
                    #remove code goes here

                elif choice == 'n':
                    print('Not deleting the password')

            else:
                print(f'The password {removePass} doesn\'t exist.')
        '''


def print_all_users(userList):
    if userList is not None and len(userList) > 0:
        for key, val in userList.items():
            print("User: " + key)
            print("pass: " + val)
            print("-------------------------------")


def print_user_data(user_info):
    if user_info is not None and len(user_info) > 0:
        for key, val in user_info.items():
            print("User: " + key)
            print("Info: " + val)
            print("-------------------------------")


def home():
    system_home = False
    while not system_home:
        print()
        print(" < register | login | quit | notes > ")

        user_select = input(" > ")
        user_select = str(user_select)

        if user_select == "register":
            system_home = True
            register()

        elif user_select == "login":
            system_home = True
            login()

        elif user_select == "quit":
            print("Are you sure you want to quit?")
            print(" < yes | no >")

            user_select = input(" > ")
            user_select = str(user_select)

            if user_select == "yes":
                system_home = True
                print("<Shutting down>")

            elif user_select == "no":
                pass

        elif user_select == "notes":
            with open('Notes.txt', 'r') as f:
                f_contents = f.read()
                print(f_contents)

        elif user_select == "":
            print("This cant be blank.")
            print()

        else:
            print("That is an invalid option. Please try again.")


home()
