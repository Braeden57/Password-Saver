#Import all libraries
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import secrets
import sys
import time

inDev = False

print('\nPassword Saver')
print('Version - [2.8]')
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


# User Organization for login
class User:
    def __init__(self, username, password, savePassDict):
        self.userName = username
        self.password = password
        self.savePassDict = savePassDict


# Encrypt/Decrypt Parameters
backend = default_backend()
iterations = 100_000
gPassword = '9609c233f5c309419fa6393a1b959c13'


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))


# Encrypter
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


# Decrypter
def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


# Register
def register():
    # Open all Data
    append_file1 = open('Users.txt', 'a')
    append_file2 = open('UsersSP.txt', 'a')
    append_file3 = open('WSPF.txt', 'a')
    f = open('Users.txt', 'r')
    users = {}
    # Sets users data for login Verification
    for line in f:
        k, v = line.strip().split(':')
        users[k.strip()] = v.strip()

    f.close()

    print("\n<Account setup>")
    print("Type cancel at anytime to cancel.")
    username_create = True
    while username_create:
        # Sets username, password, and the wanted password(s) to be saved.
        print("   Your username must be 5 characters or longer.")
        userName = input("   Please set your username > ")

        if userName == "": print("This cannot be blank.\n")

        elif userName in users: print('Username is taken, please choose a different name.\n')

        elif len(userName) < 5: print("Username is too short. Please try again.\n")

        elif userName == "cancel":
            print("< Canceling >")
            time.sleep(1)
            home()
            break

        else:
            pw_maker = True
            while pw_maker:
                print("   Minimum of 8 characters")
                userPass: str = input("   Please set your password > \n")

                if len(userPass) >= 8:
                    # Account Regristation Complete

                    a = 0
                    for x in range(0, 3):
                        a = a + 1
                        b = ('Creating Account' + "." * a)
                        sys.stdout.write('\r' + b)
                        time.sleep(0.5)

                    # Sets User Data in DB
                    append_file1.write(userName + ":" + str(hashlib.md5(userPass.encode()).hexdigest()))
                    append_file1.write('\n')
                    append_file1.close()
                    time.sleep(1)
                    print("\nAccount has been created\n")

                    savePassLoop = True
                    savePassD = {}
                    while savePassLoop:
                        print('When done just hit the enter key')
                        savePass = input("   What password would you like to save in this account > ")
                        if len(savePass) == 0:
                            savePassLoop = False
                        elif len(savePass) > 0:
                            wfor = input('  What is this password for > ')
                            
                            # Sets Current Save Password into DB
                            append_file2.write(userName + ":" + str(password_encrypt(savePass.encode(), gPassword).decode()))
                            append_file3.write(f'{str(password_encrypt(savePass.encode(), gPassword).decode())}:{wfor}')
                            append_file2.write('\n')
                            append_file3.write('\n')
                            
                            # Sets Current Save Password into Dictionary for login
                            savePassD[wfor] = str(password_encrypt(savePass.encode(), gPassword).decode())
                    append_file2.close()
                    append_file3.close()

                    # Sets up user data Structure with User Class and Logs in
                    user = User(userName, hashlib.md5(userPass.encode()).hexdigest(), savePassD)
                    logged_in(user)

                elif len(userPass) == 0:
                    print("Password cant be blank.")

                elif len(userPass) < 8:
                    print("That password is too short, please try again.")

                elif userPass == "cancel":
                    print("< Canceling >")
                    time.sleep(1)
                    home()
                    break
            break


# Login
def login():
    #Data Puller
    userData = {}

    #Users Pull
    f = open('Users.txt', 'r')
    users = {}
    for line in f:
        k, v = line.strip().split(':')
        users[k.strip()] = v.strip()
    f.close()
    if len(users) == 0:
        print('No Users Found!')
        print('Register Now')
        register()
    elif len(users) > 0:

        #Users Save Pass pull
        j = open('UsersSP.txt', 'r')
        spList = []
        usersSP = {}
        for line in j:
            myDict = {}
            k, v = line.strip().split(':')
            myDict[k.strip()] = v.strip()
            spList.append(myDict)
        j.close()
        
        # Sets Save Pass List to Specific User
        for user in users:
            passlist = []
            for items in spList:
                for keys,values in items.items():
                    if keys == user:
                        if keys not in usersSP:
                            passlist.append(password_decrypt(values.encode(), gPassword).decode())
                            usersSP[keys]=passlist
                        else:
                            passlist.append(password_decrypt(values.encode(), gPassword).decode())
                            usersSP[keys]=passlist

        #What for Pull
        l = open('WSPF.txt', 'r')
        wspf = {}
        for line in l:
            k, v = line.strip().split(':')
            wspf[k.strip()] = v.strip()
        l.close()

        # Default User Data Formater
        userData = {}
        for user in users:
            passDict = {}
            for USER in usersSP:
                if USER == user:
                    for password in wspf:
                        if password_decrypt(password.encode(), gPassword).decode() in usersSP[user]:
                            passDict[wspf[password]] = password
            data = {'username': user, 'password': users[user], 'savePass': passDict}
            userData[user] = data

        username_check = True
        password_check = True

        adminName = '9581b8785e452a9d9672ddfb2277b2af'
        adminPass = '9609c233f5c309419fa6393a1b959c13'

        print('Type cancel at anytime to cancel.\n')

        while username_check:
            # Takes users input for username
            inputName = input('What is your Username > ')

            # Checks if username is correct
            if inputName in userData:
                username_check = False
                while password_check:

                    # Takes users input for password
                    inputPass = input(f"Please enter password for {inputName} > ")

                    # Checks if Password is Correct
                    if hashlib.md5(inputPass.encode()).hexdigest() == userData[inputName]['password']:
                        # Creats new User Class with User Specific Data
                        user = User(inputName, inputPass, userData[inputName]['savePass'])
                        password_check = False
                        logged_in(user)

                    elif inputPass == "cancel":
                        print("< Canceling >")
                        time.sleep(1)
                        home()
                        break

                    # Checks if password is Incorrect
                    elif hashlib.md5(inputPass.encode()).hexdigest() != userData[inputName]['password']:
                        print("That is the incorrect password. Please try again.")

            # If input Name == Admin Name
            elif hashlib.md5(inputName.encode()).hexdigest() == adminName:
                username_check = False
                while password_check:

                    # Takes input for Admin Password
                    inputAdminPass = input("Please enter password for the Admin > ")

                    # If Password Correct
                    if hashlib.md5(inputAdminPass.encode()).hexdigest() == adminPass:
                        admin()
                        break

                    elif hashlib.md5(inputAdminPass.encode()).hexdigest() != adminPass:
                        print('Incorrect Password for Admin')

                    elif inputAdminPass == "cancel":
                        print("< Canceling >")
                        time.sleep(1)
                        home()
                        break

            elif inputName == "cancel":
                print("< Canceling >")
                time.sleep(1)
                home()
                break

            # Tells user if username is incorrect
            else: print("That is an invalid username, please try again.")


# Admin Controlls
def admin():

    print("\n < Welcome >\n")

    login_op = True
    while login_op:
        print(" Options:")
        print(" < logout | user.list.show | user.info.show >")

        userSelect = input(" > ")
        userSelect = str(userSelect)
        print()

        if userSelect == "logout":
            print(" <Logging out> from <Admin>")
            print("Logout successful")
            home()
            break

        # Deactivated
        elif userSelect == "user.list.show": pass

        # Deavtivated
        elif userSelect == "user.info.show": pass

        elif userSelect == "activate.snapshot":
            global inDev
            if inDev:
                print('Snapshot (Development) is already Active')
            elif not inDev:
                print('Snapshot (Development) Status: Active')
                inDev = True

        elif userSelect == "": print("You cannot leave this blank.")

        else: print("That is an invalid option. Please try again.")


# Logged In
def logged_in(user):
    append_file2 = open('UsersSP.txt', 'a')
    append_file3 = open('WSPF.txt', 'a')
    login_op = True

    # Main Loop
    while login_op:
        print("\n Options:")
        print(" < logout | my.info | reset.password | change.savedPassword >")
        print(' < add.pass >')

        user_select = input(" > ")
        user_select.lower()

        # Logs out from user
        if user_select == "logout":
            print(f" <Logging out> from < {user.userName} >")
            time.sleep(1)
            print("Logout successful")
            home()
            break

        # Shows user save Password(s)
        elif user_select == "my.info":
            print('\nYour passwords:')
            # Gives them the saved pw in the account
            for r in user.savePassDict:
                print(f'{r}: {password_decrypt(user.savePassDict[r].encode(), gPassword).decode()}')

        # Password Reset        
        elif user_select == "reset.password":
            print("Type cancel at anytime to cancel.")

            password_check = True
            while password_check:
                password = input("Please enter your current password to activate > ")
                if password == "":
                    print("You cant leave this blank.")

                elif password == "cancel":
                    print("< Canceling >")
                    password_check = True
                    time.sleep(1)

                else:
                    if hashlib.md5(password.encode()).hexdigest() == user.password:
                        password_check = False
                        pw_maker = True
                        while pw_maker:
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
                                break

                            elif len(newSavedPass) == 0:
                                print("Password cant be blank.")

                            elif len(newSavedPass) < 8:
                                print("That password is too short, please try again.\n")

                            elif newSavedPass == "cancel":
                                print("< Canceling >")
                                time.sleep(1)
                                break

                    elif hashlib.md5(password.encode()).hexdigest() != user.password:
                        print("That is the incorrect password. Please try again.")

        elif user_select == 'change.savedPassword':
            if inDev:
                print("Type cancel at anytime to cancel.")

                password_check = True
                while password_check:
                    password = input("Please enter your current password to continue > ")
                    if password == "":
                        print("You cant leave this blank.")

                    elif password == "cancel":
                        print("< Canceling >")
                        password_check = True
                        time.sleep(1)
                        break

                    elif password == user.password:
                        pw_maker = True
                        while pw_maker:
                            print('What password would you like to change?')
                            print('\nYour passwords:')
                            # Gives them the saved pw in the account
                            for r in user.savePassDict:
                                print(f'{r}: {password_decrypt(user.savePassDict[r].encode(), gPassword).decode()}')
                            savePassName = input("Enter Password Name > ")

                            if len(savePassName) == 0:
                                print("Password Name cant be blank.")

                            elif savePassName == "cancel":
                                print("< Canceling >")
                                pw_maker = True
                                time.sleep(1)
                                break

                            else:
                                #Decrypt user.savePassDict
                                decryptDict = {}
                                for k in user.savePassDict:
                                    v = password_decrypt(user.savePassDict[k].encode(), gPassword).decode()
                                    decryptDict[k] = v
                                
                                #Check if pass exists
                                if savePassName in decryptDict:
                                    print(f"Are you sure you want to change the password for {savePassName}?\n( yes | no )")
                                    con = input('>')
                                    if con.lower() == "yes":
                                        #Changes Pass for the selected item
                                        newSavePass = input(f'What will be the new password for {savePassName}?\n>')
                                        user.savePassDict[savePassName] = password_encrypt(newSavePass.encode(), gPassword).decode()
                                        fin = open("WSPF.txt", "rt")
                                        wspfDict = {}
                                        for line in fin:
                                            k, v = line.strip().split(':')
                                            wspfDict[k.strip()] = v.strip()
                                        
                                        for k in wspfDict:
                                            if wspfDict[k] == savePassName:
                                                encryptedPass = k        
                                        data = fin.read()
                                        data = data.replace(encryptedPass, password_encrypt(newSavePass.encode(), gPassword).decode())
                                        fin.close()

                                        fin = open("WSPF.txt", "wt")
                                        fin.write(data)
                                        fin.close()

                                        fin = open("UsersSP.txt", "rt")
                                        data = fin.read()
                                        data = data.replace(encryptedPass, password_encrypt(newSavePass.encode(), gPassword).decode())
                                        fin.close()

                                        fin = open("UsersSP.txt", "wt")
                                        fin.write(data)
                                        fin.close() 

                                    elif con.lower() == "no":
                                        #Cancels changing Pass for the selected item
                                        print(f"Canceled Change for {savePassName}")
                                        break
                                
                                elif savePassName not in decryptDict:
                                    print("Password Name nout found.")

                                '''
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
                                '''
                        break

                    elif password != user.password:
                        print("That is the incorrect password. Please try again.")
    
            elif inDev == False:
                print('This Option is deactivated for development :(')

        elif user_select == 'add.pass':
            newPass = input('   What password would you like to save in this account > ')
            if len(newPass) == 0:
                print('New Password can\'t be blank')
            elif len(newPass) > 0:
                wfor = input('   What is this password for > ')
                append_file2.write(user.userName + ":" + str(password_encrypt(newPass.encode(), gPassword).decode()))
                append_file3.write(f'{str(password_encrypt(newPass.encode(), gPassword).decode())}:{wfor}')
                append_file2.write('\n')
                append_file3.write('\n')
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
            print("That is an invalid option. Please try again.\n")


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
    system_home = True
    while system_home:
        print("\n < register | login | quit | notes > ")

        user_select = input(" > ")
        user_select.lower()

        if user_select == "register":
            register()
            break

        elif user_select == "login":
            login()
            break

        elif user_select == "quit":
            print("Are you sure you want to quit?")
            print(" < yes | no >")

            user_select = input(" > ")

            if user_select == "yes":
                exit()
                print("<Shutting down>")

            elif user_select == "no":
                pass

        elif user_select == "notes":
            with open('Notes.txt', 'r') as f:
                f_contents = f.read()
                print(f_contents)

        elif user_select == "":
            print("This cant be blank.\n")

        else:
            print("That is an invalid option. Please try again.")


home()
