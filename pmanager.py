import sqlite3, sys
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
import secrets, bcrypt
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
# from cryptography.fernet import Fernet
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Window(QWidget):
    def __init__(self):
        
        super().__init__()

        self.connectToDatabase()
        self.backend = default_backend()
        self.iterations = 100_000

        self.menu_widget = QListWidget()
        self.menu_widget.itemSelectionChanged.connect(self.selectionChanged)

        self.add_button = QPushButton("+")
        self.add_button.clicked.connect(self.addAccount)
        self.delete_button = QPushButton("-")
        self.delete_button.clicked.connect(self.deleteAccount)

        self.email = QLabel('Email:')
        self.user_email = QLabel()
        self.user_email.hide()
        self.email_input = QLineEdit()
        self.email_input.hide()
        self.email_hbox = QHBoxLayout()
        self.email_hbox.addWidget(self.email)
        self.email_hbox.addWidget(self.user_email)
        self.email_hbox.addWidget(self.email_input)

        self.username = QLabel('Username:')
        self.user_username = QLabel()
        self.user_username.hide()
        self.username_input = QLineEdit()
        self.username_input.hide()
        self.username_hbox = QHBoxLayout()
        self.username_hbox.addWidget(self.username)
        self.username_hbox.addWidget(self.user_username)
        self.username_hbox.addWidget(self.username_input)

        self.password = QLabel('Password:')
        self.user_password = QLabel()
        self.user_password.hide()
        self.password_input = QLineEdit()
        self.password_input.hide()
        self.show_hide_btn = QPushButton('Show/Hide')
        self.show_hide_btn.hide()
        self.show_hide_btn.clicked.connect(self.showHideDo)
        self.password_hbox = QHBoxLayout()
        self.password_hbox.addWidget(self.password)
        self.password_hbox.addWidget(self.user_password)
        self.password_hbox.addWidget(self.password_input)
        self.password_hbox.addWidget(self.show_hide_btn)

        self.edit = QPushButton("Edit")
        self.edit.clicked.connect(self.editDetails)
        self.done = QPushButton("Done")
        self.done.clicked.connect(self.addDetails)

        if len(self.menu_widget.selectedItems()) == 0:
            self.email.hide()
            self.username.hide()
            self.password.hide()
            self.edit.hide()
            self.done.hide()

        self.vlayout_leftside = QVBoxLayout()
        self.hlayout_leftside = QHBoxLayout()
        self.vlayout_rightside = QVBoxLayout()
        self.hlayout_rightside = QHBoxLayout()

        self.hlayout_leftside.addWidget(self.add_button)
        self.hlayout_leftside.addWidget(self.delete_button)
        
        self.vlayout_leftside.addWidget(self.menu_widget)
        self.vlayout_leftside.addLayout(self.hlayout_leftside)

        self.hlayout_rightside.addWidget(self.edit)
        self.hlayout_rightside.addWidget(self.done)
        self.vlayout_rightside.addLayout(self.email_hbox)
        self.vlayout_rightside.addLayout(self.username_hbox)
        self.vlayout_rightside.addLayout(self.password_hbox)
        self.vlayout_rightside.addLayout(self.hlayout_rightside)

        self.main_widget = QWidget()
        self.main_widget.setLayout(self.vlayout_rightside)

        layout = QHBoxLayout()
        layout.addLayout(self.vlayout_leftside, 1)
        layout.addWidget(self.main_widget, 4)
        self.setLayout(layout)

        self.setMinimumSize(400, 200)

        self.setWindowTitle("Password Manager")


    def connectToDatabase(self):

        self.conn = sqlite3.connect('accounts.db')
        print('Connected Successfully')

        check = self.conn.execute('''SELECT count(name) FROM sqlite_master WHERE type='table' AND name='ACCOUNTS' ''')
        if check.fetchone()[0] == 0:
            self.conn.execute('''CREATE TABLE ACCOUNTS
                (ID INT PRIMARY KEY     NOT NULL,
                website     TEXT,
                email       TEXT,
                username    TEXT,
                password    TEXT        NOT NULL);''')


    def selectionChanged(self):
        self.email.show()
        self.username.show()
        self.password.show()
        self.show_hide_btn.show()
        self.user_email.show()
        self.edit.show()
        self.done.show()


    def showHideDo(self):
        print()


    def addAccount(self):
        # Add account to database
        print('add')
        text, ok = QInputDialog.getText(self, 'Website', 'Enter a service')

        if ok:
            print(text)
            item = QListWidgetItem(text.capitalize())
            self.menu_widget.addItem(item)
            self.menu_widget.setCurrentItem(item)


    def editDetails(self):
        self.user_email.hide()
        self.email_input.show()
        email = self.user_email.text()
        self.email_input.setText(email)

        self.user_username.hide()
        self.username_input.show()
        user = self.user_username.text()
        self.username_input.setText(user)

        self.user_password.hide()
        self.password_input.show()
        password = self.user_password.text()
        self.password_input.setText(password)


    def addDetails(self):
        print('')


    def deleteAccount(self):
        # Delete account from database
        print('delete')


    def _derive_key(self, password: bytes, salt: bytes, iterations: int = None) -> bytes:
        #Derive a secret key from a given password and salt
        if iterations is None:
            iterations = self.iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=iterations, backend=self.backend)
        return b64e(kdf.derive(password))


    def password_encrypt(self, message: bytes, password: str, iterations: int = None) -> bytes:
        if iterations is None:
            iterations = self.iterations
        salt = secrets.token_bytes(16)
        key = self._derive_key(password.encode(), salt, iterations)
        return b64e(
            b'%b%b%b' % (
                salt,
                iterations.to_bytes(4, 'big'),
                b64d(Fernet(key).encrypt(message)),
            )
        )


    def password_decrypt(self, token: bytes, password: str) -> bytes:
        decoded = b64d(token)
        salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
        iterations = int.from_bytes(iter, 'big')
        key = _derive_key(password.encode(), salt, iterations)
        return Fernet(key).decrypt(token)


class Login(QDialog):

    def __init__(self):
        super().__init__()

        self.initUI()


    def initUI(self):

        self.user = QLineEdit()
        self.user.setPlaceholderText('Username')

        self.password = QLineEdit()
        self.password.setPlaceholderText('Password')
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handleLogin)

        self.setWindowTitle("Login Window")

        layout = QVBoxLayout(self)
        layout.addWidget(self.user)
        layout.addWidget(self.password)
        layout.addWidget(self.login_btn)


    def handleLogin(self):

        # Get the users login and password from the dialog
        user = self.user.text()
        password = self.password.text()

        if self.checkDB():
            print('check user')
            
            # Fetch the users stored in the table
            self.cur.execute("SELECT user FROM LOGIN")
            # Get the first one as I only have one user - myself
            user_db = self.cur.fetchone()[0]

            # Fetch the hashed password from the table
            pass_db = self.cur.execute("SELECT password FROM LOGIN").fetchone()[0].encode('utf-8')
            print(pass_db)
            
            # Encode the inputted password using utf-8 and compare it to the stored hash using bcrypt
            # If the hash matches and the user does, the dialog is accepted
            if bcrypt.checkpw(password.encode('utf-8'), pass_db) and user == user_db:
                print('success')

                self.accept()

        else:
            # Table does not exist, therefore checkDB() created one. New user (myself) is inserted into the table
            print('New DB')

            # Generate a salt for the hash
            pass_salt = bcrypt.gensalt()
            # Hash the password using the salt and decode it, as it will be stored as a string for later reference
            hashpw = bcrypt.hashpw(password.encode('utf-8'), pass_salt).decode('utf-8')

            # Insert the user and hash into the table
            self.cur.execute('INSERT INTO LOGIN (user, password) VALUES ("{}", "{}")'.format(user, hashpw))
            self.conn.commit()

            self.accept()


    def checkDB(self):
        # Connect to the database
        # Need to find a secure way to ensure the database is not just a random DB called login.db
        self.conn = sqlite3.connect('login.db')
        # Create cursor object to allow data access in database
        self.cur = self.conn.cursor()
        print('Connected to Login DB Successfully')

        # Check if the table already exists in the database, if so then return true, else create a table
        check = self.cur.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='LOGIN'").fetchone()[0]
        if check == 0:
            self.conn.execute('''CREATE TABLE LOGIN
                (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                user     TEXT,
                password       TEXT);''')

            return 0

        elif check == 1:
            return 1


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Dialog to retrueve login details
    login = Login()

    # If the login details are accepted then continue to run the mainwindow
    if login.exec():
        print('in')
        window = Window()
        window.show()

        # Stylesheet for the GUI
        with open("style.qss", "r") as f:
            style = f.read()
            app.setStyleSheet(style)

        sys.exit(app.exec())
