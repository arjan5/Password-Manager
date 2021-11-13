import sqlite3, bcrypt
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import sys
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *

class Window(QWidget):
    def __init__(self):
        
        super().__init__()

        self.connectToDatabase()

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


class AESCipher(object):
    
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
        self.encrypted = ''


    def getEnc(self):
        return self.encrypted


    def __pad(self, plain_text):
        num_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(num_of_bytes_to_pad)
        padding_str = num_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text


    @staticmethod
    def __unpad(plain_text):
        last_char = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_char)
        return plain_text[:-bytes_to_remove]


    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        self.encrypted = b64encode(iv + encrypted_text).decode("utf-8")
        return self.encrypted


    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)



if __name__ == "__main__":
    app = QApplication([])
    window = Window()
    window.show()

    with open("style.qss", "r") as f:
        style = f.read()
        app.setStyleSheet(style)

    sys.exit(app.exec())