import sqlite3
import sys
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *

class Window(QWidget):
    def __init__(self):
        
        super().__init__()

        menu_widget = QListWidget()
        add_button = QPushButton("+")
        delete_button = QPushButton("-")

        text_widget = QLabel()
        edit = QPushButton("Edit")
        done = QPushButton("Done")

        vlayout_leftside = QVBoxLayout()
        hlayout_leftside = QHBoxLayout()
        vlayout_rightside = QHBoxLayout()
        hlayout_rightside = QHBoxLayout()

        hlayout_leftside.addWidget(add_button)
        hlayout_leftside.addWidget(delete_button)
        
        vlayout_leftside.addWidget(menu_widget)
        vlayout_leftside.addLayout(hlayout_leftside)

        hlayout_rightside.addWidget(edit)
        hlayout_rightside.addWidget(done)
        vlayout_rightside.addWidget(text_widget)
        vlayout_rightside.addLayout(hlayout_rightside)

        main_widget = QWidget()
        main_widget.setLayout(vlayout_rightside)

        layout = QHBoxLayout()
        layout.addLayout(vlayout_leftside, 1)
        layout.addWidget(main_widget, 4)
        self.setLayout(layout)

        self.setWindowTitle("Password Manager")




if __name__ == "__main__":
    app = QApplication([])
    window = Window()
    window.show()

    with open("style.qss", "r") as f:
        _style = f.read()
        app.setStyleSheet(_style)

    sys.exit(app.exec())