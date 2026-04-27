import sys
from pathlib import Path

from PySide6.QtCore import QFile
from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QTextEdit,
)

ALPHABET_SIZE = 26 #Used for Wrapping Shifts


def shift_character(character, shift):
    if "A" <= character <= "Z":
        base = ord("A")
    elif "a" <= character <= "z":
        base = ord("a")
    else:
        return character

    return chr((ord(character) - base + shift) % ALPHABET_SIZE + base)

# Standard Caesar Cipher that Shifts by specificed amount
def caesar_cipher(text, key, encode=True):
    try:
        shift = int(key)
    except ValueError as exc:
        raise ValueError("Caesar Shift needs a whole-number key, such as 3.") from exc

    if not encode:
        shift = -shift

    return "".join(shift_character(character, shift) for character in text)


# Class Handles UI/User Interaction
class SecuredMessagesWindow:
    def __init__(self):
        self.ciphers = {
            "Caesar Shift": caesar_cipher,
        }

        self.window = self.load_ui()
        #Buttons need to be in a button group to work as radio buttons, but we don't need to do anything with the group itself
        self.mode_buttons = QButtonGroup(self.window)
        self.encode_radio = self.find_widget(QRadioButton, "encode_radio")
        self.decode_radio = self.find_widget(QRadioButton, "decode_radio")
        self.mode_buttons.addButton(self.encode_radio)
        self.mode_buttons.addButton(self.decode_radio)

        self.cipher_combo = self.find_widget(QComboBox, "cipher_combo")
        self.cipher_combo.clear()
        self.cipher_combo.addItems(self.ciphers.keys())
        self.cipher_combo.currentTextChanged.connect(self.update_key_field)

        self.key_input = self.find_widget(QLineEdit, "key_input")
        self.key_hint = self.find_widget(QLabel, "key_hint") #Tells you how to use the key field for the selected cipher

        self.message_input = self.find_widget(QTextEdit, "message_input")
        self.output_text = self.find_widget(QTextEdit, "output_text")
        self.status_label = self.find_widget(QLabel, "status_label")

        self.convert_button = self.find_widget(QPushButton, "convert_button")
        self.convert_button.clicked.connect(self.convert_message)

        self.swap_button = self.find_widget(QPushButton, "swap_button")
        self.swap_button.clicked.connect(self.swap_text)

        self.clear_button = self.find_widget(QPushButton, "clear_button")
        self.clear_button.clicked.connect(self.clear_text)

        self.copy_button = self.find_widget(QPushButton, "copy_button")
        self.copy_button.clicked.connect(self.copy_output)

        self.update_key_field(self.cipher_combo.currentText())

# Loads UI from .ui file and returns the main window widget
    def load_ui(self):
        ui_path = Path(__file__).with_name("secured_messages.ui")
        ui_file = QFile(str(ui_path))

        if not ui_file.open(QFile.ReadOnly):
            raise RuntimeError(f"Could not open UI file: {ui_path}")

        loader = QUiLoader()
        window = loader.load(ui_file)
        ui_file.close()

        if window is None:
            raise RuntimeError(loader.errorString())

        return window

    def find_widget(self, widget_type, object_name):
        widget = self.window.findChild(widget_type, object_name)

        if widget is None:
            raise RuntimeError(f"Could not find widget named {object_name}.")

        return widget

    def show(self):
        self.window.show()

    def update_key_field(self, _cipher_name):
        self.key_input.setEnabled(True)
        self.key_input.setPlaceholderText("Example: 3") #Hints for Cipher
        self.key_hint.setText("Use a whole number for the Caesar shift.") #Hints for Cipher

    def convert_message(self):
        cipher_name = self.cipher_combo.currentText()
        cipher = self.ciphers[cipher_name]
        message = self.message_input.toPlainText()
        key = self.key_input.text()
        encode = self.encode_radio.isChecked()

        try:
            converted_message = cipher(message, key, encode)
        except ValueError as exc:
            QMessageBox.warning(self.window, "Check your key", str(exc))
            self.status_label.setText("Conversion stopped. Check the key and try again.")
            return

        self.output_text.setPlainText(converted_message)
        action = "Encoded" if encode else "Decoded"
        self.status_label.setText(f"{action} with {cipher_name}.")

    def swap_text(self): #Swaps output and Input
        self.message_input.setPlainText(self.output_text.toPlainText())
        self.output_text.clear()
        self.status_label.setText("Output moved back into the message box.")

    def clear_text(self): #Clears both text boxes and resets the status label
        self.message_input.clear()
        self.output_text.clear()
        self.status_label.setText("Cleared.")

    def copy_output(self): #Basic clipboard copy funct
        QApplication.clipboard().setText(self.output_text.toPlainText())
        self.status_label.setText("Output copied to the clipboard.")


def main():
    app = QApplication(sys.argv)
    window = SecuredMessagesWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
