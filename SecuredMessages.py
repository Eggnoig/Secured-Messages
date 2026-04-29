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

# Standrd Hill Chiper- JH
#Message = user input. hillKey = what is being used to encyrpt/ to make the matrix
#Convert letters to numbers
def character_to_number(c):
    #c.upper makes the charcater upper case. The - ord('A')subtracts 65 becuase ord turns 
    #a chracter into its ASCII number.
    #This makes no input no matter what into its number place from 0 - 25.
    #"A" = 0, "B" = 1, etc.
    return ord(c.upper()) - ord('A')
#Convert numbers to letters
def number_to_character(n):
    #This allows to convert back to ASCII
    #chr() converts an ASCII number back into a character. 65 = A, 66 = B, etc.
    return chr((n % ALPHABET_SIZE) + ord('A'))
#Gcd math to help with invertibility check
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return abs(a)
#Determinant of 3 x 3 matrix
def determinant(m):
    return (
        m[0][0] * (m[1][1]*m[2][2] - m[1][2]*m[2][1])
        - m[0][1] * (m[1][0]*m[2][2] - m[1][2]*m[2][0]) 
        + m[0][2] * (m[1][0]*m[2][1] - m[1][1]*m[2][0])
    )
#Function to check if key is valid
def is_key_matrix_invertiable(matrix):
    det = determinant(matrix)
    det_modulo = det % ALPHABET_SIZE
    return gcd(det_modulo, ALPHABET_SIZE) == 1
#Build key matrix
def key_matrix(key):
    matrix = [[0 for _ in range(3)] for _ in range(3)]
    k = 0
    for i in range(3):
        for j in range(3):
            matrix[i][j] = character_to_number(key[k])
            k += 1
    return matrix
#Hill cipher math for matrix (matrix x vector)
def multiply(matrix, vector):
    result = [0, 0, 0]
    for i in range(3):
        total = 0
        for j in range(3):
            total += matrix[i][j] * vector[j]
        result[i] = total % ALPHABET_SIZE
    return result
#Encryption
def hill_encryption(block, key_matrix):
    vector = [character_to_number(c) for c in block]
    encryption = multiply(key_matrix, vector)
    return "".join(number_to_character(x) for x in encryption)
#Hill cipher main function
def hill_cipher (message, hillKey):
    message = message.upper().replace(" ", "")
    km = key_matrix(hillKey)
    if not is_key_matrix_invertiable(km):
        raise ValueError("Key matrix is not invertible, choose a different key.")
    ciphertext = ""
    while len(message) % 3 != 0: message += 'X'
    for i in range(0, len(message), 3):
        block = message [i:i+3]
        ciphertext += hill_encryption(block, km)
    return ciphertext


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
