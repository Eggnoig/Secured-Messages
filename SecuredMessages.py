import sys
from pathlib import Path #Used for .ui

# PySide6 imports
from PySide6.QtCore import QFile
from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
)
#DES imports
try:
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError:
    DES = None
    pad = None
    unpad = None
import base64

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
#Decryption
#matirx math for inverstion
def minor(m, row, col):
    sub_m = [
        [m[i][j] for j in range(3) if j != col]
        for i in range(3) if i != row
    ]
    #2x2 determinant math
    return sub_m[0][0] * sub_m[1][1] - sub_m[0][1] * sub_m[1][0]
#Finds a number that when multiplied by b gives 1 mod m, neeeded to undo the determinant in moduar math
def mod_inverse(b, m):
    b = b % m
    for x in range(1, m):
        if (b * x) % m == 1:
            return x
    return None
#Builds inverse of key matrix for decryption
def invert_key_matrix(m):
    det = determinant(m) % ALPHABET_SIZE
    det_invert = mod_inverse(det, ALPHABET_SIZE)
    if det_invert is None:
        raise ValueError("Key matrix has no modular inverse.")
    #Start with empty 3 x 3 matrix
    inverse = [[0]*3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            sign = (-1) ** (i +j)
            inverse[j][i] = (det_invert * sign * minor(m, i, j)) % ALPHABET_SIZE
    return inverse
#Same as decrypt but with inverse key
def hill_decryption(ciphertext, hillKey):
    ciphertext = ciphertext.upper().replace(" ", "")
    km = key_matrix(hillKey)
    if not is_key_matrix_invertiable(km):
        raise ValueError("Key is not invertible, choose a different key ")
    inverse_km = invert_key_matrix(km)
    plaintext = ""
    for i in range(0, len(ciphertext), 3):
        block = ciphertext[i:i+3]
        plaintext += hill_encryption(block, inverse_km)
    return plaintext
#Hill cipher main function
def hill_cipher (message, hill_key):
    message = message.upper().replace(" ", "")
    km = key_matrix(hill_key)
    if not is_key_matrix_invertiable(km):
        raise ValueError("Key matrix is not invertible, choose a different key.")
    ciphertext = ""
    while len(message) % 3 != 0: message += 'X'
    for i in range(0, len(message), 3):
        block = message [i:i+3]
        ciphertext += hill_encryption(block, km)
    return ciphertext

#DES algorithm- JH
#install pycrptodome
#DES key has to be 8 bytes
def prepare_des_key(key: str):
    if not isinstance(key, str):
        raise TypeError("DES key must be a string.")

    if len(key) > 8:
        raise ValueError("DES key must be 8 characters or fewer.")

    padded_key = key.ljust(8)
    des_key = padded_key.encode("utf-8")

    if len(des_key) != 8:
        raise ValueError("DES key must use single-byte characters only.")

    return des_key, padded_key != key


#DES Encryption
#plaintext: str -> str can be removed if it is already a string
#that the user input is a string. Just put that variable there
def des_encryption(plaintext: str, des_key: bytes) -> str:
    #input validation
    if not isinstance(plaintext, str):
        raise TypeError("Input must be a string.")
    #convert string to bytes (since DES only works with bytes)
    bytes = plaintext.encode("utf-8")
    #Pad user input to a multiple of 8 bytes
    padded_bytes = pad(bytes, DES.block_size)
    des_algorithm = DES.new(des_key, DES.MODE_CBC)
    #Convert the message to bytes and pad it
    #DES requires data to be in multiple of 8 bytes to work
    ciphertext = des_algorithm.encrypt(padded_bytes)
    #We add the IV to the ciphertext so that we can decode later
    #It is base64 encoded so it is a clean string for UI
    return base64.b64encode(des_algorithm.iv + ciphertext).decode("utf-8")

#DES Decryption
def des_decryption(encoded_ciphertext: str, des_key: bytes) -> str:
    #First need to decode from base64 back to the raw bytes
    raw_bytes = base64.b64decode(encoded_ciphertext)
    #Extract IV (first 8 bytes)
    #The rest of the raw_bytes (from index 8) is the message
    des_algorithm = DES.new(des_key, DES.MODE_CBC, iv=raw_bytes[:8])
    #Decrypt the cipherttext and take out the padding to get the original message
    plaintext = unpad(des_algorithm.decrypt(raw_bytes[8:]), DES.block_size)
    return plaintext.decode("utf-8")

def hill_cipher_ui(message, hill_key, encode=True):
    if not encode:
        raise ValueError("Hill Cipher decode is not implemented yet.")

    hill_key = hill_key.upper().replace(" ", "")

    if len(hill_key) != 9:
        raise ValueError("Hill Cipher requires a 9-letter keyword for the 3 x 3 key matrix.")

    if not hill_key.isalpha():
        raise ValueError("Hill Cipher keyword must contain letters only.")

    return hill_cipher(message, hill_key)
def des_cipher(message, key, encode=True):
    if DES is None:
        raise ValueError("DES support requires installing pycryptodome.")

    des_key, _ = prepare_des_key(key)

    try:
        if encode:
            return des_encryption(message, des_key)

        return des_decryption(message, des_key)
    except (ValueError, TypeError) as exc:
        raise ValueError(str(exc)) from exc
# Class Handles UI/User Interaction
class SecuredMessagesWindow:
    def __init__(self):
        self.ciphers = {
            "Caesar Shift": caesar_cipher,
            "Hill Cipher": hill_cipher_ui,
            "DES": des_cipher,
        }

        self.window = self.load_ui()
        #Buttons need to be in a button group to work as radio buttons, 
        # but we don't need to do anything with the group itself
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
        self.matrix_group = self.find_widget(QGroupBox, "matrix_group")
        self.matrix_hint = self.find_widget(QLabel, "matrix_hint")
        self.matrix_table = self.find_widget(QTableWidget, "matrix_table")

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

        self.initialize_matrix_table()
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
    #Helper function to find widgets by type and name, with error handling
    def find_widget(self, widget_type, object_name):
        widget = self.window.findChild(widget_type, object_name)

        if widget is None:
            raise RuntimeError(f"Could not find widget named {object_name}.")

        return widget

    def show(self):
        self.window.show()
# Initializes the 3 x 3 matrix table with default values (1s on the diagonal, 0s elsewhere)
    def initialize_matrix_table(self):
        self.matrix_table.setRowCount(3)
        self.matrix_table.setColumnCount(3)

        for row_index in range(3):
            for column_index in range(3):
                cell_value = "1" if row_index == column_index else "0"
                self.matrix_table.setItem(row_index, column_index, QTableWidgetItem(cell_value))

    def read_matrix_values(self):
        matrix = []

        for row_index in range(self.matrix_table.rowCount()):
            row_values = []

            for column_index in range(self.matrix_table.columnCount()):
                item = self.matrix_table.item(row_index, column_index)
                cell_text = item.text().strip() if item is not None else ""

                if not cell_text:
                    raise ValueError(
                        f"Matrix cell R{row_index + 1}, C{column_index + 1} is empty."
                    )

                try:
                    row_values.append(int(cell_text))
                except ValueError as exc:
                    raise ValueError(
                        f"Matrix cell R{row_index + 1}, C{column_index + 1} must be a whole number."
                    ) from exc

            matrix.append(row_values)

        return matrix

#Updates the key input field and hints based on the selected cipher. 
# Shows the matrix group for Hill Cipher and hides it for others.
    def update_key_field(self, cipher_name):
        self.matrix_group.setVisible(False)

        if cipher_name == "Caesar Shift":
            self.key_input.setEnabled(True)
            self.key_input.setPlaceholderText("Example: 3") #Hints for Cipher
            self.key_hint.setText("Use a whole number for the Caesar shift.") #Hints for Cipher
            self.matrix_hint.setText("Enter Hill Cipher matrix values from 0 to 25.")
        elif cipher_name == "Hill Cipher":
            self.key_input.setEnabled(True)
            self.key_input.setPlaceholderText("Example: GYBNQKURP") #Hints for Cipher
            self.key_hint.setText("Use a 9-letter keyword to build the 3 x 3 Hill Cipher key matrix.") #Hints for Cipher
            self.matrix_hint.setText("Enter Hill Cipher matrix values from 0 to 25.")
        else:
            self.key_input.setEnabled(True)
            self.key_input.setPlaceholderText("Up to 8 characters") #Hints for Cipher
            self.key_hint.setText("DES uses up to 8 characters. Short keys are padded to 8.") #Hints for Cipher

#
    def convert_message(self):
        cipher_name = self.cipher_combo.currentText()
        cipher = self.ciphers[cipher_name]
        message = self.message_input.toPlainText()
        key = self.key_input.text()
        encode = self.encode_radio.isChecked()
        des_key_was_padded = False

        try:
            if cipher_name == "DES":
                _, des_key_was_padded = prepare_des_key(key)
            converted_message = cipher(message, key, encode)
        except ValueError as exc:
            QMessageBox.warning(self.window, "Check your key", str(exc))
            self.status_label.setText("Conversion stopped. Check the key and try again.")
            return

        self.output_text.setPlainText(converted_message)
        action = "Encoded" if encode else "Decoded"
        if cipher_name == "DES" and des_key_was_padded:
            self.status_label.setText(f"{action} with {cipher_name}. Key padded to 8 characters.")
        else:
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
