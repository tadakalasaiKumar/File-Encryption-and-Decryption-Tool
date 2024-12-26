import tkinter as tk
from tkinter import messagebox, filedialog
import webbrowser
from PIL import Image, ImageTk
import os
import subprocess
import pkg_resources
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

required_packages = ['pycryptodomex', 'cryptography']

# Check if each required package is installed
for package in required_packages:
    try:
        pkg_resources.get_distribution(package)
    except pkg_resources.DistributionNotFound:
        # If the package is not installed, install it
        print(f"{package} is not installed. Installing...")
        subprocess.check_call(['pip', 'install', package])

from Cryptodome.Random import get_random_bytes


def encrypt_file(filepath, sender_email, receiver_email, smtp_password):
    if filepath == '':
        messagebox.showerror("Error", "Please select a file to encrypt.")
        return
    if not os.path.exists(filepath):
        messagebox.showerror("Error", "Invalid file path.")
        return

    # Generate a key for encryption
    key = Fernet.generate_key()

    # Create a Fernet object with the key
    fernet = Fernet(key)

    if os.path.isfile(filepath):
        # Read the content of the file
        with open(filepath, 'rb') as file:
            data = file.read()

        # Encrypt the data using Fernet
        encrypted_data = fernet.encrypt(data)

        # Write the encrypted data back to the file
        with open(filepath, 'wb') as file:
            file.write(encrypted_data)

        # Save the key to an email for decryption later
        subject = 'The Key for Encrypted file'
        message = 'The Key for Encrypted file ' + filepath + ' is:\n' + str(key)

        # Set up SMTP server configuration
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        smtp_username = sender_email

        # Create a multipart message object
        msg = MIMEMultipart()
        msg['from'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        # Add a text message to the email
        msg.attach(MIMEText(message, 'plain'))

        try:
            # Connect to the SMTP server
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_username, smtp_password)

            server.send_message(msg)
            server.quit()
            messagebox.showinfo("Info", "File encrypted successfully.")
            window_1.destroy()
        except smtplib.SMTPException:
            messagebox.showerror("Error", "Failed to send email. File encrypted, but key not sent.")

    else:
        messagebox.showerror("Error", "Invalid file.")


def decrypt_file(filepath, password):
    if filepath == '':
        messagebox.showerror("Error", "Please select a file to decrypt.")
        return
    if not os.path.exists(filepath):
        messagebox.showerror("Error", "Invalid file path.")
        return
    if password == '':
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        key = password.encode()
        key = key[2:-1]

        try:
            # Create a Fernet object with the key
            fernet = Fernet(key)

            if os.path.isfile(filepath):
                # Read the encrypted contents of the file
                with open(filepath, 'rb') as file:
                    encrypted_data = file.read()

                try:
                    # Decrypt the data using Fernet
                    decrypted_data = fernet.decrypt(encrypted_data)

                    # Write the decrypted data back to the file
                    with open(filepath, 'wb') as file:
                        file.write(decrypted_data)

                    messagebox.showinfo("Info", "File decrypted successfully.")
                    window2.destroy()
                except InvalidToken:
                    messagebox.showerror("Error", "Invalid key. Decryption failed.")
                    return
        except ValueError:
            messagebox.showerror("Error", "Invalid password.")
            return

    except Exception as e:
        messagebox.showinfo("Info", "Failed to decrypt file: " + str(e))


def decrypt_browse_file(entry_filepath):
    filepath = filedialog.askopenfilename()
    entry_filepath.delete(0, tk.END)
    entry_filepath.insert(0, filepath)


def encrypt_browse_file(e_filepath):
    filepath = filedialog.askopenfilename()
    e_filepath.delete(0, tk.END)
    e_filepath.insert(0, filepath)


def encrypt_window():
    global window_1
    window_1 = tk.Toplevel(window)
    window_1.title("Encrypt.....")
    window_1.geometry("500x300+200+200")

    frame = tk.Frame(window_1, width=50, height=50)
    frame.pack(fill="x")
    label1 = tk.Label(frame, text="file path", font=("Arial", 10))
    label1.pack(ipady=20, padx=20, side="left")

    e_filepath = tk.Entry(frame, width=50)
    e_filepath.pack(pady=10, side="left")

    e_browse = tk.Button(frame, text="browse", command=lambda: encrypt_browse_file(e_filepath))
    e_browse.pack(side="left", padx=5, pady=10)

    frame2 = tk.Frame(window_1, width=50, height=50)
    frame2.pack(fill="x")

    label2 = tk.Label(frame2, text="Sender mail", font=("Arial", 10))
    label2.pack(ipady=20, padx=10, side="left")

    sender = tk.Entry(frame2, width=50)
    sender.pack(pady=10, side="left")

    frame4 = tk.Frame(window_1, width=50, height=50)
    frame4.pack(fill="x", pady=5)

    label4 = tk.Label(frame4, text="smtp passwd", font=("Arial", 10))
    label4.pack(padx=8, side="left")

    smtp_passwd = tk.Entry(frame4, width=50, show="*")
    smtp_passwd.pack(side="left")

    frame3 = tk.Frame(window_1, width=50, height=50)
    frame3.pack(fill="x", pady=5)

    label3 = tk.Label(frame3, text="Receiver mail", font=("Arial", 10))
    label3.pack(padx=8, side="left")

    receiver = tk.Entry(frame3, width=50)
    receiver.pack(side="left")

    encrypt_button = tk.Button(window_1, text="Encrypt", width=10, height=2, bg="red", fg="white", font=("Arial", 10, "bold"),
                               command=lambda: encrypt_file(e_filepath.get(), sender.get(), receiver.get(), smtp_passwd.get()))
    encrypt_button.pack(pady=10)


def dec_window():
    global window2
    window2 = tk.Toplevel(window)
    window2.title("Decrypting...")
    window2.geometry("500x150+200+200")

    l1 = tk.Label(window2, text="filepath")
    l1.grid(row=0, column=0, padx=10, pady=10)

    entry_filepath = tk.Entry(window2, width=50)
    entry_filepath.grid(row=0, column=1, padx=10, pady=10)

    de_browse = tk.Button(window2, text="Browse", command=lambda: decrypt_browse_file(entry_filepath))
    de_browse.grid(row=0, column=4)

    password_label = tk.Label(window2, text="Password:")
    password_label.grid(row=2, column=0)

    password_entry = tk.Entry(window2, width=50, show="*")
    password_entry.grid(row=2, column=1, padx=5, pady=5)

    button = tk.Button(window2, text="Decrypt", width=10, height=2, bg="red", fg="white", font=("Arial", 10, "bold"),
                       command=lambda: decrypt_file(entry_filepath.get(), password_entry.get()))
    button.grid(row=3, column=1, pady=5)




window = tk.Tk()
window.title('Encrypt and Decrypt File!!')
window.geometry("500x500")
window.geometry("+100+100")
window.configure(background='black')
window.resizable(False, False)



encrypt_label = tk.Label(window, text="Secure Your Files!!!", font=("Helvetica", 16, "bold"), fg="Red", bg="black")
encrypt_label.pack(pady=30)


frame = tk.Frame(window, width=300, height=400, bg="grey")
frame.pack(pady=20)

enc_button = tk.Button(frame, text="Encrytp File!", width=10, height=2, bg="red", fg="white",
                       font=("Helvetica", 12, "bold"), relief=tk.RAISED, command=encrypt_window)
enc_button.pack(padx=50, pady=10)

dec_button = tk.Button(frame, text="Decrypt File!", width=10, height=2, bg="red", fg="white",
                       font=("Helvetica", 12, "bold"), relief=tk.RAISED, command=dec_window)
dec_button.pack(padx=50, pady=10)

window.mainloop()
