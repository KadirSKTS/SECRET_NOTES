from tkinter import *
from tkinter import messagebox

from PIL import Image, ImageTk
from cryptography.fernet import Fernet

FONT = ("arial", 17, "normal")

parola_list = []

ciphertext = ""

window = Tk()
window.minsize(width=400, height=670)
window.config(bg="white")
window.title("SECRET NOTES")

image = Image.open('Top-Secret-Logo.jpg')
image = image.resize((90, 90), Image.LANCZOS)
display = ImageTk.PhotoImage(image)
label_png = Label(window, image=display, bd=0)
label_png.pack()

# TİTLE LABEL
title_label = Label(text="Enter Your Title", font=FONT, bg="white", padx=10, pady=10)
title_label.pack()

# TİTLE ENTRY
enter_title = Entry(width=25)
enter_title.pack()

# SECRET LABEL
secret_label = Label(text="Enter Your Secret", font=FONT, bg="white", padx=10, pady=10)
secret_label.pack()

# SECRET TEXT
secret_text = Text(width=29, height=15)
secret_text.pack()

# MASTER KEY LABEL
master_key_label = Label(text="Enter Master Key", font=FONT, bg="white", padx=10, pady=10)
master_key_label.pack()

# MASTER KEY ENTRY
master_key_entry = Entry(width=25)
master_key_entry.pack()

def Save_and_Encrypt():
    global fernet
    global ciphertext

    with open("my_secret.txt", "a") as secret:
        secret.write(enter_title.get())
        secret.write("\n")

    key = Fernet.generate_key()
    fernet = Fernet(key)

    plaintext = secret_text.get("1.0", END).encode()
    ciphertext = fernet.encrypt(plaintext)

    with open("my_secret.txt", "a") as secret:
        secret.write(ciphertext.decode())
        secret.write("\n\n")

    secret_text.delete("1.0", END)
    master_key_entry.delete(0, END)
    enter_title.delete(0, END)


def Decrypt():
    global parola_list
    global ciphertext

    if master_key_entry.get() in  parola_list:
        if ciphertext:
            decrypted_text = fernet.decrypt(ciphertext)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_text)
        else:
            messagebox.showerror("Error", "No encrypted text found")
    else:
        messagebox.showerror("Error", "Incorrect Master Key")

   # parola_list.clear()

def password_kontrol():
    global parola_list
    parola_list.append(master_key_entry.get())

    Decrypt()

encrypt_button = Button(text="Save & Encrypt", font=("arial", 8, "normal"), bg="white", padx=10, pady=10, command=Save_and_Encrypt)
encrypt_button.config(height=0)
encrypt_button.pack()

decrypt_button = Button(text="Decrypt", font=("arial", 8, "normal"), bg="white", padx=10, pady=10, command=password_kontrol)
decrypt_button.config(height=0)
decrypt_button.pack()

master_key_entry.bind('<Return>', lambda event: password_kontrol())

window.mainloop()
