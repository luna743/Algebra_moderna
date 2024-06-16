import gnupg
import hashlib
import os
import requests
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox, filedialog

# Initialize GnuPG instance
gpg = gnupg.GPG(gnupghome='C:\\Users\\32917\\AppData\\Roaming\\gnupg', gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')
gpg.encoding = 'utf-8'

# Define users and their GnuPG key IDs and passwords 
users = {
    "user1": {"keyid": "3ED074E1F607B0616437C9B0C42C92A0DD3874E1", "password": "password1"},
    "user2": {"keyid": "15890EB8AE0A854014A522B35676BD726CF39EF3", "password": "password2"},
    "user3": {"keyid": "BC2A04A38379F0B513CE56C78CA2CCAB7A1F3629", "password": "password3"},
    "user4": {"keyid": "6254DF66B55776B8E75665D4F929BD6B6BC1786A", "password": "password4"},
    "user5": {"keyid": "DD425664BCFA7CABFD095B054A51FCDC0536460F", "password": "password5"},
}
#seria un base de datos ya generado de usuarios diferentes.
database_path = r'C:\\Users\\32917\\python\\semestre 5\\bloque 3'

def download_pdf(url, local_filename):
    """Download a PDF from a URL."""
    response = requests.get(url)
    response.raise_for_status()
    with open(local_filename, 'wb') as f:
        f.write(response.content)
    return local_filename

def hash_file(filename):
    """Create a SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def sign_pdf(user, pdf_path, database_path, login_time):
    """Sign the PDF with the user's key and save the signature to the database."""
    if user in users:
        try:
            file_hash = hash_file(pdf_path)
            print(f"Hash of the file: {file_hash}")
            
            # Sign data with GPG
            signed_data = gpg.sign(file_hash, detach=True, keyid=users[user]["keyid"], passphrase=users[user]["password"], extra_args=['--pinentry-mode', 'loopback'])
            
            if signed_data:
                document_name = os.path.basename(pdf_path)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Format the signature into a multi-line string
                signature_formatted = signed_data.data.decode('utf-8').strip()
                
                # Construct the signature record with the formatted signature
                signature_record = f"{user}, {timestamp}, {document_name}, {file_hash}, \n{signature_formatted}\n"
                
                # Paths for user activities and database records
                user_activity_path = os.path.join(database_path, f"{user}_activities.txt")
                database_file_path = os.path.join(database_path, "firmas.txt")
                
                # Log user activity
                with open(user_activity_path, "a") as activity_file:
                    activity_file.write(f"{login_time} - {timestamp}: {user} signed {document_name}\n")
                
                # Write the signature record to the database
                with open(database_file_path, "a") as db_file:
                    db_file.write(signature_record)
                
                print(f"Document signed by {user}. Signature and activity saved to {database_path}.")
                messagebox.showinfo("Success", "Document signed successfully.")
            else:
                print(f"Failed to sign document with user {user}'s key. Check your password or file permissions.")
                messagebox.showerror("Error", "Failed to sign document. Check your password or file permissions.")
        except Exception as e:
            print(f"An error occurred while signing the document: {e}")
            messagebox.showerror("Error", f"An error occurred while signing the document: {e}")
    else:
        print("User not recognized.")
        messagebox.showerror("Error", "User not recognized.")

def check_if_signed(pdf_path, database_path):
    """Check if a PDF is already signed and return the details."""
    file_hash = hash_file(pdf_path)
    database_file_path = os.path.join(database_path, "firmas.txt")
    try:
        with open(database_file_path, "r") as db_file:
            records = db_file.read().split('\n-----END PGP SIGNATURE-----')
            for record in records:
                if record.strip():  # Ensure the record is not empty
                    parts = record.strip().split(', ')
                    if len(parts) >= 4:  # Ensure that there are enough parts to form a record
                        user, timestamp, document_name, stored_hash = parts[:4]
                        if stored_hash == file_hash:
                            return True, f"{document_name} was signed by {user} on {timestamp}"
    except FileNotFoundError:
        print("Database file not found.")
        messagebox.showerror("Error", "Database file not found.")
    return False, "Document is not signed."

def check_last_activity(user, database_path):
    """Check the last activity time of a user and return True if it's more than a month."""
    user_activity_path = os.path.join(database_path, f"{user}_activities.txt")
    try:
        with open(user_activity_path, "r") as activity_file:
            lines = activity_file.readlines()
            if lines:
                # Extract the last line and get the last activity time
                last_activity = lines[-1].split(" - ")[0]
                last_activity_time = datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S')
                
                if datetime.now() - last_activity_time > timedelta(days=30):
                    # More than a month since last activity
                    return True
    except FileNotFoundError:
        # No activity file exists, this might be a new user
        print("No previous activity detected, proceeding as new user.")
    return False

def login():
    user = user_entry.get()
    if user in users:
        if check_last_activity(user, database_path):
            messagebox.showwarning("Inactive", "Your account has been inactive for more than a month. Please contact the administrator to reactivate your account.")
            return
        
        password = password_entry.get()
        if password == users[user]["password"]:
            login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            show_main_menu(user, login_time)
        else:
            messagebox.showerror("Error", "Incorrect password")
    else:
        messagebox.showerror("Error", "User not recognized")

def show_main_menu(user, login_time):
    main_menu = tk.Toplevel(root)
    main_menu.title("Main Menu")

    tk.Label(main_menu, text="Select an option:").pack()

    def option_1():
        pdf_path = filedialog.askopenfilename()
        if pdf_path:
            is_signed, message = check_if_signed(pdf_path, database_path)
            if is_signed:
                messagebox.showinfo("Info", message)
            else:
                sign_pdf(user, pdf_path, database_path, login_time)
        main_menu.destroy()

    def option_2():
        def download_and_sign():
            pdf_url = url_entry.get()
            pdf_path = download_pdf(pdf_url, 'temp_downloaded.pdf')
            is_signed, message = check_if_signed(pdf_path, database_path)
            if is_signed:
                messagebox.showinfo("Info", message)
            else:
                sign_pdf(user, pdf_path, database_path, login_time)
            os.remove(pdf_path)
            download_window.destroy()

        download_window = tk.Toplevel(main_menu)
        download_window.title("Download PDF")
        
        tk.Label(download_window, text="Enter PDF URL:").pack()
        url_entry = tk.Entry(download_window)
        url_entry.pack()
        tk.Button(download_window, text="Download and Sign", command=download_and_sign).pack()

    def option_3():
        pdf_path = filedialog.askopenfilename()
        if pdf_path:
            is_signed, message = check_if_signed(pdf_path, database_path)
            messagebox.showinfo("Info", message)
        main_menu.destroy()

    tk.Button(main_menu, text="1. Provide a local file path for signing", command=option_1).pack()
    tk.Button(main_menu, text="2. Provide a URL to download and sign the PDF", command=option_2).pack()
    tk.Button(main_menu, text="3. Check if a PDF is already signed", command=option_3).pack()

    def logout():
        logout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user_activity_path = os.path.join(database_path, f"{user}_activities.txt")
        with open(user_activity_path, "a") as activity_file:
            activity_file.write(f"{login_time} - {logout_time}: {user} session ended.\n")
        main_menu.destroy()

    main_menu.protocol("WM_DELETE_WINDOW", logout)

# Initialize the main GUI window
root = tk.Tk()
root.title("Login")

tk.Label(root, text="Username:").grid(row=0)
tk.Label(root, text="Password:").grid(row=1)

user_entry = tk.Entry(root)
password_entry = tk.Entry(root, show="*")

user_entry.grid(row=0, column=1)
password_entry.grid(row=1, column=1)

tk.Button(root, text="Login", command=login).grid(row=2, column=1)

root.mainloop()


