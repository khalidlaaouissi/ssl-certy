import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk, Text, Button
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from collections import namedtuple
from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto
import webbrowser
import idna

# Configure the window
window = tk.Tk()
window.title(" SSL Certy - All in One ")
window.configure(bg="#d1c9bf")  # Set a vintage-style background color

# Set the title label
title_label = tk.Label(window, text=" SSL Certy - All in On ", font=("Arial", 16), bg="#d1c9bf", pady=15)
title_label.pack()

# Define the CertificateDetails namedtuple
CertificateDetails = namedtuple("CertificateDetails", ["subject_name", "issuer_name", "validity", "fingerprint"])

# Certificate Verification Section
def verify_ssl_certificate():
    method_window = tk.Toplevel()
    method_window.title("Verification Method")
    method_window.geometry("300x150")
    method_window.configure(bg="#eaf2f8")  # Set the background color

    def verify_with_file():
        method_window.destroy()
        pem_path = filedialog.askopenfilename(title="Select SSL Certificate (.pem) file")

        try:
            with open(pem_path, "rb") as pem_file:
                pem_data = pem_file.read()

            cert = load_pem_x509_certificate(pem_data)
            details = get_certificate_details(cert)
            show_certificate_details(details)

        except FileNotFoundError:
            messagebox.showerror("Certificate Verification", "File not found.")

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            error_code = repr(e)
            messagebox.showerror("Certificate Verification", error_message)
            window.clipboard_clear()
            window.clipboard_append(error_code)

    def verify_with_url():
        method_window.destroy()
        url = simpledialog.askstring("Certificate Verification", "Enter URL to verify SSL certificate:")

        try:
            cert = get_server_certificate(url)
            details = get_certificate_details(cert)
            show_certificate_details(details)

        except socket.gaierror:
            messagebox.showerror("Certificate Verification", "Invalid URL or connection error.")

        except ssl.SSLError as e:
            error_message = f"SSL error occurred: {str(e)}"
            error_code = repr(e)
            messagebox.showerror("Certificate Verification", error_message)
            window.clipboard_clear()
            window.clipboard_append(error_code)

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            error_code = repr(e)
            messagebox.showerror("Certificate Verification", error_message)
            window.clipboard_clear()
            window.clipboard_append(error_code)

    def get_certificate_details(cert: "X509 Certificate") -> CertificateDetails:
        subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        valid_from = cert.not_valid_before
        valid_to = cert.not_valid_after
        validity = f"{valid_from} to {valid_to}"
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        return CertificateDetails(subject_name=subject, issuer_name=issuer, validity=validity, fingerprint=fingerprint)

    def show_certificate_details(details: CertificateDetails):
        details_window = tk.Toplevel()
        details_window.title("Certificate Details")
        details_window.geometry("500x300")
        details_window.configure(bg="#eaf2f8")  # Set the background color

        text_widget = Text(details_window, wrap="word", height=20, width=60)
        text_widget.insert(tk.END, f"Subject Name: {details.subject_name}\n")
        text_widget.insert(tk.END, f"Issuer Name: {details.issuer_name}\n")
        text_widget.insert(tk.END, f"Validity: {details.validity}\n")
        text_widget.insert(tk.END, f"Fingerprint: {details.fingerprint}\n")
        text_widget.pack()

        def copy_to_clipboard():
            if text_widget.tag_ranges("sel"):
                selected_text = text_widget.get("sel.first", "sel.last")
                window.clipboard_clear()
                window.clipboard_append(selected_text)
                messagebox.showinfo("Text Copied", "The selected text has been copied to the clipboard.")
            else:
                messagebox.showwarning("No Selection", "No text is selected.")

        copy_button = Button(details_window, text="Copy", command=copy_to_clipboard)
        copy_button.pack(pady=15)

    def get_server_certificate(url: str) -> "X509 Certificate":
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.split(":")[0]  # Extract the hostname from the URL

        # Convert the hostname to ASCII representation
        hostname = idna.encode(hostname).decode("ascii")

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as s:
                cert_pem = ssl.get_server_certificate((hostname, 443))

        cert = load_pem_x509_certificate(cert_pem.encode())
        return cert

    file_button = Button(method_window, text="Upload SSL Certificate File", command=verify_with_file)
    file_button.pack(pady=15)

    url_button = Button(method_window, text="Enter URL to Verify Certificate", command=verify_with_url)
    url_button.pack(pady=15)

verify_button = tk.Button(window, text="Verify SSL Certificate", command=verify_ssl_certificate, bg="#bfad9f", fg="white", relief=tk.FLAT)
verify_button.pack(pady=15)

# Certificate Generation Section
def generate_ssl_certificate():
    generation_window = tk.Toplevel()
    generation_window.title("Generate SSL Certificate")
    generation_window.geometry("400x600")
    generation_window.configure(bg="#e4e4e4")  # Set the background color

    label_key_size = tk.Label(generation_window, text="Key Size (bits):", bg="#eaf2f8")
    label_key_size.pack(pady=15)
    key_size_entry = ttk.Combobox(generation_window, values=["2048", "4096", "8192"])
    key_size_entry.current(0)  # Set the default key size selection
    key_size_entry.pack(pady=15)

    label_common_name = tk.Label(generation_window, text="Common Name:", bg="#eaf2f8")
    label_common_name.pack(pady=15)
    common_name_entry = tk.Entry(generation_window)
    common_name_entry.pack(pady=15)

    #label_serial_number = tk.Label(generation_window, text="Serial Number:", bg="#eaf2f8")
    #label_serial_number.pack(pady=15)
    #serial_number_entry = tk.Entry(generation_window)
    #serial_number_entry.insert(tk.END, "1000")  # Set a default serial number
    #serial_number_entry.pack(pady=15)

    label_validity_period = tk.Label(generation_window, text="Validity Period (days):", bg="#eaf2f8")
    label_validity_period.pack(pady=15)
    validity_period_entry = tk.Entry(generation_window)
    validity_period_entry.insert(tk.END, "365")  # Set a default validity period (365 days)
    validity_period_entry.pack(pady=15)

    label_hash_algorithm = tk.Label(generation_window, text="Hash Algorithm:", bg="#eaf2f8")
    label_hash_algorithm.pack(pady=15)
    hash_algorithm_combo = ttk.Combobox(generation_window, values=["sha256", "sha384", "sha512"])
    hash_algorithm_combo.current(0)  # Set the default hash algorithm selection
    hash_algorithm_combo.pack(pady=15)

    def get_hash_algorithm(hash_algorithm):
        if hash_algorithm == "sha384":
            return "sha384"
        elif hash_algorithm == "sha512":
            return "sha512"
        else:
            return "sha256"

    def submit_certificate():
        key_size = int(key_size_entry.get())  # Get the selected key size
        common_name = common_name_entry.get()  # Get the entered common name
        #serial_number = serial_number_entry.get()  # Get the entered serial number
        validity_period = int(validity_period_entry.get()) * 24 * 60 * 60  # Get the entered validity period in days
        hash_algorithm = hash_algorithm_combo.get()  # Get the selected hash algorithm

        # Create a new private key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, key_size)

        # Check if the common name contains special characters
        if any(char in common_name for char in ("/", "\\")):
            messagebox.showerror("Certificate Generation", "Invalid Common Name. The Common Name should not contain slashes (/).")
            return

        # Create a new self-signed certificate
        cert = crypto.X509()
        cert.get_subject().CN = common_name
        #cert.set_serial_number(int(serial_number))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validity_period)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, get_hash_algorithm(hash_algorithm))

        # Open a file dialog to save the certificate as a .pem file
        file_path = filedialog.asksaveasfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            if not file_path.lower().endswith(".pem"):
                file_path += ".pem"

            try:
                # Export the certificate as a .pem file
                with open(file_path, "wb") as pem_file:
                    pem_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
                messagebox.showinfo("Certificate Generation", f"Certificate exported as: {file_path}")

            except IOError as e:
                messagebox.showerror("Certificate Generation", f"An error occurred while exporting the certificate: {str(e)}")

    generate_button = tk.Button(generation_window, text="Generate", command=submit_certificate, bg="#2196f3", fg="white")
    generate_button.pack(pady=15)

# Generate Certificate Section
generate_button = tk.Button(window, text="Generate SSL Certificate", command=generate_ssl_certificate, bg="#3b83bd", fg="white", relief=tk.FLAT)
generate_button.pack(pady=15)
# Frame for LinkedIn and GitHub buttons
button_frame = tk.Frame(window, bg="#d1c9bf")
button_frame.pack(pady=10)
# LinkedIn Button
def open_linkedin():
    webbrowser.open("https://www.linkedin.com/in/laaouissikh/")  # Replace with your LinkedIn profile URL

linkedin_button = tk.Button(button_frame, text="LinkedIn", command=open_linkedin, bg="#000088", fg="white", relief=tk.RAISED)
linkedin_button.pack(side=tk.RIGHT, padx=5)

# GitHub Button
def open_github():
    webbrowser.open("https://github.com/khalidmarquis")  # Replace with your GitHub profile URL

github_button = tk.Button(button_frame, text="GitHub", command=open_github, bg="#0a0a0a", fg="white", relief=tk.RAISED)
github_button.pack(side=tk.LEFT, padx=5)
# Set the copyright notice
copyright_label = tk.Label(window, text="Author: Khalid Laaoussi © .", font=("Arial", 10), bg="#d1c9bf", pady=15)
copyright_label.pack()

# Start the Tkinter event loop
window.mainloop()