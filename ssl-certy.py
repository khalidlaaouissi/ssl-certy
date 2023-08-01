from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import ssl
import socket
from urllib.parse import urlparse
from collections import namedtuple
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from OpenSSL import crypto
import webbrowser
import idna

# Configure the window
window = tk.Tk()
window.title("SSL Certy - All in One")
window.geometry("400x350")
window.configure(bg="#d1c9bf")  # Set a vintage-style background color

# Set the title label
title_label = tk.Label(window, text="SSL Certy - All in One", font=("Arial", 16), bg="#d1c9bf", pady=15)
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
        details_window.geometry("500x500")
        details_window.configure(bg="#eaf2f8")  # Set the background color

        text_widget = tk.Text(details_window, wrap="word", height=20, width=60)
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

        copy_button = tk.Button(details_window, text="Copy", command=copy_to_clipboard)
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

    file_button = tk.Button(method_window, text="Upload SSL Certificate File", command=verify_with_file)
    file_button.pack(pady=15)

    url_button = tk.Button(method_window, text="Enter URL to Verify Certificate", command=verify_with_url)
    url_button.pack(pady=15)

verify_button = tk.Button(window, text="Verify SSL Certificate", command=verify_ssl_certificate, bg="#bfad9f", fg="white", relief=tk.FLAT)
verify_button.pack(pady=15)

# Helper function to get an attribute value or return an empty string if not present
def get_attribute_or_empty_string(cert, oid):
    attributes = cert.subject.get_attributes_for_oid(oid)
    return attributes[0].value if attributes else ""

# Function for generating the private key
def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
# Global variables for entry fields
country_entry = None
state_entry = None
locality_entry = None
organization_entry = None
common_name_entry = None
key_size_entry = None  # Add this line
# Function for creating a generic subject name
def create_generic_subject_name(country, state, locality, organization, common_name, email):
    return x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email),
    ])
# Certificate Generation Section
def generate_ssl_certificate():
    global country_entry, state_entry, locality_entry, organization_entry, common_name_entry, email_entry,  key_size_entry

    generation_window = tk.Toplevel()
    generation_window.title("Generate SSL Certificate")
    generation_window.geometry("400x800")
    generation_window.configure(bg="#e4e4e4")  # Set the background color

    country_label = tk.Label(generation_window, text="Country Name:", bg="#eaf2f8")
    country_label.pack(pady=10)
    country_entry = tk.Entry(generation_window)
    country_entry.pack(pady=5)

    state_label = tk.Label(generation_window, text="State/Province Name:", bg="#eaf2f8")
    state_label.pack(pady=10)
    state_entry = tk.Entry(generation_window)
    state_entry.pack(pady=5)

    locality_label = tk.Label(generation_window, text="Locality Name:", bg="#eaf2f8")
    locality_label.pack(pady=10)
    locality_entry = tk.Entry(generation_window)
    locality_entry.pack(pady=5)

    organization_label = tk.Label(generation_window, text="Organization Name:", bg="#eaf2f8")
    organization_label.pack(pady=10)
    organization_entry = tk.Entry(generation_window)
    organization_entry.pack(pady=5)

    common_name_label = tk.Label(generation_window, text="Common Name:", bg="#eaf2f8")
    common_name_label.pack(pady=10)
    common_name_entry = tk.Entry(generation_window)
    common_name_entry.pack(pady=5)

    email_label = tk.Label(generation_window, text="Email Address:", bg="#eaf2f8")
    email_label.pack(pady=10)
    email_entry = tk.Entry(generation_window)
    email_entry.pack(pady=5)

    label_key_size = tk.Label(generation_window, text="Key Size (bits):", bg="#eaf2f8")
    label_key_size.pack(pady=15)
    key_size_entry = ttk.Combobox(generation_window, values=["2048", "4096", "8192"])
    key_size_entry.current(0)  # Set the default key size selection
    key_size_entry.pack(pady=15)

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
        # Get the subject name attributes from the entry widgets
        country = country_entry.get()
        state = state_entry.get()
        locality = locality_entry.get()
        organization = organization_entry.get()
        common_name = common_name_entry.get()
        email = email_entry.get()

        key_size = int(key_size_entry.get())  # Get the key size from the entry widget
        validity_period = int(validity_period_entry.get())  # Get the validity period from the entry widget

        # Create a new private key
        private_key = generate_private_key()

        # Get the subject name
        subject_name = create_generic_subject_name(country, state, locality, organization, common_name, email)

        # Create a new self-signed certificate using the private key
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject_name)
        builder = builder.issuer_name(subject_name)  # Self-signed certificate, so issuer is the same as subject
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=validity_period))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())
        builder = builder.sign(private_key, hashes.SHA256(), default_backend())

        # Open a file dialog to save the certificate as a .pem file
        cert_file_path = filedialog.asksaveasfilename(filetypes=[("PEM files", "*.pem")])
        if cert_file_path:
            if not cert_file_path.lower().endswith(".pem"):
                cert_file_path+= ".pem"

            key_file_path = cert_file_path.replace(".pem", "_private_key.pem")

            try:
                # Export the certificate as a .pem file
                with open(cert_file_path, "wb") as pem_file:
                    pem_file.write(builder.public_bytes(Encoding.PEM))

                # Export the private key as a .pem file
                with open(key_file_path, "wb") as key_file:
                    key_file.write(private_key.private_bytes(
                        Encoding.PEM,
                        PrivateFormat.PKCS8,
                        NoEncryption()
                    ))
                
                messagebox.showinfo("Certificate Generation", f"Certificate and private key exported as: {cert_file_path} and {key_file_path}")
                
            except IOError as e:
                messagebox.showerror("Certificate Generation", f"An error occurred while exporting the certificate: {str(e)}")
            except Exception as e:
                # Handle any other errors that may occur during certificate generation
                error_message = f"An error occurred: {str(e)}"
                error_code = repr(e)
                messagebox.showerror("Certificate Generation", error_message)
                window.clipboard_clear()
                window.clipboard_append(error_code)

    generate_button = tk.Button(generation_window, text="Generate", command=submit_certificate, bg="#2196f3", fg="white")
    generate_button.pack(pady=15)

# Generate Certificate Section
generate_button = tk.Button(window, text="Generate SSL Certificate", command=generate_ssl_certificate, bg="#3b83bd", fg="white", relief=tk.FLAT)
generate_button.pack(pady=15)

# Certificate Renewal Section
def choose_cert_file():
    root = tk.Tk()
    root.withdraw()
    cert_file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    return cert_file_path

# Helper function to get an attribute value or return an empty string if not present
def get_attribute_or_empty_string(cert, oid):
    attributes = cert.subject.get_attributes_for_oid(oid)
    return attributes[0].value if attributes else ""

# Function for renewing the certificate
def renew_certificate():
    cert_file_path = choose_cert_file()
    if not cert_file_path:
        return  # User canceled the file selection

    # Create a new window for the certificate renewal
    renewal_window = tk.Toplevel()
    renewal_window.title("Renew SSL Certificate")
    renewal_window.geometry("400x150")
    renewal_window.configure(bg="#e4e4e4")  # Set the background color

    # Function to toggle the visibility of the validity days entry widget
    def toggle_validity_days():
        if validity_days_entry.winfo_ismapped():
            validity_days_label.pack_forget()
            validity_days_entry.pack_forget()
        else:
            validity_days_label.pack(pady=10)
            validity_days_entry.pack()

    # Create the entry widget for specifying the number of days
    validity_days_label = tk.Label(renewal_window, text="Number of Days to Add:")
    validity_days_label.pack(pady=10)

    validity_days_entry = tk.Entry(renewal_window)
    validity_days_entry.pack()

    # Function to renew the SSL certificate
    def renew_ssl_certificate():
        try:
            # Get the number of days to add from the validity_days_entry widget
            validity_days = int(validity_days_entry.get())

            # Load the existing certificate
            with open(cert_file_path, "rb") as cert_file:
                cert_data = cert_file.read()

            # Parse the existing certificate
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Get the subject name attributes from the certificate
            country = get_attribute_or_empty_string(cert, x509.NameOID.COUNTRY_NAME)
            state = get_attribute_or_empty_string(cert, x509.NameOID.STATE_OR_PROVINCE_NAME)
            locality = get_attribute_or_empty_string(cert, x509.NameOID.LOCALITY_NAME)
            organization = get_attribute_or_empty_string(cert, x509.NameOID.ORGANIZATION_NAME)
            common_name = get_attribute_or_empty_string(cert, x509.NameOID.COMMON_NAME)
            email = get_attribute_or_empty_string(cert, x509.NameOID.EMAIL_ADDRESS)

            subject_name = create_generic_subject_name(country, state, locality, organization, common_name, email)
            
            # Create a new private key
            private_key = generate_private_key()

            # Create a new self-signed certificate
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject_name)
            builder = builder.issuer_name(cert.issuer)
            builder = builder.not_valid_before(datetime.utcnow())
            builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(private_key.public_key())
            builder = builder.sign(private_key, hashes.SHA256(), default_backend())

            # Ask the user to choose the file path to save the new certificate
            new_cert_file_path = filedialog.asksaveasfilename(filetypes=[("PEM Files", "*.pem")])

            if new_cert_file_path:

                if not new_cert_file_path.lower().endswith(".pem"):
                    new_cert_file_path += ".pem"

                key_file_path = new_cert_file_path.replace(".pem", "_private_key.pem")

                try:
                    # Export the new certificate as a .pem file
                    with open(new_cert_file_path, "wb") as new_cert_file:
                         new_cert_file.write(builder.public_bytes(Encoding.PEM))
                    
                    # Export the new private key as a .pem file
                    with open(key_file_path, "wb") as key_file:
                        key_file.write(private_key.private_bytes(
                            Encoding.PEM,
                            PrivateFormat.PKCS8,
                            NoEncryption()
                        ))

                    messagebox.showinfo("Certificate Renewal", f"New certificate saved as: {new_cert_file_path}")

                except IOError as e:
                    messagebox.showerror("Certificate Renewal", f"An error occurred while exporting the certificate: {str(e)}")
                except Exception as e:
             # Handle any other errors that may occur during certificate renewal
                    messagebox.showerror("Error", f"Failed to renew the certificate:\n{e}")
                    error_message = f"An error occurred: {str(e)}"
                    error_code = repr(e)
                    window.clipboard_clear()
                    window.clipboard_append(error_code)
        # Close the renewal window after successful renewal
            renewal_window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to renew the certificate:\n{e}")
            error_message = f"An error occurred: {str(e)}"
            error_code = repr(e)
            window.clipboard_clear()
            window.clipboard_append(error_code)

    renew_button = tk.Button(renewal_window, text="Renew Certificate", command=renew_ssl_certificate, bg="#87a96b", fg="white", relief=tk.FLAT)
    renew_button.pack(pady=15)

# Add the "Renew Certificate" button to the main menu
renew_button = tk.Button(window, text="Renew Certificate", command=renew_certificate, bg="#87a96b", fg="white", relief=tk.FLAT)
renew_button.pack(pady=15)
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        window.destroy()
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
copyright_label = tk.Label(window, text="Version 0.2", font=("Arial", 10), bg="#d1c9bf", pady=15)
copyright_label.pack()
# Function to handle the About menu option
def show_about():
    about_message = "SSL Certy - All in One\nVersion 0.2\n\nA simple tool for SSL certificate operations:\n- Verify SSL certificates from files or URLs\n- Generate self-signed SSL certificates\n- Renew SSL certificates\n\nAuthor: Khalid Laaouissi"
    messagebox.showinfo("About SSL Certy", about_message)

# Menu Bar
menu_bar = tk.Menu(window)
window.config(menu=menu_bar)

# File Menu
file_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Exit", command=window.quit)

# Help Menu
help_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="About", command=show_about)

# Bind the window closing event to the on_closing function
window.protocol("WM_DELETE_WINDOW", window.quit)

# Start the Tkinter event loop
window.mainloop()