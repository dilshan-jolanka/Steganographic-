import streamlit as st
import numpy as np
from PIL import Image
import io
import base64
import hashlib
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timezone
import time
import random
import zipfile
import mimetypes

# Set page configuration - THIS MUST BE THE FIRST STREAMLIT COMMAND
st.set_page_config(
    page_title="CLASSIFIED - FBI Steganography System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add pyzipper for secure ZIP encryption - AFTER page config
try:
    import pyzipper  # You may need to install this with pip install pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False
    st.warning("For full ZIP password protection, please install the pyzipper library.")
# Custom CSS for FBI-themed styling with image size fixes
st.markdown("""
<style>
    /* Main theme colors - FBI inspired */
    :root {
        --primary: #001F54;       /* Dark blue */
        --secondary: #0A3161;     /* Navy blue */
        --accent: #D00000;        /* FBI red */
        --text: #FFFFFF;          /* White */
        --background: #000000;    /* Black */
        --panel: #0F1B2B;         /* Dark blue-gray */
        --success: #00843D;       /* Green */
        --warning: #F7B801;       /* Amber */
        --error: #BF0A30;         /* Red */
        --highlight: #00843D;     /* Green highlight */
    }
    
    /* Override Streamlit's default styling for dark mode */
    .stApp {
        background-color: var(--background);
        color: var(--text);
    }
    
    /* Main header styling */
    .main-header {
        color: var(--text);
        font-size: 2.5rem !important;
        font-weight: 700 !important;
        text-align: center;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 0 !important;
    }
    
    /* FBI badge/seal */
    .fbi-badge {
        text-align: center;
        margin-bottom: 0.5rem;
    }
    
    /* Classification banner */
    .classification-banner {
        background-color: var(--accent);
        color: var(--text);
        text-align: center;
        padding: 5px 0;
        font-weight: bold;
        margin: 10px 0 20px 0;
        text-transform: uppercase;
        letter-spacing: 3px;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.8; }
        100% { opacity: 1; }
    }
    
    /* Subheader styling */
    .sub-header {
        color: var(--text);
        font-size: 1.2rem !important;
        font-weight: 400 !important;
        opacity: 0.8;
        text-align: center;
        margin-bottom: 1.5rem !important;
        text-transform: uppercase;
    }
    
    /* Section styling */
    .section-header {
        color: var(--text);
        font-size: 1.5rem !important;
        font-weight: 600 !important;
        margin-top: 1rem !important;
        border-bottom: 2px solid var(--accent);
        padding-bottom: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Card styling - FBI terminal look */
    .stcard {
        background-color: var(--panel);
        border: 1px solid #1a2c42;
        border-radius: 5px;
        padding: 20px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
        margin-bottom: 20px;
    }
    
    /* Button styling override - FBI style */
    .stButton>button {
        background-color: var(--secondary);
        color: white;
        font-weight: 600;
        border-radius: 3px;
        border: 1px solid #0A3161;
        padding: 0.5rem 1rem;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .stButton>button:hover {
        background-color: var(--accent);
        border-color: var(--accent);
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }
    
    /* Success message */
    .success-box {
        background-color: rgba(0, 132, 61, 0.2);
        border-left: 5px solid var(--success);
        padding: 10px 15px;
        border-radius: 3px;
        margin: 1rem 0;
    }
    
    /* Warning message */
    .warning-box {
        background-color: rgba(247, 184, 1, 0.2);
        border-left: 5px solid var(--warning);
        padding: 10px 15px;
        border-radius: 3px;
        margin: 1rem 0;
    }

    /* Critical warning message */
    .critical-warning-box {
        background-color: rgba(191, 10, 48, 0.2);
        border-left: 5px solid var(--error);
        padding: 10px 15px;
        border-radius: 3px;
        margin: 1rem 0;
    }
    
    /* Info box in sidebar */
    .info-box {
        background-color: rgba(10, 49, 97, 0.4);
        border: 1px solid rgba(10, 49, 97, 0.8);
        border-radius: 3px;
        padding: 15px;
        margin-bottom: 15px;
    }
    
    /* Terminal-like text areas */
    textarea {
        background-color: #0a192f !important;
        color: #7df9ff !important;
        font-family: 'Courier New', monospace !important;
        border: 1px solid #1a365d !important;
    }
    
    /* Input fields - terminal style */
    .stTextInput>div>div>input {
        background-color: #0a192f;
        color: #7df9ff;
        font-family: 'Courier New', monospace;
        border: 1px solid #1a365d;
    }
    
    /* Footer styling */
    .footer {
        text-align: center;
        margin-top: 3rem;
        padding-top: 1rem;
        border-top: 1px solid #1a365d;
        color: #607d8b;
        font-size: 0.8rem;
    }
    
    /* Terminal blinking cursor */
    .terminal-cursor {
        display: inline-block;
        width: 8px;
        height: 15px;
        background-color: #7df9ff;
        animation: blink 1s step-end infinite;
        margin-left: 2px;
    }
    @keyframes blink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0; }
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
        background-color: var(--panel);
        padding: 5px 5px 0 5px;
        border-radius: 5px 5px 0 0;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #0A3161;
        border-radius: 4px 4px 0 0;
        gap: 1px;
        padding: 10px 16px;
        color: white;
    }
    .stTabs [aria-selected="true"] {
        background-color: var(--accent) !important;
        color: white !important;
    }
    
    /* Loading animation */
    @keyframes scanner {
        0% { transform: translateY(0); background-color: rgba(0, 132, 61, 0.6); }
        50% { transform: translateY(100px); background-color: rgba(208, 0, 0, 0.6); }
        100% { transform: translateY(0); background-color: rgba(0, 132, 61, 0.6); }
    }
    .scanner-line {
        width: 100%;
        height: 2px;
        background-color: var(--highlight);
        position: relative;
        animation: scanner 2s ease-in-out infinite;
    }
    
    /* Image container with size constraints */
    .img-container {
        display: flex;
        justify-content: center;
        margin: 20px 0;
        position: relative;
        overflow: hidden;
        max-height: 350px; /* Fixed maximum height */
        text-align: center;
    }
    .img-container img {
        max-width: 100%;
        max-height: 350px; /* Fixed maximum height */
        width: auto !important;
        height: auto !important;
        object-fit: contain;
        border: 1px solid #1a365d;
        border-radius: 3px;
    }
    
    /* Streamlit image container override */
    .stImage img {
        max-height: 350px;
        width: auto !important;
        object-fit: contain !important;
    }
    
    /* For timestamp display */
    .timestamp {
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
        color: #7df9ff;
        text-align: right;
        margin-bottom: 10px;
    }
    
    /* User info display */
    .user-info {
        font-family: 'Courier New', monospace;
        background-color: rgba(10, 49, 97, 0.4);
        padding: 10px;
        border-radius: 3px;
        margin-bottom: 20px;
        border: 1px solid #1a365d;
    }
    
    /* Status indicators */
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 5px;
    }
    .status-online {
        background-color: var(--success);
        box-shadow: 0 0 5px var(--success);
    }
    
    /* Random ID generator */
    .operation-id {
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
        color: #7df9ff;
    }
    
    /* Security level indicators */
    .security-level {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 0.8rem;
        font-weight: bold;
        text-transform: uppercase;
        margin-left: 10px;
    }
    .security-top-secret {
        background-color: var(--accent);
        color: white;
    }
    
    /* System messages */
    .system-message {
        font-family: 'Courier New', monospace;
        color: #7df9ff;
        margin: 5px 0;
    }
    
    /* Progress bar override */
    .stProgress > div > div > div > div {
        background-color: var(--accent);
    }
    
    /* Fix for sidebar image size */
    .sidebar-image {
        max-width: 150px;
        margin: 0 auto;
        display: block;
    }

    /* Notification badge */
    .notification-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        background-color: var(--accent);
        color: white;
        width: 20px;
        height: 20px;
        border-radius: 50%;
        font-size: 12px;
        font-weight: bold;
        margin-left: 8px;
        animation: pulse 1s infinite;
    }

    /* Risk level indicator */
    .risk-indicator {
        display: inline-block;
        width: 15px;
        height: 15px;
        border-radius: 50%;
        margin-right: 8px;
    }
    .risk-high {
        background-color: var(--error);
        box-shadow: 0 0 5px var(--error);
    }
    .risk-medium {
        background-color: var(--warning);
        box-shadow: 0 0 5px var(--warning);
    }
    .risk-low {
        background-color: var(--success);
        box-shadow: 0 0 5px var(--success);
    }
    
    /* Platform comparison table */
    .platform-table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
    }
    .platform-table th, .platform-table td {
        padding: 8px;
        border: 1px solid #1a365d;
        text-align: left;
    }
    .platform-table th {
        background-color: rgba(10, 49, 97, 0.7);
    }
    .platform-table tr:nth-child(even) {
        background-color: rgba(10, 49, 97, 0.3);
    }
    
    /* New recommendation highlight */
    .recommendation-highlight {
        background-color: rgba(0, 132, 61, 0.15);
        border: 1px dashed var(--success);
        padding: 15px;
        border-radius: 5px;
        margin: 15px 0;
    }
    
    /* ZIP protection illustration */
    .zip-illustration {
        background-color: rgba(10, 49, 97, 0.2);
        padding: 15px;
        border-radius: 5px;
        text-align: center;
        margin: 15px 0;
    }
    
    /* Step boxes */
    .step-box {
        background-color: rgba(10, 49, 97, 0.3);
        border-left: 3px solid var(--secondary);
        padding: 10px 15px;
        margin: 8px 0;
    }
    
    /* New feature tag */
    .new-feature {
        background-color: var(--accent);
        color: white;
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 0.7rem;
        font-weight: bold;
        display: inline-block;
        margin-left: 8px;
    }

    /* Processing animation */
    .processing-animation {
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 15px 0;
    }
    .processing-dot {
        width: 12px;
        height: 12px;
        margin: 0 5px;
        background-color: var(--highlight);
        border-radius: 50%;
        animation: bounce 1.5s infinite ease-in-out;
    }
    .processing-dot:nth-child(1) { animation-delay: 0s; }
    .processing-dot:nth-child(2) { animation-delay: 0.2s; }
    .processing-dot:nth-child(3) { animation-delay: 0.4s; }
    @keyframes bounce {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-10px); }
    }
    
    /* File type icon styling */
    .file-type-icon {
        display: inline-block;
        width: 36px;
        height: 36px;
        margin-right: 10px;
        background-color: var(--panel);
        border-radius: 3px;
        text-align: center;
        line-height: 36px;
        font-weight: bold;
        font-size: 12px;
        color: white;
    }
    .file-type-zip {
        background-color: #8B5CF6;
    }
    .file-type-pdf {
        background-color: #EF4444;
    }
    .file-type-doc {
        background-color: #3B82F6;
    }
    .file-type-img {
        background-color: #10B981;
    }
    .file-type-txt {
        background-color: #F59E0B;
    }
    .file-type-other {
        background-color: #6B7280;
    }
    
    /* File details display */
    .file-details {
        display: flex;
        align-items: center;
        padding: 10px;
        background-color: rgba(10, 49, 97, 0.2);
        border-radius: 5px;
        margin-top: 10px;
    }
    .file-details-info {
        flex-grow: 1;
    }
    .file-name {
        font-weight: bold;
        margin-bottom: 2px;
    }
    .file-meta {
        font-size: 0.8rem;
        color: #A3A3A3;
    }
    
    /* Capacity bar */
    .capacity-bar-container {
        margin-top: 10px;
        background-color: rgba(255, 255, 255, 0.1);
        height: 8px;
        border-radius: 4px;
        overflow: hidden;
    }
    .capacity-bar-fill {
        height: 100%;
        border-radius: 4px;
    }
    .capacity-text {
        font-size: 0.7rem;
        margin-top: 2px;
        text-align: right;
    }
    .capacity-low {
        background-color: var(--success);
    }
    .capacity-medium {
        background-color: var(--warning);
    }
    .capacity-high {
        background-color: var(--error);
    }
</style>
""", unsafe_allow_html=True)

# Function to generate a random operation ID
def generate_operation_id():
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    numbers = "23456789"
    return f"OP-{''.join(random.choice(letters) for _ in range(3))}-{''.join(random.choice(numbers) for _ in range(4))}"

# Function to derive encryption key from password
def get_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Function to encrypt message or data with password
def encrypt_data(data, password):
    key, salt = get_key_from_password(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    # Prepend salt to the encrypted message for decryption later
    return salt + encrypted_data

# Function to decrypt message or data with password
def decrypt_data(encrypted_data, password):
    try:
        # Extract salt (first 16 bytes) and encrypted message
        salt, encrypted_message = encrypted_data[:16], encrypted_data[16:]
        
        # Get key from password and salt
        key, _ = get_key_from_password(password, salt)
        
        # Decrypt the message
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_message)
        return decrypted_data
    except Exception as e:
        st.error(f"Decryption failed: Incorrect password or invalid data")
        return None

# Improved function to create a ZIP file containing the image with password protection
def create_protected_zip(image_data, zip_password, filename="secure_package.png"):
    """Create a ZIP file containing the steganographic image with optional password protection"""
    # Create a BytesIO object to hold the ZIP file
    zip_buffer = io.BytesIO()
    
    try:
        if zip_password and HAS_PYZIPPER:
            # Use pyzipper for password-protected ZIP with AES encryption
            with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zip_file:
                zip_file.setpassword(zip_password.encode())
                zip_file.writestr(filename, image_data)
        else:
            # Use standard zipfile for non-password-protected ZIP
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr(filename, image_data)
        
        # Reset the buffer position to the beginning
        zip_buffer.seek(0)
        
        # Return the ZIP file as bytes
        return zip_buffer.getvalue()
    except Exception as e:
        st.error(f"Error creating ZIP file: {str(e)}")
        return None

# Function to extract file from a ZIP archive with password support
def extract_from_zip(zip_data, password=None):
    """Extract files from a ZIP archive with password support"""
    # Create a BytesIO object from the ZIP data
    zip_buffer = io.BytesIO(zip_data)
    
    try:
        # First try with pyzipper which supports AES encryption
        if HAS_PYZIPPER:
            try:
                with pyzipper.AESZipFile(zip_buffer) as zip_ref:
                    # Set password if provided
                    if password:
                        zip_ref.setpassword(password.encode())
                    
                    # Get list of files in the ZIP
                    file_list = zip_ref.namelist()
                    
                    # Filter for image files
                    image_files = [f for f in file_list if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
                    
                    if not image_files:
                        return None, "No image files found in the ZIP archive", None
                    
                    # Use the first image file if there's only one, otherwise let the caller handle selection
                    if len(image_files) == 1:
                        selected_file = image_files[0]
                    else:
                        return None, "Multiple images found", image_files
                    
                    # Try to extract the file
                    try:
                        file_data = zip_ref.read(selected_file)
                        return file_data, "Success", None
                    except RuntimeError as e:
                        return None, f"Error: Password may be incorrect - {str(e)}", None
            except Exception:
                # Fall back to standard zipfile if pyzipper fails
                zip_buffer.seek(0)  # Reset buffer position
        
        # Use standard zipfile as fallback
        with zipfile.ZipFile(zip_buffer) as zip_ref:
            # Get list of files in the ZIP
            file_list = zip_ref.namelist()
            
            # Filter for image files
            image_files = [f for f in file_list if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
            
            if not image_files:
                return None, "No image files found in the ZIP archive", None
            
            # Use the first image file if there's only one, otherwise let the caller handle selection
            if len(image_files) == 1:
                selected_file = image_files[0]
            else:
                return None, "Multiple images found", image_files
            
            # Try to extract the file
            try:
                # Try with password if provided
                pwd = password.encode() if password else None
                file_data = zip_ref.read(selected_file, pwd=pwd)
                return file_data, "Success", None
            except RuntimeError as e:
                return None, f"Error: Password may be incorrect - {str(e)}", None
    
    except zipfile.BadZipFile:
        return None, "Invalid ZIP file", None
    except Exception as e:
        return None, f"Error: {str(e)}", None

# Function to convert data to binary string
def data_to_binary(data):
    """Convert binary data to a string of binary digits"""
    binary = ''
    for byte in data:
        binary += format(byte, '08b')
    return binary

# Function to convert binary string back to bytes
def binary_to_data(binary):
    """Convert binary string to bytes"""
    data = bytearray()
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:  # Ensure we have a complete byte
            data.append(int(byte, 2))
    return bytes(data)

# Custom LSB steganography functions
def hide_data_in_image(image, data):
    """Hide binary data in an image using LSB steganography"""
    # Convert image to RGB mode if it's not already
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    # Convert data to binary
    binary_data = data_to_binary(data)
    
    # Add data length header (32 bits = 4 bytes to store length)
    data_length = len(binary_data)
    length_header = format(data_length, '032b')
    binary_data_with_header = length_header + binary_data
    
    # Create a copy of the image
    encoded_image = image.copy()
    width, height = image.size
    
    # Counter for binary data position
    data_index = 0
    
    # Embed the binary data into the image
    for y in range(height):
        for x in range(width):
            # If we've embedded all the data, break
            if data_index >= len(binary_data_with_header):
                break
                
            pixel = list(image.getpixel((x, y)))
            
            # Modify the least significant bit of each color channel
            for c in range(3):  # RGB channels
                if data_index < len(binary_data_with_header):
                    # Replace the LSB of this color with our data bit
                    pixel[c] = (pixel[c] & 0xFE) | int(binary_data_with_header[data_index])
                    data_index += 1
            
            # Update the pixel in the new image
            encoded_image.putpixel((x, y), tuple(pixel))
            
            # If we've embedded all the data, break
            if data_index >= len(binary_data_with_header):
                break
        
        # If we've embedded all the data, break
        if data_index >= len(binary_data_with_header):
            break
    
    # Check if we could fit the entire message
    if data_index < len(binary_data_with_header):
        raise ValueError("Image too small to hide the data")
        
    return encoded_image

def extract_data_from_image(image):
    """Extract hidden binary data from an image"""
    # Convert image to RGB mode if it's not already
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    width, height = image.size
    binary_data = ""
    
    # First, extract enough bits to determine the data length (first 32 bits)
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            
            # Extract the LSB from each color channel
            for c in range(3):  # RGB channels
                binary_data += str(pixel[c] & 1)
                
                # Once we have 32 bits, we can determine the data length
                if len(binary_data) == 32:
                    break
            
            if len(binary_data) == 32:
                break
                
        if len(binary_data) == 32:
            break
    
    # Convert the first 32 bits to an integer (data length)
    try:
        data_length = int(binary_data, 2)
    except ValueError:
        raise ValueError("Could not extract valid length header - possible data corruption")
    
    # Sanity check for data length
    if data_length <= 0 or data_length > 1000000000:  # Arbitrary upper limit
        raise ValueError("Invalid data length detected - possible data corruption")
    
    # Reset binary data to start extracting the actual data
    binary_data = ""
    bits_needed = data_length + 32  # Include the header
    
    # Now extract the actual data bits
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            
            # Extract the LSB from each color channel
            for c in range(3):  # RGB channels
                binary_data += str(pixel[c] & 1)
                
                # If we've extracted all the bits we need, stop
                if len(binary_data) >= bits_needed:
                    break
            
            if len(binary_data) >= bits_needed:
                break
                
        if len(binary_data) >= bits_needed:
            break
    
    # Skip the header and convert binary data to bytes
    data_binary = binary_data[32:bits_needed]
    extracted_data = binary_to_data(data_binary)
    
    return extracted_data

# Function to calculate maximum data capacity of an image
def calculate_capacity(image):
    """Calculate the maximum data capacity of an image in bytes"""
    width, height = image.size
    # Each pixel can store 3 bits (1 per RGB channel)
    total_bits = width * height * 3
    # Convert to bytes (8 bits per byte)
    total_bytes = total_bits // 8
    # Subtract 4 bytes for the length header
    available_bytes = total_bytes - 4
    return available_bytes

# Function to resize image if needed
def resize_image_if_needed(image, max_dimension=1024):
    """Resize image while maintaining aspect ratio if it exceeds max_dimension"""
    width, height = image.size
    
    # Check if resizing is needed
    if width > max_dimension or height > max_dimension:
        # Calculate aspect ratio
        aspect_ratio = width / height
        
        # Resize based on the larger dimension
        if width > height:
            new_width = max_dimension
            new_height = int(new_width / aspect_ratio)
        else:
            new_height = max_dimension
            new_width = int(new_height * aspect_ratio)
            
        # Resize the image
        image = image.resize((new_width, new_height), Image.LANCZOS)
        
    return image

# Initialize session states
if 'operation_id' not in st.session_state:
    st.session_state['operation_id'] = generate_operation_id()
if 'extracted_image' not in st.session_state:
    st.session_state['extracted_image'] = None
if 'zip_extraction_error' not in st.session_state:
    st.session_state['zip_extraction_error'] = None
if 'zip_file_list' not in st.session_state:
    st.session_state['zip_file_list'] = None

# Display FBI badge and classification banners
st.markdown('<div class="fbi-badge">🔰</div>', unsafe_allow_html=True)
st.markdown('<h1 class="main-header">Federal Bureau of Investigation</h1>', unsafe_allow_html=True)
st.markdown('<div class="classification-banner">TOP SECRET - CONFIDENTIAL</div>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Digital Steganography Intelligence System</p>', unsafe_allow_html=True)

# Use the provided timestamp and user login
current_time = "2025-07-16 10:44:32"  # Using the timestamp provided
user_login = "dilshan-jolanka"  # Using the provided user login

st.markdown(f"""
<div class="user-info">
    <span class="status-indicator status-online"></span> <b>AGENT:</b> {st.session_state['operation_id']} | <b>USER:</b> {user_login} | <b>UTC:</b> {current_time}
    <div class="operation-id">SECURITY CLEARANCE: <span class="security-level security-top-secret">TOP SECRET</span></div>
    <div class="timestamp">CONNECTION ESTABLISHED • SECURE CHANNEL</div>
</div>
""", unsafe_allow_html=True)

# System initialization messages
with st.expander("▶ SYSTEM LOG", expanded=False):
    log_container = st.container()
    with log_container:
        st.markdown('<div class="system-message">> Initializing secure connection...</div>', unsafe_allow_html=True)
        st.markdown('<div class="system-message">> Verifying credentials...</div>', unsafe_allow_html=True)
        st.markdown('<div class="system-message">> Encryption protocols active...</div>', unsafe_allow_html=True)
        st.markdown('<div class="system-message">> Steganographic systems online...</div>', unsafe_allow_html=True)
        st.markdown('<div class="system-message">> Session secured. Welcome Agent.</div>', unsafe_allow_html=True)

# New Feature Banner
st.markdown('<div class="recommendation-highlight">', unsafe_allow_html=True)
st.markdown('<h3>🆕 MULTI-MODE STEGANOGRAPHY <span class="new-feature">NEW</span></h3>', unsafe_allow_html=True)
st.markdown("""
We've enhanced the system with multiple data hiding options:

**1. Text Mode:** Hide text messages within images (Original functionality)
**2. File Mode:** Hide ANY file type within images (New functionality)

The system now supports hiding:
- Document files (PDF, DOCX, TXT, etc.)
- ZIP archives
- Media files
- Executable files
- Any binary data
""")
st.markdown('</div>', unsafe_allow_html=True)

# Create tabs with FBI styling
tabs = st.tabs(["🔒 **ENCODE INTELLIGENCE**", "🔑 **DECODE INTELLIGENCE**"])

# Encoding section
with tabs[0]:
    st.markdown('<h2 class="section-header">Intelligence Concealment Protocol</h2>', unsafe_allow_html=True)
    
    # Create two columns for layout
    col1, col2 = st.columns([3, 2])
    
    with col1:
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("📄 CLASSIFIED DATA INPUT")
        
        # Add option to choose between text and file
        input_type = st.radio("Select intelligence type:", ["Text Message", "File Upload"])
        
        if input_type == "Text Message":
            # Text input for the secret message (original functionality)
            st.markdown('<div class="timestamp">AUTHORIZED PERSONNEL ONLY</div>', unsafe_allow_html=True)
            secret_message = st.text_area("Enter classified intelligence:", height=150, 
                                          placeholder="Enter confidential information here...")
            
            # Prepare data for hiding
            is_file = False
            data_to_hide = secret_message.encode('utf-8') if secret_message else b""
            file_name = "classified_message.txt"
            file_type = "text/plain"
        else:
            # File uploader for binary data (new functionality)
            st.markdown('<div class="timestamp">FILE CLASSIFICATION SYSTEM</div>', unsafe_allow_html=True)
            uploaded_file = st.file_uploader("Upload classified file:", 
                                            type=None,  # Allow any file type
                                            help="Any file type can be hidden within the carrier image",
                                            key="secret_file")
            
            if uploaded_file is not None:
                # Prepare data for hiding
                is_file = True
                data_to_hide = uploaded_file.getvalue()
                file_name = uploaded_file.name
                file_type = uploaded_file.type or "application/octet-stream"
                
                # Show file details
                file_size_kb = len(data_to_hide) / 1024
                
                # Determine file icon based on file type
                file_icon = "📄"
                file_class = "file-type-other"
                
                if file_name.lower().endswith(('.zip', '.rar', '.7z')):
                    file_icon = "🗜️"
                    file_class = "file-type-zip"
                elif file_name.lower().endswith('.pdf'):
                    file_icon = "📕"
                    file_class = "file-type-pdf"
                elif file_name.lower().endswith(('.doc', '.docx')):
                    file_icon = "📘"
                    file_class = "file-type-doc"
                elif file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                    file_icon = "🖼️"
                    file_class = "file-type-img"
                elif file_name.lower().endswith('.txt'):
                    file_icon = "📝"
                    file_class = "file-type-txt"
                
                st.markdown(f"""
                <div class="file-details">
                    <div class="file-type-icon {file_class}">{file_icon}</div>
                    <div class="file-details-info">
                        <div class="file-name">{file_name}</div>
                        <div class="file-meta">{file_size_kb:.2f} KB • {file_type or "Unknown type"}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                is_file = True
                data_to_hide = b""
                file_name = None
                file_type = None
        
        # Password protection for encoding
        st.subheader("🔐 SECURITY PROTOCOLS")
        encode_password = st.text_input("Establish security key:", type="password", 
                                       help="Minimum 8 characters recommended", 
                                       placeholder="Enter high-security passphrase")
        
        confirm_password = st.text_input("Confirm security key:", type="password", 
                                         placeholder="Re-enter passphrase for verification")
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("🖼️ CARRIER IMAGE SELECTION")
        
        # File uploader for encoding
        uploaded_file = st.file_uploader("Select cover image file", 
                                         type=["png", "jpg", "jpeg"], 
                                         help="PNG format provides optimal security coverage",
                                         key="encode_uploader")
        
        if uploaded_file is not None:
            # Display the original image
            original_image = Image.open(uploaded_file)
            
            # Resize image if needed
            original_image = resize_image_if_needed(original_image)
            
            st.markdown('<div class="img-container">', unsafe_allow_html=True)
            st.image(original_image, caption="SELECTED COVER IMAGE", use_container_width=True)
            # Add scanner effect
            st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Image metadata and capacity
            width, height = original_image.size
            file_size = len(uploaded_file.getvalue()) / 1024  # size in KB
            capacity = calculate_capacity(original_image) / 1024  # capacity in KB
            
            st.markdown(f"""
            <div class="timestamp">
            FILE DATA: {width}x{height} pixels | {file_size:.1f} KB | Format: {original_image.format}
            </div>
            """, unsafe_allow_html=True)
            
            # Show capacity information
            st.markdown(f"""
            <div class="timestamp">
            CAPACITY: {capacity:.1f} KB available for hidden data
            </div>
            """, unsafe_allow_html=True)
            
            # If file is selected, show capacity bar
            if is_file and len(data_to_hide) > 0:
                usage_percent = len(data_to_hide) / (calculate_capacity(original_image)) * 100
                
                # Determine color based on usage
                if usage_percent < 50:
                    capacity_color = "capacity-low"
                elif usage_percent < 80:
                    capacity_color = "capacity-medium"
                else:
                    capacity_color = "capacity-high"
                
                st.markdown(f"""
                <div class="capacity-bar-container">
                    <div class="capacity-bar-fill {capacity_color}" style="width: {min(100, usage_percent)}%;"></div>
                </div>
                <div class="capacity-text">
                    {len(data_to_hide)/1024:.1f} KB / {capacity:.1f} KB ({min(100, usage_percent):.1f}%)
                </div>
                """, unsafe_allow_html=True)
                
                # Warning if file is too large
                if usage_percent > 100:
                    st.markdown('<div class="critical-warning-box">', unsafe_allow_html=True)
                    st.markdown(f"⚠️ **ERROR:** File too large for this image. Please use a larger image or a smaller file.")
                    st.markdown(f"Required capacity: {len(data_to_hide)/1024:.1f} KB, Available: {capacity:.1f} KB")
                    st.markdown('</div>', unsafe_allow_html=True)
                elif usage_percent > 80:
                    st.markdown('<div class="warning-box">', unsafe_allow_html=True)
                    st.markdown("⚠️ **WARNING:** File uses a large portion of available capacity. This may increase detection risk.")
                    st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.warning("⚠️ NO CARRIER IMAGE SELECTED")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # ZIP Protection Feature
    st.markdown('<div class="stcard">', unsafe_allow_html=True)
    st.subheader("🔒 ZIP PROTECTION SETTINGS")
    
    # ZIP protection option
    enable_zip = st.checkbox("Enable ZIP protection for sharing via messaging platforms", value=True)
    
    # ZIP password option
    if enable_zip:
        st.markdown("""
        <div class="zip-illustration">
            <div style="font-size:2rem;">📄 → 🔐 → 📱 → 🔓 → 📄</div>
            <div style="margin-top:10px;">Image → ZIP → Share → Extract → Preserved Image</div>
        </div>
        """, unsafe_allow_html=True)
        
        # ZIP password input
        zip_password = st.text_input("ZIP password (optional):", type="password", 
                                   help="Set a password for the ZIP file. Leave blank for no password.",
                                   placeholder="Enter ZIP password")
        
        if HAS_PYZIPPER:
            st.markdown("""
            <div class="success-box">
            <b>ZIP Password Protection:</b> Password-protected ZIP files require the same password for extraction.
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="warning-box">
            <b>Note:</b> Enhanced ZIP password protection requires the pyzipper library. 
            Without it, ZIP passwords will be limited in security. For maximum security, 
            rely on the steganography password.
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="step-box">
            <b>Step 1:</b> System will create a ZIP file containing your steganographic image
        </div>
        <div class="step-box">
            <b>Step 2:</b> Share the ZIP file through any platform (WhatsApp, Email, etc.)
        </div>
        <div class="step-box">
            <b>Step 3:</b> Recipient extracts the ZIP file to get the original uncompressed image
        </div>
        <div class="step-box">
            <b>Step 4:</b> Recipient can decode the hidden message successfully
        </div>
        """, unsafe_allow_html=True)
    else:
        zip_password = ""  # Initialize zip_password even when not using ZIP
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Encode button row
    if uploaded_file is not None:
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("🔐 OPERATION EXECUTION")
        
        encode_col1, encode_col2, encode_col3 = st.columns([1, 2, 1])
        with encode_col2:
            encode_button = st.button("🔒 INITIATE ENCODING SEQUENCE", key="encode_button", use_container_width=True)
        
        if encode_button:
            # Check for valid data to hide
            if (input_type == "Text Message" and secret_message == "") or (input_type == "File Upload" and not data_to_hide):
                st.error("⚠️ ERROR: No intelligence data provided.")
            elif encode_password == "":
                st.error("⚠️ ERROR: Security key required for encryption.")
            elif encode_password != confirm_password:
                st.error("⚠️ ERROR: Security key verification failed. Keys do not match.")
            elif len(encode_password) < 6:
                st.error("⚠️ ERROR: Security key insufficient. Minimum 6 characters required.")
            else:
                # Check capacity
                if len(data_to_hide) > calculate_capacity(original_image):
                    st.error(f"⚠️ ERROR: Data too large for this image. Required: {len(data_to_hide)/1024:.1f} KB, Available: {calculate_capacity(original_image)/1024:.1f} KB")
                else:
                    # Show progress
                    progress_text = "Initializing encryption protocols..."
                    progress_bar = st.progress(0)
                    
                    for i in range(101):
                        # Update progress bar
                        progress_bar.progress(i)
                        if i == 10:
                            progress_text = "Analyzing carrier image..."
                            time.sleep(0.05)
                        elif i == 30:
                            progress_text = "Applying encryption algorithms..."
                            time.sleep(0.05)
                        elif i == 50:
                            progress_text = "Embedding intelligence data..."
                            time.sleep(0.05)
                        elif i == 70:
                            progress_text = "Applying steganographic techniques..."
                            time.sleep(0.05)
                        elif i == 90:
                            if enable_zip:
                                progress_text = "Preparing ZIP protection..."
                            else:
                                progress_text = "Finalizing secure package..."
                            time.sleep(0.05)
                        
                        # Display the current status
                        st.markdown(f'<div class="system-message">> {progress_text}</div>', unsafe_allow_html=True)
                        
                        # Add a small delay to simulate processing
                        time.sleep(0.01)
                    
                    try:
                        # Convert to RGB if image is in RGBA mode
                        if original_image.mode == 'RGBA':
                            original_image = original_image.convert('RGB')
                        
                        # Prepare metadata
                        metadata = {
                            "type": "file" if is_file else "text",
                            "name": file_name,
                            "mime": file_type,
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        # Convert metadata to JSON and then to bytes
                        metadata_bytes = json.dumps(metadata).encode('utf-8')
                        
                        # Combine metadata and data
                        metadata_length = len(metadata_bytes).to_bytes(4, byteorder='big')
                        combined_data = metadata_length + metadata_bytes + data_to_hide
                        
                        # Encrypt the combined data
                        encrypted_data = encrypt_data(combined_data, encode_password)
                        
                        # Use our custom steganography function to hide the encrypted data
                        secret_image = hide_data_in_image(original_image, encrypted_data)
                        
                        # Generate a unique operation code
                        operation_code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=8))
                        
                        # Display success message
                        st.markdown('<div class="success-box">', unsafe_allow_html=True)
                        st.markdown(f'✅ **MISSION SUCCESSFUL** • OPERATION CODE: {operation_code}')
                        
                        if is_file:
                            st.markdown(f'File "{file_name}" successfully embedded and encrypted.')
                        else:
                            st.markdown('Intelligence message successfully embedded and encrypted.')
                            
                        if enable_zip:
                            st.markdown('ZIP protection successfully applied.')
                            if zip_password:
                                if HAS_PYZIPPER:
                                    st.markdown(f'ZIP file protected with AES encryption. Password will be required to extract.')
                                else:
                                    st.markdown(f'ZIP password set, but enhanced encryption requires pyzipper library.')
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        # Display the encoded image
                        st.markdown('<div class="img-container">', unsafe_allow_html=True)
                        st.image(secret_image, caption="SECURE INTELLIGENCE PACKAGE", use_container_width=True)
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        # Create image data as PNG
                        buf = io.BytesIO()
                        secret_image.save(buf, format="PNG")
                        image_data = buf.getvalue()
                        
                        # Generate download buttons
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            # Regular image download
                            st.download_button(
                                label="💾 DOWNLOAD IMAGE ONLY",
                                data=image_data,
                                file_name=f"FBI_SEC_{operation_code}.png",
                                mime="image/png",
                                use_container_width=True
                            )
                        
                        with col2:
                            if enable_zip:
                                # Create and download ZIP file
                                zip_data = create_protected_zip(image_data, zip_password, f"FBI_SEC_{operation_code}.png")
                                
                                if zip_data:
                                    # ZIP file download button
                                    st.download_button(
                                        label="🔐 DOWNLOAD PROTECTED ZIP",
                                        data=zip_data,
                                        file_name=f"FBI_SEC_{operation_code}.zip",
                                        mime="application/zip",
                                        use_container_width=True
                                    )
                            else:
                                # Show button to enable ZIP protection
                                if st.button("ENABLE ZIP PROTECTION", use_container_width=True):
                                    st.session_state['enable_zip'] = True
                                    st.rerun()  # Changed from experimental_rerun
                        
                        # Warning based on protection method
                        if enable_zip:
                            st.markdown('<div class="success-box">', unsafe_allow_html=True)
                            st.markdown('✅ **PROTECTED FOR SHARING:** This ZIP file can be safely shared through any platform including WhatsApp, Telegram, and email.')
                            st.markdown("""
                            **Instructions for recipients:**
                            1. Download the ZIP file
                            2. Extract the image file from the ZIP
                            3. Use the extracted image with this system to decode the message
                            """)
                            st.markdown('</div>', unsafe_allow_html=True)
                        else:
                            st.markdown('<div class="warning-box">', unsafe_allow_html=True)
                            st.markdown('⚠️ **SHARING WARNING:** This image must NOT be shared through WhatsApp or other platforms that compress images.')
                            st.markdown('Consider using the ZIP protection option above for safer sharing.')
                            st.markdown('</div>', unsafe_allow_html=True)
                        
                        # Security warnings
                        st.markdown('<div class="warning-box">', unsafe_allow_html=True)
                        st.markdown('⚠️ **SECURITY ADVISORY:** Protect your security key with highest precautions.')
                        st.markdown('Share encryption passwords through a separate secure channel.')
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        # Image metadata after encoding
                        width, height = secret_image.size
                        st.markdown(f"""
                        <div class="timestamp">
                        PACKAGE DATA: {width}x{height} pixels | Format: PNG | Operation: {operation_code}
                        </div>
                        """, unsafe_allow_html=True)
                        
                    except ValueError as e:
                        st.error(f"⚠️ OPERATION FAILED: {str(e)}")
                    except Exception as e:
                        st.error(f"⚠️ OPERATION FAILED: {str(e)}")
        st.markdown('</div>', unsafe_allow_html=True)

# Decoding section
with tabs[1]:
    st.markdown('<h2 class="section-header">Intelligence Extraction Protocol</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 2])
    
    with col1:
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("🖼️ ENCRYPTED INTELLIGENCE")
        
        # File uploader for decoding
        decode_file = st.file_uploader("Upload intelligence package (Image or ZIP)", 
                                      type=["png", "jpg", "jpeg", "zip"],
                                      help="Select image containing embedded intelligence or ZIP file", 
                                      key="decode_uploader")
        
        # Handle ZIP extraction
        if decode_file is not None and decode_file.name.lower().endswith('.zip'):
            st.markdown('<div class="success-box">', unsafe_allow_html=True)
            st.markdown('🔓 **ZIP FILE DETECTED**')
            st.markdown('ZIP files protect images from compression during transfer.')
            st.markdown('</div>', unsafe_allow_html=True)
            
            # ZIP password input for extraction
            zip_extract_password = st.text_input("ZIP password (if required):", type="password", 
                                              placeholder="Leave blank if no password", 
                                              help="Enter the password for this ZIP file")
            
            # Extract button for ZIP
            extract_button = st.button("📤 EXTRACT IMAGE FROM ZIP", key="extract_button", use_container_width=True)
            
            if extract_button:
                st.markdown('<div class="processing-animation"><div class="processing-dot"></div><div class="processing-dot"></div><div class="processing-dot"></div></div>', unsafe_allow_html=True)
                st.markdown('<div class="system-message">> Processing ZIP archive...</div>', unsafe_allow_html=True)
                
                # Extract the image with optional password
                image_data, error_msg, file_list = extract_from_zip(decode_file.getvalue(), zip_extract_password)
                
                # Handle multiple files
                if file_list:
                    st.session_state['zip_file_list'] = file_list
                    st.success(f"Found {len(file_list)} image files in ZIP")
                    selected_image = st.selectbox("Select image from ZIP:", file_list)
                    
                    if st.button("USE SELECTED IMAGE", key="use_selected", use_container_width=True):
                        # Extract the selected image
                        try:
                            if HAS_PYZIPPER and zip_extract_password:
                                # Try with pyzipper for AES encryption
                                zip_buffer = io.BytesIO(decode_file.getvalue())
                                with pyzipper.AESZipFile(zip_buffer) as zip_ref:
                                    if zip_extract_password:
                                        zip_ref.setpassword(zip_extract_password.encode())
                                    image_data = zip_ref.read(selected_image)
                            else:
                                # Fall back to standard zipfile
                                zip_buffer = io.BytesIO(decode_file.getvalue())
                                with zipfile.ZipFile(zip_buffer, 'r') as zip_ref:
                                    pwd = zip_extract_password.encode() if zip_extract_password else None
                                    image_data = zip_ref.read(selected_image, pwd=pwd)
                            
                            # Process the extracted image
                            image_io = io.BytesIO(image_data)
                            decode_image = Image.open(image_io)
                            st.session_state['extracted_image'] = decode_image
                            st.session_state['zip_extraction_error'] = None
                            st.success(f"Successfully extracted: {selected_image}")
                            st.rerun()  # Changed from experimental_rerun
                        except Exception as e:
                            st.error(f"Error extracting file: {str(e)}")
                            st.session_state['zip_extraction_error'] = str(e)
                
                # Handle extraction errors
                elif error_msg != "Success":
                    st.error(f"Error: {error_msg}")
                    st.session_state['zip_extraction_error'] = error_msg
                
                # Process successful extraction
                elif image_data:
                    try:
                        # Convert to PIL Image
                        image_io = io.BytesIO(image_data)
                        decode_image = Image.open(image_io)
                        st.session_state['extracted_image'] = decode_image
                        st.session_state['zip_extraction_error'] = None
                        st.success("Image successfully extracted from ZIP!")
                        st.rerun()  # Changed from experimental_rerun
                    except Exception as e:
                        st.error(f"Error processing extracted image: {str(e)}")
                        st.session_state['zip_extraction_error'] = str(e)
        
        # Use the extracted image if available
        if st.session_state['extracted_image'] is not None:
            decode_image = st.session_state['extracted_image']
            st.markdown('<div class="img-container">', unsafe_allow_html=True)
            st.image(decode_image, caption="EXTRACTED FROM ZIP", use_container_width=True)
            st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Image metadata
            width, height = decode_image.size
            st.markdown(f"""
            <div class="timestamp">
            EXTRACTED IMAGE: {width}x{height} pixels | Format: {decode_image.format} | Source: ZIP Archive
            </div>
            """, unsafe_allow_html=True)
            
            # Add button to clear extracted image
            if st.button("✖️ CLEAR EXTRACTED IMAGE", key="clear_extracted", use_container_width=True):
                st.session_state['extracted_image'] = None
                st.session_state['zip_extraction_error'] = None
                st.session_state['zip_file_list'] = None
                st.rerun()  # Changed from experimental_rerun
                
        # Regular image file
        elif decode_file is not None and not decode_file.name.lower().endswith('.zip'):
            try:
                # Display the image to decode
                decode_image = Image.open(decode_file)
                
                # Resize image if needed
                decode_image = resize_image_if_needed(decode_image)
                
                st.markdown('<div class="img-container">', unsafe_allow_html=True)
                st.image(decode_image, caption="INTELLIGENCE CARRIER IMAGE", use_container_width=True)
                # Add scanner effect
                st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
                
                # File metadata
                width, height = decode_image.size
                file_size = len(decode_file.getvalue()) / 1024  # size in KB
                st.markdown(f"""
                <div class="timestamp">
                PACKAGE DATA: {width}x{height} pixels | {file_size:.1f} KB | Format: {decode_image.format}
                </div>
                """, unsafe_allow_html=True)
            except Exception as e:
                st.error(f"Error opening image: {str(e)}")
        else:
            # If no image or file is loaded
            if not st.session_state['extracted_image']:
                st.warning("⚠️ NO INTELLIGENCE PACKAGE LOADED")
                st.markdown("""
                <div class="zip-illustration">
                    <div>You can now upload either:</div>
                    <div style="margin-top:10px;">
                        <span style="margin:0 15px;"><b>📄 Image File</b></span> OR 
                        <span style="margin:0 15px;"><b>🗜️ ZIP Archive</b></span>
                    </div>
                    <div style="margin-top:10px; opacity:0.8;">ZIP files protect images during transmission</div>
                </div>
                """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("🔑 AUTHENTICATION")
        
        # Password input for decoding
        st.markdown('<div class="timestamp">CLEARANCE REQUIRED</div>', unsafe_allow_html=True)
        decode_password = st.text_input("Enter security key:", 
                                      type="password",
                                      help="Enter the security key used for encryption",
                                      placeholder="Enter your security clearance key", 
                                      key="decode_password")
        
        # Information about transmission method
        transmission_method = st.selectbox(
            "How was this image transmitted?",
            [
                "ZIP protected transfer (recommended)",
                "Direct file transfer (USB, local network)",
                "Cloud storage direct download",
                "Email attachment (downloaded directly)",
                "WhatsApp / Telegram / Messenger",
                "Social media (Facebook, Instagram, Twitter)",
                "Other / Unknown"
            ]
        )
        
        # Warning based on transmission method
        if "WhatsApp" in transmission_method or "Social media" in transmission_method:
            if 'decode_image' in locals() and not decode_file.name.lower().endswith('.zip'):
                st.markdown('<div class="critical-warning-box">', unsafe_allow_html=True)
                st.markdown('⚠️ **WARNING:** This transmission method destroys steganographic data!')
                st.markdown('Decoding will likely fail. Request a ZIP-protected version instead.')
                st.markdown('</div>', unsafe_allow_html=True)
        
        # Decode button - show if an image is loaded (either directly or from ZIP)
        show_decode_button = ('decode_image' in locals() or st.session_state['extracted_image'] is not None)
        
        if show_decode_button:
            # Use the correct image source for decoding
            if 'decode_image' not in locals() and st.session_state['extracted_image'] is not None:
                decode_image = st.session_state['extracted_image']
            
            decode_button = st.button("🔓 EXECUTE DECRYPTION PROTOCOL", key="decode_button", use_container_width=True)
            
            if decode_button:
                if decode_password == "":
                    st.error("⚠️ ACCESS DENIED: Security key required.")
                else:
                    # Show progress
                    progress_text = "Initializing decryption sequence..."
                    progress_bar = st.progress(0)
                    
                    for i in range(101):
                        # Update progress bar
                        progress_bar.progress(i)
                        if i == 10:
                            progress_text = "Scanning carrier image..."
                            time.sleep(0.05)
                        elif i == 30:
                            progress_text = "Extracting embedded data..."
                            time.sleep(0.05)
                        elif i == 50:
                            progress_text = "Verifying security key..."
                            time.sleep(0.05)
                        elif i == 70:
                            progress_text = "Applying decryption algorithms..."
                            time.sleep(0.05)
                        elif i == 90:
                            progress_text = "Retrieving intelligence data..."
                            time.sleep(0.05)
                        
                        # Display the current status
                        st.markdown(f'<div class="system-message">> {progress_text}</div>', unsafe_allow_html=True)
                        
                        # Add a small delay to simulate processing
                        time.sleep(0.01)
                    
                    try:
                        # Use our custom steganography function to extract the encrypted data
                        extracted_encrypted_data = extract_data_from_image(decode_image)
                        
                        # Decrypt the data with the password
                        decrypted_data = decrypt_data(extracted_encrypted_data, decode_password)
                        
                        if decrypted_data:
                            # Parse the metadata - first 4 bytes is metadata length
                            metadata_length = int.from_bytes(decrypted_data[:4], byteorder='big')
                            
                            # Extract metadata JSON string and convert to dict
                            metadata_bytes = decrypted_data[4:4+metadata_length]
                            metadata = json.loads(metadata_bytes.decode('utf-8'))
                            
                            # Get the payload data
                            payload_data = decrypted_data[4+metadata_length:]
                            
                            # Success animation and message
                            st.success("✅ AUTHENTICATION SUCCESSFUL - INTELLIGENCE RETRIEVED")
                            
                            # Generate a unique access code
                            access_code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
                            st.markdown(f'<div class="system-message">> Access code: {access_code}</div>', unsafe_allow_html=True)
                            
                            # If this was from a ZIP, show a success message about the ZIP protection
                            if st.session_state['extracted_image'] is not None or (decode_file is not None and decode_file.name.lower().endswith('.zip')):
                                st.markdown('<div class="success-box">', unsafe_allow_html=True)
                                st.markdown('✅ **ZIP PROTECTION SUCCESSFUL**')
                                st.markdown('The ZIP protection preserved the steganographic data during transfer.')
                                st.markdown('</div>', unsafe_allow_html=True)
                            
                            # Process according to content type
                            if metadata["type"] == "text":
                                # It's a text message
                                revealed_message = payload_data.decode('utf-8')
                                st.session_state["revealed_message"] = revealed_message
                                st.session_state["revealed_file_data"] = None
                                st.session_state["revealed_file_name"] = None
                                st.session_state["revealed_file_type"] = None
                            else:
                                # It's a file
                                st.session_state["revealed_message"] = None
                                st.session_state["revealed_file_data"] = payload_data
                                st.session_state["revealed_file_name"] = metadata["name"]
                                st.session_state["revealed_file_type"] = metadata["mime"]
                                
                                # Display file info
                                file_size = len(payload_data) / 1024
                                st.markdown(f"""
                                <div class="success-box">
                                <h3>🔓 FILE EXTRACTED SUCCESSFULLY</h3>
                                <p><b>File name:</b> {metadata["name"]}</p>
                                <p><b>File size:</b> {file_size:.2f} KB</p>
                                <p><b>File type:</b> {metadata["mime"] or "Unknown"}</p>
                                </div>
                                """, unsafe_allow_html=True)
                        else:
                            st.error("⚠️ AUTHENTICATION FAILED: Invalid security key.")
                    except ValueError as e:
                        # Specific error for data corruption (possibly from WhatsApp)
                        if "data corruption" in str(e) or "length" in str(e):
                            st.markdown('<div class="critical-warning-box">', unsafe_allow_html=True)
                            st.markdown('🚨 **DATA CORRUPTION DETECTED** 🚨')
                            
                            if transmission_method.startswith("WhatsApp") or transmission_method.startswith("Social media"):
                                st.markdown(f"""
                                The image appears to have been damaged by {transmission_method.split(' ')[0]} compression.
                                
                                **SOLUTION:**
                                Request the sender to use ZIP protection when sharing the image:
                                1. Sender should select "Enable ZIP protection" during encoding
                                2. Sender should share the ZIP file instead of the raw image
                                3. You extract the image from the ZIP before decoding
                                """)
                            else:
                                st.markdown("""
                                This image appears to have been compressed or modified, destroying the embedded data.
                                
                                **RECOMMENDED SOLUTION:**
                                Request a ZIP-protected version of the image.
                                """)
                            st.markdown('</div>', unsafe_allow_html=True)
                        else:
                            st.error(f"⚠️ EXTRACTION FAILED: {str(e)}")
                    except Exception as e:
                        st.error(f"⚠️ EXTRACTION FAILED: Invalid carrier image or data corruption detected.")
        else:
            st.info("Please upload or extract an image to decode")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Results section that appears only after successful decoding
    if "revealed_message" in st.session_state and st.session_state["revealed_message"]:
        # Display text message results
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("📜 CLASSIFIED INTELLIGENCE")
        
        # Add a "classified" stamp effect
        stamp_col1, stamp_col2, stamp_col3 = st.columns([1, 2, 1])
        with stamp_col2:
            st.markdown('<div style="color:#D00000; transform:rotate(-15deg); font-size:1.5rem; font-weight:bold; border:2px solid #D00000; padding:5px; text-align:center; margin:10px 0;">TOP SECRET</div>', unsafe_allow_html=True)
        
        # Display the revealed message in a custom styled box
        st.text_area("Decrypted content:", st.session_state["revealed_message"], height=150, key="revealed_text")
        
        # Option to download the message as a text file
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.download_button(
                label="💾 ARCHIVE INTELLIGENCE DATA",
                data=st.session_state["revealed_message"],
                file_name=f"FBI_INTEL_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )
        
        # Add warning about data handling
        st.markdown('<div class="warning-box">', unsafe_allow_html=True)
        st.markdown('⚠️ **SECURITY NOTICE:** This intelligence is classified.')
        st.markdown('Unauthorized disclosure is subject to penalties under federal law.')
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    elif "revealed_file_data" in st.session_state and st.session_state["revealed_file_data"]:
        # Display file download results
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("📂 EXTRACTED FILE")
        
        # Add a "classified" stamp effect
        stamp_col1, stamp_col2, stamp_col3 = st.columns([1, 2, 1])
        with stamp_col2:
            st.markdown('<div style="color:#D00000; transform:rotate(-15deg); font-size:1.5rem; font-weight:bold; border:2px solid #D00000; padding:5px; text-align:center; margin:10px 0;">TOP SECRET</div>', unsafe_allow_html=True)
        
        # File details
        file_name = st.session_state["revealed_file_name"]
        file_type = st.session_state["revealed_file_type"]
        file_size = len(st.session_state["revealed_file_data"]) / 1024
        
        # Determine file icon based on file type
        file_icon = "📄"
        if file_name.lower().endswith(('.zip', '.rar', '.7z')):
            file_icon = "🗜️"
        elif file_name.lower().endswith('.pdf'):
            file_icon = "📕"
        elif file_name.lower().endswith(('.doc', '.docx')):
            file_icon = "📘"
        elif file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
            file_icon = "🖼️"
        elif file_name.lower().endswith('.txt'):
            file_icon = "📝"
        
        st.markdown(f"""
        <div class="timestamp">
        FILE TYPE: {file_icon} {file_type} | SIZE: {file_size:.2f} KB | NAME: {file_name}
        </div>
        """, unsafe_allow_html=True)
        
        # Preview for text files
        if file_name.lower().endswith('.txt') or file_type == "text/plain":
            try:
                text_content = st.session_state["revealed_file_data"].decode('utf-8')
                st.text_area("File Preview:", text_content, height=150)
            except:
                st.info("File preview not available - binary content")
        # Preview for image files
        elif file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
            try:
                image = Image.open(io.BytesIO(st.session_state["revealed_file_data"]))
                st.image(image, caption=f"Preview of {file_name}")
            except:
                st.info("Image preview not available")
        else:
            st.info("Preview not available for this file type")
        
        # Download button
        st.download_button(
            label=f"💾 DOWNLOAD FILE: {file_name}",
            data=st.session_state["revealed_file_data"],
            file_name=file_name,
            mime=file_type or "application/octet-stream",
            use_container_width=True
        )
        
        # Add warning about data handling
        st.markdown('<div class="warning-box">', unsafe_allow_html=True)
        st.markdown('⚠️ **SECURITY NOTICE:** This file is classified.')
        st.markdown('Unauthorized disclosure is subject to penalties under federal law.')
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# Sidebar with information
with st.sidebar:
    # Using markdown for image instead of st.image for better size control
    st.markdown("""
    <div style="text-align: center;">
        <img class="sidebar-image" src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/da/Seal_of_the_Federal_Bureau_of_Investigation.svg/300px-Seal_of_the_Federal_Bureau_of_Investigation.svg.png" width="150">
    </div>
    """, unsafe_allow_html=True)
    st.markdown(f"<h3 style='text-align: center;'>SECURE TERMINAL</h3>", unsafe_allow_html=True)
    
    # Multi-Mode Highlight
    st.markdown('<div style="background-color:#00843D; color:white; padding:10px; border-radius:5px; margin:10px 0; font-weight:bold; text-align:center;">', unsafe_allow_html=True)
    st.markdown('🔄 MULTI-MODE ACTIVE <span class="new-feature">NEW</span>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("📘 MULTI-MODE STEGANOGRAPHY")
    st.write("""
    The system now supports two operational modes:

    1. **Text Mode**: Hide text messages within images
       - For short messages, notes, and communications
       - Lower detection risk due to smaller payload
    
    2. **File Mode**: Hide any file within images
       - Documents, archives, executables, media files
       - Maximum file size depends on carrier image dimensions
       - Typical capacity: ~0.37 bits per pixel (3 bits per 8 pixels)
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("🛡️ SECURITY PROTOCOLS")
    st.write("""
    - **LSB Steganography**: Hides data in least significant bits
    - **AES-128 Encryption**: Military-grade data security
    - **ZIP Protection**: Preserves data during transmission
    - **Password Options**: Use strong steganography passwords
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("⚠️ SHARING SECURITY")
    st.markdown("""
    <span style="color: #00843D; font-weight: bold;">✅ SAFE (with ZIP protection):</span>
    <ul>
        <li>WhatsApp, Telegram, Facebook Messenger</li>
        <li>Email (all methods)</li>
        <li>Social media platforms</li>
        <li>Any platform that normally compresses images</li>
    </ul>
    
    <span style="color: #BF0A30; font-weight: bold;">⛔ UNSAFE (without ZIP protection):</span>
    <ul>
        <li>WhatsApp, Telegram (normal mode)</li>
        <li>Facebook, Instagram, Twitter</li>
        <li>Most messaging applications</li>
        <li>Email with inline images</li>
    </ul>
    """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Updated info about ZIP password protection
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("ℹ️ ZIP PASSWORD PROTECTION")
    if HAS_PYZIPPER:
        st.markdown("""
        This application uses AES encryption for ZIP password protection.

        For secure transmission:
        1. Use the steganography encryption password for data security
        2. Use ZIP password for an additional layer of protection during transfer
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        For full ZIP password protection, install the pyzipper library.
        
        Without pyzipper, ZIP passwords have limited security. For maximum security:
        1. Rely primarily on the steganography encryption password
        2. Use an external tool like 7-Zip to add secure password protection to ZIPs
        """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Session information
    st.markdown(f"""
    <div class="info-box">
    <h4>SECURE SESSION DATA</h4>
    <div class="operation-id">OPERATOR: {user_login}</div>
    <div class="operation-id">OPERATION ID: {st.session_state['operation_id']}</div>
    <div class="operation-id">SESSION START: {current_time}</div>
    <div class="operation-id">AUTHORIZATION: ACTIVE</div>
    </div>
    """, unsafe_allow_html=True)

# Footer
st.markdown('<div class="footer">', unsafe_allow_html=True)
st.markdown("""
FEDERAL BUREAU OF INVESTIGATION | DIGITAL INTELLIGENCE DIVISION | CLASSIFIED SYSTEM
<br>WARNING: This system contains U.S. Government information. Unauthorized access is prohibited.<br>Developed by
© Dilshan. All rights reserved.
""", unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)
