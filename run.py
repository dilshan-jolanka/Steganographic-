import streamlit as st
import numpy as np
from PIL import Image
import io
import base64
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timezone
import time
import random
import zipfile

# Set page configuration
st.set_page_config(
    page_title="CLASSIFIED - FBI Steganography System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

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

# Function to encrypt message with password
def encrypt_message(message, password):
    key, salt = get_key_from_password(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    # Prepend salt to the encrypted message for decryption later
    return base64.b64encode(salt + encrypted_message).decode()

# Function to decrypt message with password
def decrypt_message(encrypted_data, password):
    try:
        # Decode from base64
        decoded_data = base64.b64decode(encrypted_data)
        # Extract salt (first 16 bytes) and encrypted message
        salt, encrypted_message = decoded_data[:16], decoded_data[16:]
        
        # Get key from password and salt
        key, _ = get_key_from_password(password, salt)
        
        # Decrypt the message
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        st.error(f"Decryption failed: Incorrect password or invalid data")
        return None

# Function to create a password-protected ZIP file containing the steganographic image
def create_protected_zip(image_data, zip_password, filename="secure_package.png"):
    # Create a BytesIO object to hold the ZIP file
    zip_buffer = io.BytesIO()
    
    # Create a new ZIP file
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add the image to the ZIP file with the specified filename
        zip_file.writestr(filename, image_data)
        
        # Set the password for the ZIP file if provided
        if zip_password:
            # Apply password to the added file
            zip_info = zip_file.getinfo(filename)
            zip_info.flag_bits |= 0x1
    
    # Reset the buffer position to the beginning
    zip_buffer.seek(0)
    
    # Return the ZIP file as bytes
    return zip_buffer.getvalue()

# Custom LSB steganography functions
def int_to_bin(i):
    """Convert an integer to its binary representation as a string"""
    return bin(i)[2:].zfill(8)

def bin_to_int(binary):
    """Convert a binary string to integer"""
    return int(binary, 2)

def text_to_binary(text):
    """Convert text to a string of binary digits"""
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary

def binary_to_text(binary):
    """Convert binary digits to text"""
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:  # Ensure we have a complete byte
            text += chr(int(byte, 2))
    return text

def hide_message(image, message):
    """Hide a message in an image using LSB steganography"""
    # Convert image to RGB mode if it's not already
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    # Convert message to binary
    binary_message = text_to_binary(message)
    
    # Add message length header (32 bits = 4 bytes to store length)
    message_length = len(binary_message)
    length_header = format(message_length, '032b')
    binary_data = length_header + binary_message
    
    # Create a copy of the image
    encoded_image = image.copy()
    width, height = image.size
    
    # Counter for binary data position
    data_index = 0
    
    # Embed the binary data into the image
    for y in range(height):
        for x in range(width):
            # If we've embedded all the data, break
            if data_index >= len(binary_data):
                break
                
            pixel = list(image.getpixel((x, y)))
            
            # Modify the least significant bit of each color channel
            for c in range(3):  # RGB channels
                if data_index < len(binary_data):
                    # Replace the LSB of this color with our data bit
                    pixel[c] = (pixel[c] & 0xFE) | int(binary_data[data_index])
                    data_index += 1
            
            # Update the pixel in the new image
            encoded_image.putpixel((x, y), tuple(pixel))
            
            # If we've embedded all the data, break
            if data_index >= len(binary_data):
                break
        
        # If we've embedded all the data, break
        if data_index >= len(binary_data):
            break
    
    # Check if we could fit the entire message
    if data_index < len(binary_data):
        raise ValueError("Image too small to hide the message")
        
    return encoded_image

def reveal_message(image):
    """Extract a hidden message from an image"""
    # Convert image to RGB mode if it's not already
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    width, height = image.size
    binary_data = ""
    
    # First, extract enough bits to determine the message length (first 32 bits)
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            
            # Extract the LSB from each color channel
            for c in range(3):  # RGB channels
                binary_data += str(pixel[c] & 1)
                
                # Once we have 32 bits, we can determine the message length
                if len(binary_data) == 32:
                    break
            
            if len(binary_data) == 32:
                break
                
        if len(binary_data) == 32:
            break
    
    # Convert the first 32 bits to an integer (message length)
    try:
        message_length = int(binary_data, 2)
    except ValueError:
        raise ValueError("Could not extract valid length header - possible data corruption")
    
    # Sanity check for message length
    if message_length <= 0 or message_length > 1000000:  # Arbitrary upper limit
        raise ValueError("Invalid message length detected - possible data corruption")
    
    # Reset binary data to start extracting the actual message
    binary_data = ""
    bits_needed = message_length
    
    # Now extract the actual message bits
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            
            # Extract the LSB from each color channel
            for c in range(3):  # RGB channels
                # Skip the first 32 bits (length header) when (y,x,c) = (0,0,0), (0,0,1), etc.
                if y == 0 and x < 11:  # First 32 bits (approx. 11 pixels)
                    if not (y == 0 and x == 0 and c == 0):  # Not the very first bit
                        continue
                
                binary_data += str(pixel[c] & 1)
                bits_needed -= 1
                
                # If we've extracted all the bits we need, stop
                if bits_needed <= 0:
                    break
            
            if bits_needed <= 0:
                break
                
        if bits_needed <= 0:
            break
    
    # Take only the bits needed for the message (discard any extra)
    binary_message = binary_data[-message_length:]
    
    # Convert binary message to text
    message = binary_to_text(binary_message)
    
    return message

# Function to resize image if needed
def resize_image_if_needed(image, max_dimension=800):
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

# Initialize session state for operation ID if it doesn't exist
if 'operation_id' not in st.session_state:
    st.session_state['operation_id'] = generate_operation_id()

# Display FBI badge and classification banners
st.markdown('<div class="fbi-badge">🔰</div>', unsafe_allow_html=True)
st.markdown('<h1 class="main-header">Federal Bureau of Investigation</h1>', unsafe_allow_html=True)
st.markdown('<div class="classification-banner">TOP SECRET - CONFIDENTIAL</div>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Digital Steganography Intelligence System</p>', unsafe_allow_html=True)

# Use the provided timestamp and user login
current_time = "2025-07-11 06:30:12"  # Using the provided timestamp
user_login = "*************"     # Using the provided user login

st.markdown(f"""
<div class="user-info">
    <span class="status-indicator status-online"></span> <b>AGENT:</b> {st.session_state['operation_id']} | <b>USER:</b> {user_login} | <b>UTC:</b> {current_time}Z
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

# ZIP Protection Feature Recommendation
st.markdown('<div class="recommendation-highlight">', unsafe_allow_html=True)
st.markdown('<h3>🆕 ZIP PROTECTION FEATURE <span class="new-feature">NEW</span></h3>', unsafe_allow_html=True)
st.markdown("""
We've implemented your excellent suggestion of using ZIP files to protect steganographic images!

**This solves the compression problem completely** by ensuring that:
1. Image is downloaded as-is with no compression
2. The ZIP container protects the image data during transfer 
3. After extraction, the original image with hidden data is fully preserved

**When to use ZIP protection:**
- When sharing through messaging platforms (WhatsApp, Telegram, etc.)
- When sending via email
- When uploading to any platform that might compress images
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
        st.subheader("📄 CLASSIFIED MESSAGE INPUT")
        
        # Text input for the secret message
        st.markdown('<div class="timestamp">AUTHORIZED PERSONNEL ONLY</div>', unsafe_allow_html=True)
        secret_message = st.text_area("Enter classified intelligence:", height=150, 
                                      placeholder="Enter confidential information here...")
        
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
            
            # Image metadata
            width, height = original_image.size
            file_size = len(uploaded_file.getvalue()) / 1024  # size in KB
            st.markdown(f"""
            <div class="timestamp">
            FILE DATA: {width}x{height} pixels | {file_size:.1f} KB | Format: {original_image.format}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.warning("⚠️ NO CARRIER IMAGE SELECTED")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # ZIP Protection Feature
    st.markdown('<div class="stcard">', unsafe_allow_html=True)
    st.subheader("🔒 ZIP PROTECTION SETTINGS")
    
    # ZIP protection option
    enable_zip = st.checkbox("Enable ZIP protection for sharing via messaging platforms", value=True)
    
    # ZIP password option
    zip_password = ""
    if enable_zip:
        st.markdown("""
        <div class="zip-illustration">
            <div style="font-size:2rem;">📄 → 🔐 → 📱 → 🔓 → 📄</div>
            <div style="margin-top:10px;">Image → ZIP → Share → Extract → Preserved Image</div>
        </div>
        """, unsafe_allow_html=True)
        
        # ZIP password input
        zip_password = st.text_input("Optional ZIP password:", type="password", 
                                    help="Add an additional layer of protection to the ZIP file", 
                                    placeholder="Leave blank for no ZIP password")
        
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
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Encode button row
    if uploaded_file is not None:
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("🔐 OPERATION EXECUTION")
        
        encode_col1, encode_col2, encode_col3 = st.columns([1, 2, 1])
        with encode_col2:
            encode_button = st.button("🔒 INITIATE ENCODING SEQUENCE", key="encode_button", use_container_width=True)
        
        if encode_button:
            if secret_message == "":
                st.error("⚠️ ERROR: No intelligence data provided.")
            elif encode_password == "":
                st.error("⚠️ ERROR: Security key required for encryption.")
            elif encode_password != confirm_password:
                st.error("⚠️ ERROR: Security key verification failed. Keys do not match.")
            elif len(encode_password) < 6:
                st.error("⚠️ ERROR: Security key insufficient. Minimum 6 characters required.")
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
                    
                    # Encrypt the message with the password
                    encrypted_message = encrypt_message(secret_message, encode_password)
                    
                    # Use our custom steganography function to hide the encrypted message
                    secret_image = hide_message(original_image, encrypted_message)
                    
                    # Generate a unique operation code
                    operation_code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=8))
                    
                    # Display success message
                    st.markdown('<div class="success-box">', unsafe_allow_html=True)
                    st.markdown(f'✅ **MISSION SUCCESSFUL** • OPERATION CODE: {operation_code}')
                    st.markdown('Intelligence data successfully embedded and encrypted.')
                    if enable_zip:
                        st.markdown('ZIP protection successfully applied.')
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
                            
                            # ZIP file download button
                            st.download_button(
                                label="🔐 DOWNLOAD PROTECTED ZIP",
                                data=zip_data,
                                file_name=f"FBI_SEC_{operation_code}.zip",
                                mime="application/zip",
                                use_container_width=True
                            )
                            
                            if zip_password:
                                st.markdown(f'<div class="system-message">> ZIP password: {zip_password}</div>', unsafe_allow_html=True)
                        else:
                            # Show button to enable ZIP protection
                            if st.button("ENABLE ZIP PROTECTION", use_container_width=True):
                                st.session_state['enable_zip'] = True
                                st.experimental_rerun()
                    
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
        
        # Handle uploaded file
        if decode_file is not None:
            # Check if the file is a ZIP file
            if decode_file.name.lower().endswith('.zip'):
                st.markdown('<div class="success-box">', unsafe_allow_html=True)
                st.markdown('🔓 **ZIP FILE DETECTED**')
                st.markdown('ZIP files protect images from compression during transfer.')
                st.markdown('</div>', unsafe_allow_html=True)
                
                # ZIP password input for extraction
                zip_extract_password = st.text_input("ZIP password (if required):", type="password", 
                                                  placeholder="Leave blank if no password", 
                                                  help="Enter the password for this ZIP file")
                
                try:
                    # Create a BytesIO object from the uploaded ZIP file
                    zip_data = io.BytesIO(decode_file.getvalue())
                    
                    # Open the ZIP file
                    with zipfile.ZipFile(zip_data, 'r') as zip_ref:
                        # List files in the ZIP
                        file_list = zip_ref.namelist()
                        
                        # Filter for image files
                        image_files = [f for f in file_list if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
                        
                        if not image_files:
                            st.error("No image files found in the ZIP archive.")
                        else:
                            # If multiple images, let user select
                            if len(image_files) > 1:
                                selected_image = st.selectbox("Select image file from ZIP:", image_files)
                            else:
                                selected_image = image_files[0]
                            
                            try:
                                # Extract the selected image
                                if zip_extract_password:
                                    # If password provided, use it
                                    image_data = zip_ref.read(selected_image, pwd=zip_extract_password.encode())
                                else:
                                    # Try without password
                                    image_data = zip_ref.read(selected_image)
                                    
                                # Load the image from bytes
                                image_io = io.BytesIO(image_data)
                                decode_image = Image.open(image_io)
                                
                                # Success message
                                st.success(f"Successfully extracted image: {selected_image}")
                                
                                # Display the image
                                st.markdown('<div class="img-container">', unsafe_allow_html=True)
                                st.image(decode_image, caption="EXTRACTED IMAGE FROM ZIP", use_container_width=True)
                                st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)
                                st.markdown('</div>', unsafe_allow_html=True)
                                
                                # Image metadata
                                width, height = decode_image.size
                                file_size = len(image_data) / 1024  # size in KB
                                st.markdown(f"""
                                <div class="timestamp">
                                IMAGE DATA: {width}x{height} pixels | {file_size:.1f} KB | Format: {decode_image.format} | Source: ZIP Archive
                                </div>
                                """, unsafe_allow_html=True)
                                
                            except RuntimeError as e:
                                if "password required" in str(e).lower() or "bad password" in str(e).lower():
                                    st.error("ZIP file is password protected. Please enter the correct password.")
                                else:
                                    st.error(f"Error extracting file: {str(e)}")
                            except Exception as e:
                                st.error(f"Error processing image: {str(e)}")
                    
                except zipfile.BadZipFile:
                    st.error("Invalid ZIP file. The file may be corrupted.")
                except Exception as e:
                    st.error(f"Error opening ZIP file: {str(e)}")
                
            else:
                # Regular image file
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
            if "decode_image" in locals() and not decode_file.name.lower().endswith('.zip'):
                st.markdown('<div class="critical-warning-box">', unsafe_allow_html=True)
                st.markdown('⚠️ **WARNING:** This transmission method destroys steganographic data!')
                st.markdown('Decoding will likely fail. Request a ZIP-protected version instead.')
                st.markdown('</div>', unsafe_allow_html=True)
        
        # Decode button - only show if an image is loaded (either directly or from ZIP)
        if 'decode_image' in locals():
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
                        # Use our custom steganography function to reveal the encrypted message
                        encrypted_message = reveal_message(decode_image)
                        
                        # Decrypt the message with the password
                        revealed_message = decrypt_message(encrypted_message, decode_password)
                        
                        if revealed_message:
                            # Success animation and message
                            st.success("✅ AUTHENTICATION SUCCESSFUL - INTELLIGENCE RETRIEVED")
                            
                            # Generate a unique access code
                            access_code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
                            st.markdown(f'<div class="system-message">> Access code: {access_code}</div>', unsafe_allow_html=True)
                            
                            # If this was from a ZIP, show a success message about the ZIP protection
                            if decode_file.name.lower().endswith('.zip'):
                                st.markdown('<div class="success-box">', unsafe_allow_html=True)
                                st.markdown('✅ **ZIP PROTECTION SUCCESSFUL**')
                                st.markdown('The ZIP protection preserved the steganographic data during transfer.')
                                st.markdown('</div>', unsafe_allow_html=True)
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
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Results section that appears only after successful decoding
    if 'revealed_message' in locals() and revealed_message:
        st.markdown('<div class="stcard">', unsafe_allow_html=True)
        st.subheader("📜 CLASSIFIED INTELLIGENCE")
        
        # Add a "classified" stamp effect
        stamp_col1, stamp_col2, stamp_col3 = st.columns([1, 2, 1])
        with stamp_col2:
            st.markdown('<div style="color:#D00000; transform:rotate(-15deg); font-size:1.5rem; font-weight:bold; border:2px solid #D00000; padding:5px; text-align:center; margin:10px 0;">TOP SECRET</div>', unsafe_allow_html=True)
        
        # Display the revealed message in a custom styled box
        st.text_area("Decrypted content:", revealed_message, height=150, key="revealed_text")
        
        # Option to download the message as a text file
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.download_button(
                label="💾 ARCHIVE INTELLIGENCE DATA",
                data=revealed_message,
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

# Sidebar with information
with st.sidebar:
    # Using markdown for image instead of st.image for better size control
    st.markdown("""
    <div style="text-align: center;">
        <img class="sidebar-image" src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/da/Seal_of_the_Federal_Bureau_of_Investigation.svg/300px-Seal_of_the_Federal_Bureau_of_Investigation.svg.png" width="150">
    </div>
    """, unsafe_allow_html=True)
    st.markdown(f"<h3 style='text-align: center;'>SECURE TERMINAL</h3>", unsafe_allow_html=True)
    
    # ZIP Protection Highlight
    st.markdown('<div style="background-color:#00843D; color:white; padding:10px; border-radius:5px; margin:10px 0; font-weight:bold; text-align:center;">', unsafe_allow_html=True)
    st.markdown('✅ ZIP PROTECTION ACTIVE <span class="new-feature">NEW</span>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("📘 NEW ZIP PROTECTION")
    st.write("""
    Your suggestion to use ZIP files as protection has been implemented! This is an excellent solution because:

    - ZIP files preserve the exact binary data of the image
    - No compression is applied to the image inside the ZIP
    - The image can be extracted exactly as it was before
    - Works with all messaging platforms and email
    
    This completely solves the problem of messaging apps compressing images and destroying steganographic data.
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("🛡️ SECURITY PROTOCOLS")
    st.write("""
    - **LSB Steganography**: Hides data in least significant bits
    - **AES-128 Encryption**: Military-grade message security
    - **ZIP Protection**: Preserves data during transmission
    - **Password Options**: Both for steganography and ZIP
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
<br>WARNING: This system contains U.S. Government information. Unauthorized access is prohibited.<br>Developped by
© Dilshan. All rights reserved.
""", unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)
