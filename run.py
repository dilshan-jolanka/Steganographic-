import streamlit as st
import numpy as np
from PIL import Image
import io
import base64
from stegano import lsb
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timezone
import time
import random

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

# Function to resize image to suitable dimensions
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

# Current timestamp in UTC with military format
current_time = "2025-07-11 04:11:36"  # Using the provided timestamp
st.markdown(f"""
<div class="user-info">
    <span class="status-indicator status-online"></span> <b>AGENT:</b> {st.session_state['operation_id']} | <b>USER:</b> ************** | <b>UTC:</b> {current_time}Z
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
                    
                    # Use stegano to hide the encrypted message
                    secret_image = lsb.hide(original_image, encrypted_message)
                    
                    # Generate a unique operation code
                    operation_code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=8))
                    
                    # Display success message
                    st.markdown('<div class="success-box">', unsafe_allow_html=True)
                    st.markdown(f'✅ **MISSION SUCCESSFUL** • OPERATION CODE: {operation_code}')
                    st.markdown('Intelligence data successfully embedded and encrypted.')
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Display the encoded image
                    st.markdown('<div class="img-container">', unsafe_allow_html=True)
                    st.image(secret_image, caption="SECURE INTELLIGENCE PACKAGE", use_container_width=True)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Create a download button for the encoded image
                    buf = io.BytesIO()
                    secret_image.save(buf, format="PNG")
                    byte_im = buf.getvalue()
                    
                    col1, col2, col3 = st.columns([1, 2, 1])
                    with col2:
                        st.download_button(
                            label="💾 EXTRACT INTELLIGENCE PACKAGE",
                            data=byte_im,
                            file_name=f"FBI_SEC_{operation_code}.png",
                            mime="image/png",
                            use_container_width=True
                        )
                    
                    # Warning message
                    st.markdown('<div class="warning-box">', unsafe_allow_html=True)
                    st.markdown('⚠️ **SECURITY ADVISORY:** Protect your security key with highest precautions.')
                    st.markdown('Only share intelligence through secure, approved channels.')
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Image metadata after encoding
                    width, height = secret_image.size
                    st.markdown(f"""
                    <div class="timestamp">
                    PACKAGE DATA: {width}x{height} pixels | Format: PNG | Operation: {operation_code}
                    </div>
                    """, unsafe_allow_html=True)
                    
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
        decode_file = st.file_uploader("Upload intelligence package", 
                                      type=["png", "jpg", "jpeg"],
                                      help="Select image containing embedded intelligence", 
                                      key="decode_uploader")
        
        if decode_file is not None:
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
        else:
            st.warning("⚠️ NO INTELLIGENCE PACKAGE LOADED")
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
        
        # Decode button
        if decode_file is not None:
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
                        # Use stegano to reveal the encrypted message
                        encrypted_message = lsb.reveal(decode_image)
                        
                        # Decrypt the message with the password
                        revealed_message = decrypt_message(encrypted_message, decode_password)
                        
                        if revealed_message:
                            # Success animation and message
                            st.success("✅ AUTHENTICATION SUCCESSFUL - INTELLIGENCE RETRIEVED")
                            
                            # Generate a unique access code
                            access_code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
                            st.markdown(f'<div class="system-message">> Access code: {access_code}</div>', unsafe_allow_html=True)
                    except Exception as e:
                        st.error(f"⚠️ EXTRACTION FAILED: Invalid carrier image or format not recognized.")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Results section that appears only after successful decoding
    if decode_file is not None and 'revealed_message' in locals() and revealed_message:
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
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("📘 STEGANOGRAPHY BRIEFING")
    st.write("""
    Steganography is the practice of concealing intelligence within ordinary data carriers to avoid detection.
    
    Unlike encryption which may raise suspicion, steganography disguises the very existence of secret communications.
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("🛡️ SECURITY PROTOCOLS")
    st.write("""
    - **LSB Concealment**: Advanced pixel manipulation for data hiding
    - **Military-grade Encryption**: AES-128 with unique key derivation
    - **Anti-forensic Measures**: Detection countermeasures active
    - **Zero-knowledge Protocol**: No data retention on servers
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("📝 FIELD MANUAL")
    st.write("""
    **Encoding Protocol:**
    1. Select suitable carrier image
    2. Input classified intelligence data
    3. Establish strong security key (min. 8 chars)
    4. Execute encoding sequence
    5. Extract intelligence package to secure storage
    
    **Decoding Protocol:**
    1. Load intelligence package
    2. Provide correct security key
    3. Execute decryption protocol
    4. Secure extracted intelligence
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("⚠️ SECURITY ADVISORIES")
    st.write("""
    - Use maximum-strength security keys
    - Transmit security keys via separate secure channels
    - Avoid multiple encoding of same carrier image
    - Use PNG format for optimal information integrity
    - Clear temporary files after operations
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Session information
    st.markdown(f"""
    <div class="info-box">
    <h4>SECURE SESSION DATA</h4>
    <div class="operation-id">OPERATOR: dilshan-jolankai</div>
    <div class="operation-id">OPERATION ID: {st.session_state['operation_id']}</div>
    <div class="operation-id">SESSION START: 2025-07-11 04:11</div>
    <div class="operation-id">AUTHORIZATION: ACTIVE</div>
    </div>
    """, unsafe_allow_html=True)

# Footer
st.markdown('<div class="footer">', unsafe_allow_html=True)
st.markdown("""
FEDERAL BUREAU OF INVESTIGATION | DIGITAL INTELLIGENCE DIVISION | CLASSIFIED SYSTEM
<br>WARNING: This system contains U.S. Government information. Unauthorized access is prohibited.
""", unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)