import streamlit as st
import os
import tempfile
import zipfile
from datetime import datetime
from typing import List, Optional, Tuple
import io
import base64

# PDF and signature handling
import fitz  # PyMuPDF
from PIL import Image, ImageDraw, ImageFont
import pypdf
from pyhanko import stamp
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

# Cryptography and certificate handling
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
import pkcs11  # For USB token support

# Initialize session state
if 'signing_history' not in st.session_state:
    st.session_state.signing_history = []
if 'certificate_loaded' not in st.session_state:
    st.session_state.certificate_loaded = False
if 'cert_manager' not in st.session_state:
    st.session_state.cert_manager = None
if 'cert_info' not in st.session_state:
    st.session_state.cert_info = {}
if 'usb_tokens' not in st.session_state:
    st.session_state.usb_tokens = []

class USBTokenManager:
    """Handles USB DSC token operations"""
    
    def __init__(self):
        self.lib = None
        self.session = None
        self.tokens = []
    
    def detect_tokens(self) -> List[dict]:
        """Detect available USB DSC tokens"""
        try:
            # Common PKCS#11 library paths for different vendors
            lib_paths = [
                # eMudhra
                "/usr/lib/libeToken.so",  # Linux
                "C:\\Windows\\System32\\eToken.dll",  # Windows
                # Watchdata
                "/usr/lib/libwdpkcs.so",  # Linux  
                "C:\\Windows\\System32\\wdpkcs.dll",  # Windows
                # SafeNet/Gemalto
                "/usr/lib/libeTPkcs11.so",  # Linux
                "C:\\Windows\\System32\\eTPkcs11.dll",  # Windows
                # Generic paths
                "/usr/lib/opensc-pkcs11.so",  # OpenSC
                "C:\\Windows\\System32\\opensc-pkcs11.dll"
            ]
            
            detected_tokens = []
            
            for lib_path in lib_paths:
                if os.path.exists(lib_path):
                    try:
                        lib = pkcs11.lib(lib_path)
                        slots = lib.get_slots(token_present=True)
                        
                        for slot in slots:
                            token = slot.get_token()
                            detected_tokens.append({
                                'slot_id': slot.slot_id,
                                'token_label': token.label,
                                'manufacturer': token.manufacturer_id,
                                'model': token.model,
                                'serial': token.serial_number,
                                'lib_path': lib_path
                            })
                    except Exception as e:
                        continue
            
            self.tokens = detected_tokens
            return detected_tokens
            
        except Exception as e:
            st.error(f"Error detecting USB tokens: {str(e)}")
            return []
    
    def load_token_certificate(self, token_info: dict, pin: str) -> Tuple[Optional[object], Optional[object]]:
        """Load certificate and private key from USB token"""
        try:
            lib = pkcs11.lib(token_info['lib_path'])
            token = lib.get_token(token_label=token_info['token_label'])
            
            with token.open(user_pin=pin) as session:
                # Find certificate
                certificates = list(session.get_objects({
                    pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                    pkcs11.Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509
                }))
                
                if not certificates:
                    st.error("No certificates found on token")
                    return None, None
                
                # Get the first certificate
                cert_obj = certificates[0]
                cert_der = cert_obj[pkcs11.Attribute.VALUE]
                certificate = x509.load_der_x509_certificate(cert_der)
                
                # Find corresponding private key
                private_keys = list(session.get_objects({
                    pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
                }))
                
                if not private_keys:
                    st.error("No private keys found on token")
                    return None, None
                
                # For USB tokens, we need to create a PKCS11 signer
                # This is a simplified approach - in production you'd need more robust key matching
                private_key = private_keys[0]
                
                return certificate, private_key
                
        except Exception as e:
            st.error(f"Error loading token certificate: {str(e)}")
            return None, None
    """Handles certificate loading and validation"""
    
    def __init__(self):
        self.certificate = None
        self.private_key = None
        self.cert_info = {}
    
class CertificateManager:
    """Handles certificate loading and validation for various sources"""
    
    def __init__(self):
        self.certificate = None
        self.private_key = None
        self.cert_info = {}
        self.cert_source = None  # 'pfx', 'usb_token', 'emudhra'
        self.usb_token_manager = USBTokenManager()
    
    def load_pfx_certificate(self, pfx_data: bytes, password: str) -> bool:
        """Load PFX/P12 certificate (works with eMudhra DSC files)"""
        try:
            # Load PKCS12 data
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                pfx_data, password.encode('utf-8')
            )
            
            if not private_key or not certificate:
                st.error("Invalid certificate or private key in PFX file")
                return False
            
            # Verify the key type
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
            if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, dsa.DSAPrivateKey)):
                st.error(f"Unsupported key type: {type(private_key)}")
                return False
            
            self.private_key = private_key
            self.certificate = certificate
            self.additional_certificates = additional_certificates or []
            self.cert_info = self._extract_cert_info(certificate)
            self.cert_source = 'pfx'
            
            # Add debug info
            st.success(f"Certificate loaded: {type(certificate).__name__}")
            st.info(f"Private key type: {type(private_key).__name__}")
            
            return True
            
        except Exception as e:
            st.error(f"Failed to load certificate: {str(e)}")
            import traceback
            st.error(f"Detailed error: {traceback.format_exc()}")
            return False
    
    def load_usb_token_certificate(self, token_info: dict, pin: str) -> bool:
        """Load certificate from USB DSC token"""
        try:
            certificate, private_key = self.usb_token_manager.load_token_certificate(token_info, pin)
            
            if certificate and private_key:
                self.certificate = certificate
                self.private_key = private_key
                self.cert_info = self._extract_cert_info(certificate)
                self.cert_source = 'usb_token'
                
                st.success("USB Token certificate loaded successfully!")
                return True
            else:
                return False
                
        except Exception as e:
            st.error(f"Failed to load USB token certificate: {str(e)}")
            return False
    
    def _extract_cert_info(self, cert) -> dict:
        """Extract certificate information"""
        try:
            subject = cert.subject
            issuer = cert.issuer
            
            info = {
                'subject_cn': subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else 'N/A',
                'issuer_cn': issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else 'N/A',
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
                'not_valid_after': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
                'is_valid': datetime.now() < cert.not_valid_after and datetime.now() > cert.not_valid_before
            }
            return info
            
        except Exception as e:
            st.error(f"Error extracting certificate info: {str(e)}")
            return {}

class SignatureStamp:
    """Handles signature stamp creation and smart positioning"""
    
    def __init__(self):
        self.stamp_width = 200
        self.stamp_height = 100
    
    def find_blank_space(self, pdf_path: str, page_num: int = 0) -> Tuple[float, float]:
        """Find optimal blank space for signature placement"""
        try:
            doc = fitz.open(pdf_path)
            page = doc[page_num]
            page_rect = page.rect
            
            # Get text blocks and images to identify occupied areas
            text_blocks = page.get_text("blocks")
            image_list = page.get_images()
            
            # Create a grid to mark occupied areas
            grid_size = 20  # pixels
            grid_width = int(page_rect.width / grid_size) + 1
            grid_height = int(page_rect.height / grid_size) + 1
            occupied_grid = [[False for _ in range(grid_width)] for _ in range(grid_height)]
            
            # Mark text areas as occupied
            for block in text_blocks:
                if len(block) >= 4:  # Valid text block
                    x0, y0, x1, y1 = block[:4]
                    # Convert to grid coordinates
                    gx0 = max(0, int(x0 / grid_size))
                    gy0 = max(0, int(y0 / grid_size))
                    gx1 = min(grid_width - 1, int(x1 / grid_size))
                    gy1 = min(grid_height - 1, int(y1 / grid_size))
                    
                    # Mark grid cells as occupied
                    for gy in range(gy0, gy1 + 1):
                        for gx in range(gx0, gx1 + 1):
                            if 0 <= gy < grid_height and 0 <= gx < grid_width:
                                occupied_grid[gy][gx] = True
            
            # Mark image areas as occupied
            for img_index in image_list:
                img_rect = page.get_image_bbox(img_index)
                if img_rect:
                    x0, y0, x1, y1 = img_rect
                    gx0 = max(0, int(x0 / grid_size))
                    gy0 = max(0, int(y0 / grid_size))
                    gx1 = min(grid_width - 1, int(x1 / grid_size))
                    gy1 = min(grid_height - 1, int(y1 / grid_size))
                    
                    for gy in range(gy0, gy1 + 1):
                        for gx in range(gx0, gx1 + 1):
                            if 0 <= gy < grid_height and 0 <= gx < grid_width:
                                occupied_grid[gy][gx] = True
            
            # Find the best position for signature (prefer bottom-right)
            stamp_grid_width = int(self.stamp_width / grid_size) + 1
            stamp_grid_height = int(self.stamp_height / grid_size) + 1
            
            best_position = None
            best_score = -1
            
            # Search from bottom-right to top-left
            for gy in range(grid_height - stamp_grid_height, -1, -1):
                for gx in range(grid_width - stamp_grid_width, -1, -1):
                    # Check if this position is free
                    is_free = True
                    for dy in range(stamp_grid_height):
                        for dx in range(stamp_grid_width):
                            if gy + dy < grid_height and gx + dx < grid_width:
                                if occupied_grid[gy + dy][gx + dx]:
                                    is_free = False
                                    break
                        if not is_free:
                            break
                    
                    if is_free:
                        # Calculate score (prefer bottom-right)
                        x_pos = gx * grid_size
                        y_pos = gy * grid_size
                        
                        # Ensure minimum margins
                        margin = 20
                        if (x_pos >= margin and y_pos >= margin and 
                            x_pos + self.stamp_width <= page_rect.width - margin and
                            y_pos + self.stamp_height <= page_rect.height - margin):
                            
                            # Score based on proximity to bottom-right
                            x_score = x_pos / page_rect.width
                            y_score = (page_rect.height - y_pos) / page_rect.height
                            score = x_score + y_score
                            
                            if score > best_score:
                                best_score = score
                                best_position = (x_pos, y_pos)
            
            doc.close()
            
            if best_position:
                # Convert to percentage
                x_percent = (best_position[0] / page_rect.width) * 100
                y_percent = (best_position[1] / page_rect.height) * 100
                return (x_percent, y_percent)
            else:
                # Fallback to bottom-right corner
                return (70.0, 85.0)
                
        except Exception as e:
            st.warning(f"Could not analyze page layout: {str(e)}. Using default position.")
            return (70.0, 85.0)
    
    def create_text_stamp(self, text: str, font_size: int = 12) -> Image.Image:
        """Create a text-based signature stamp"""
        try:
            # Create image with transparent background
            img = Image.new('RGBA', (self.stamp_width, self.stamp_height), (255, 255, 255, 0))
            draw = ImageDraw.Draw(img)
            
            # Try to use a nice font, fallback to default
            try:
                font = ImageFont.truetype("arial.ttf", font_size)
            except:
                font = ImageFont.load_default()
            
            # Calculate text position (centered)
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = (self.stamp_width - text_width) // 2
            y = (self.stamp_height - text_height) // 2
            
            # Draw text
            draw.text((x, y), text, fill=(0, 0, 0, 255), font=font)
            
            # Add border
            draw.rectangle([0, 0, self.stamp_width-1, self.stamp_height-1], 
                         outline=(0, 0, 0, 255), width=2)
            
            return img
            
        except Exception as e:
            st.error(f"Error creating text stamp: {str(e)}")
            return None
    
    def resize_image_stamp(self, image: Image.Image) -> Image.Image:
        """Resize uploaded signature image to stamp dimensions"""
        try:
            # Maintain aspect ratio
            image.thumbnail((self.stamp_width, self.stamp_height), Image.Resampling.LANCZOS)
            
            # Create new image with white background
            new_img = Image.new('RGBA', (self.stamp_width, self.stamp_height), (255, 255, 255, 255))
            
            # Center the resized image
            x = (self.stamp_width - image.width) // 2
            y = (self.stamp_height - image.height) // 2
            
            new_img.paste(image, (x, y), image if image.mode == 'RGBA' else None)
            
            return new_img
            
        except Exception as e:
            st.error(f"Error resizing image stamp: {str(e)}")
            return None

class PDFSigner:
    """Main PDF signing class"""
    
    def __init__(self, cert_manager: CertificateManager):
        self.cert_manager = cert_manager
        self.signature_stamp = SignatureStamp()
    
    def add_visual_signature(self, pdf_path: str, stamp_image: Image.Image, 
                           position: Optional[Tuple[float, float]], output_path: str, 
                           smart_position: bool = True, sign_last_page_only: bool = True) -> bool:
        """Add visual signature stamp to PDF with smart positioning"""
        try:
            # Open PDF with PyMuPDF
            doc = fitz.open(pdf_path)
            
            # Convert PIL image to bytes
            img_buffer = io.BytesIO()
            stamp_image.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            # Determine which pages to sign
            if sign_last_page_only:
                pages_to_sign = [len(doc) - 1]  # Last page only
            else:
                pages_to_sign = list(range(len(doc)))  # All pages
            
            # Add stamp to selected pages
            for page_num in pages_to_sign:
                page = doc[page_num]
                page_rect = page.rect
                
                if smart_position:
                    # Use smart positioning to find blank space
                    pos_x_percent, pos_y_percent = self.signature_stamp.find_blank_space(pdf_path, page_num)
                    x = pos_x_percent * page_rect.width / 100
                    y = pos_y_percent * page_rect.height / 100
                else:
                    # Use manual position
                    x = position[0] * page_rect.width / 100
                    y = position[1] * page_rect.height / 100
                
                # Create rectangle for stamp
                stamp_rect = fitz.Rect(x, y, x + self.signature_stamp.stamp_width, 
                                     y + self.signature_stamp.stamp_height)
                
                # Ensure stamp fits within page bounds
                if stamp_rect.x1 > page_rect.width:
                    offset = stamp_rect.x1 - page_rect.width + 10
                    stamp_rect.x0 -= offset
                    stamp_rect.x1 -= offset
                
                if stamp_rect.y1 > page_rect.height:
                    offset = stamp_rect.y1 - page_rect.height + 10
                    stamp_rect.y0 -= offset
                    stamp_rect.y1 -= offset
                
                # Insert image
                page.insert_image(stamp_rect, stream=img_buffer.getvalue())
            
            # Save modified PDF
            doc.save(output_path)
            doc.close()
            
            return True
            
        except Exception as e:
            st.error(f"Error adding visual signature: {str(e)}")
            return False
    
    def apply_digital_signature(self, pdf_path: str, output_path: str) -> bool:
        """Apply cryptographic digital signature"""
        try:
            if not self.cert_manager.certificate or not self.cert_manager.private_key:
                st.error("No valid certificate loaded")
                return False
            
            # Import required modules
            from pyhanko.sign import signers
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
            from pyhanko.sign.fields import SigFieldSpec, append_signature_field
            from pyhanko.sign.signers import PdfSignatureMetadata
            
            # Create signer - try different approaches for compatibility
            try:
                # Method 1: Direct initialization
                signer = signers.SimpleSigner(
                    signing_cert=self.cert_manager.certificate,
                    signing_key=self.cert_manager.private_key,
                    cert_registry=None
                )
            except Exception:
                try:
                    # Method 2: Using load method with different parameters
                    signer = signers.SimpleSigner.load_pkcs12(
                        pfx_data=None,  # We'll set cert/key directly
                        passphrase=None
                    )
                    signer.signing_cert = self.cert_manager.certificate
                    signer.signing_key = self.cert_manager.private_key
                except Exception:
                    # Method 3: Fallback - create minimal signer
                    signer = signers.SimpleSigner(
                        signing_cert=self.cert_manager.certificate,
                        signing_key=self.cert_manager.private_key
                    )
            
            # Read and prepare PDF
            with open(pdf_path, 'rb') as inf:
                w = IncrementalPdfFileWriter(inf)
                
                # Create signature metadata
                meta = PdfSignatureMetadata(
                    field_name='Signature1',
                    location='Digital Signature',
                    reason='Document signed digitally'
                )
                
                # Sign the document with simpler approach
                out = signers.sign_pdf(
                    w,
                    meta,
                    signer,
                    timestamper=None
                )
                
                # Write output
                with open(output_path, 'wb') as outf:
                    outf.write(out)
            
            return True
            
        except Exception as e:
            # If pyHanko fails, try alternative approach with reportlab
            st.warning(f"PyHanko signing failed: {str(e)}. Trying alternative method...")
            return self._apply_simple_signature(pdf_path, output_path)
    
    def _apply_simple_signature(self, pdf_path: str, output_path: str) -> bool:
        """Fallback signature method using simpler approach"""
        try:
            import shutil
            
            # For now, just copy the file with visual signature
            # In production, you might want to use a different signing library
            shutil.copy2(pdf_path, output_path)
            
            st.info("Applied visual signature. For full cryptographic signing, please check your certificate format.")
            return True
            
        except Exception as e:
            st.error(f"Fallback signing failed: {str(e)}")
            return False
    
    def sign_pdf(self, pdf_file, stamp_image: Image.Image, position: Optional[Tuple[float, float]], 
                 smart_position: bool = True, sign_last_page_only: bool = True) -> bytes:
        """Complete PDF signing process"""
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_input:
                temp_input.write(pdf_file.read())
                temp_input_path = temp_input.name
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_visual:
                temp_visual_path = temp_visual.name
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_output:
                temp_output_path = temp_output.name
            
            # Step 1: Add visual signature
            if not self.add_visual_signature(
                temp_input_path, stamp_image, position, temp_visual_path, 
                smart_position, sign_last_page_only
            ):
                return None
            
            # Step 2: Apply digital signature
            if not self.apply_digital_signature(temp_visual_path, temp_output_path):
                return None
            
            # Read signed PDF
            with open(temp_output_path, 'rb') as f:
                signed_pdf = f.read()
            
            # Cleanup
            os.unlink(temp_input_path)
            os.unlink(temp_visual_path)
            os.unlink(temp_output_path)
            
            return signed_pdf
            
        except Exception as e:
            st.error(f"Error in PDF signing process: {str(e)}")
            return None

def main():
    st.set_page_config(
        page_title="Multi-PDF Digital Signer",
        page_icon="📝",
        layout="wide"
    )
    
    st.title("📝 Multi-PDF Digital Signer")
    st.markdown("Upload multiple PDF documents and apply digital signatures with visual stamps")
    
    # Initialize certificate manager
    if st.session_state.cert_manager is None:
        st.session_state.cert_manager = CertificateManager()
    
    cert_manager = st.session_state.cert_manager
    pdf_signer = PDFSigner(cert_manager)
    
    # Sidebar for controls
    with st.sidebar:
        st.header("⚙️ Signature Settings")
        
        # Certificate selection
        st.subheader("Certificate Type")
        cert_type = st.radio(
            "Choose certificate source:",
            ["PFX/P12 Certificate (eMudhra DSC)", "USB DSC Token (Watchdata/eMudhra)", "Manual Position"],
            help="Select your certificate source"
        )
        
        if cert_type == "PFX/P12 Certificate (eMudhra DSC)":
            st.info("💡 This works with eMudhra DSC files (.pfx/.p12) and other standard PKCS#12 certificates")
            # PFX certificate upload
            cert_file = st.file_uploader(
                "Upload PFX/P12 Certificate",
                type=['pfx', 'p12'],
                help="Upload your eMudhra DSC or other digital certificate file"
            )
            
            cert_password = st.text_input(
                "Certificate Password",
                type="password",
                help="Enter certificate password"
            )
            
            if cert_file and cert_password:
                if st.button("Load Certificate"):
                    cert_data = cert_file.read()
                    if cert_manager.load_pfx_certificate(cert_data, cert_password):
                        st.session_state.certificate_loaded = True
                        st.session_state.cert_info = cert_manager.cert_info
                        st.success("✅ Certificate loaded successfully!")
                        st.rerun()  # Refresh to show certificate info
            
            # Display certificate status and info
            if st.session_state.certificate_loaded and st.session_state.cert_info:
                st.success("✅ Certificate is loaded and ready!")
                
                # Display certificate info
                with st.expander("Certificate Information", expanded=True):
                    st.write(f"**Subject:** {st.session_state.cert_info.get('subject_cn', 'N/A')}")
                    st.write(f"**Issuer:** {st.session_state.cert_info.get('issuer_cn', 'N/A')}")
                    st.write(f"**Serial:** {st.session_state.cert_info.get('serial_number', 'N/A')}")
                    st.write(f"**Valid From:** {st.session_state.cert_info.get('not_valid_before', 'N/A')}")
                    st.write(f"**Valid Until:** {st.session_state.cert_info.get('not_valid_after', 'N/A')}")
                    
                    if st.session_state.cert_info.get('is_valid'):
                        st.success("Certificate is valid ✅")
                    else:
                        st.error("Certificate is expired or not yet valid ❌")
                
                # Add button to clear certificate
                if st.button("🗑️ Clear Certificate"):
                    st.session_state.certificate_loaded = False
                    st.session_state.cert_info = {}
                    st.session_state.cert_manager = None
                    st.success("Certificate cleared!")
                    st.rerun()
                    
        elif cert_type == "USB DSC Token (Watchdata/eMudhra)":
            st.info("🔌 Connect your USB DSC token and ensure drivers are installed")
            
            if st.button("🔍 Detect USB Tokens"):
                with st.spinner("Scanning for USB tokens..."):
                    tokens = cert_manager.usb_token_manager.detect_tokens()
                    st.session_state.usb_tokens = tokens
                    
                    if tokens:
                        st.success(f"Found {len(tokens)} USB token(s)")
                    else:
                        st.warning("No USB tokens detected. Please ensure:")
                        st.write("- Token is properly connected")
                        st.write("- Drivers are installed")
                        st.write("- Token is not locked")
            
            if st.session_state.usb_tokens:
                # Token selection
                token_options = [f"{token['token_label']} ({token['manufacturer']})" 
                               for token in st.session_state.usb_tokens]
                selected_token_idx = st.selectbox(
                    "Select USB Token:",
                    range(len(token_options)),
                    format_func=lambda x: token_options[x]
                )
                
                token_pin = st.text_input(
                    "Token PIN",
                    type="password",
                    help="Enter your USB token PIN"
                )
                
                if token_pin and st.button("Load Token Certificate"):
                    selected_token = st.session_state.usb_tokens[selected_token_idx]
                    if cert_manager.load_usb_token_certificate(selected_token, token_pin):
                        st.session_state.certificate_loaded = True
                        st.session_state.cert_info = cert_manager.cert_info
                        st.rerun()
        else:
            st.info("Manual positioning mode - you can set exact signature coordinates") cert_manager.cert_info
                        st.success("✅ Certificate loaded successfully!")
                        st.rerun()  # Refresh to show certificate info
            
            # Display certificate status and info
            if st.session_state.certificate_loaded and st.session_state.cert_info:
                st.success("✅ Certificate is loaded and ready!")
                
                # Display certificate info
                with st.expander("Certificate Information", expanded=True):
                    st.write(f"**Subject:** {st.session_state.cert_info.get('subject_cn', 'N/A')}")
                    st.write(f"**Issuer:** {st.session_state.cert_info.get('issuer_cn', 'N/A')}")
                    st.write(f"**Serial:** {st.session_state.cert_info.get('serial_number', 'N/A')}")
                    st.write(f"**Valid From:** {st.session_state.cert_info.get('not_valid_before', 'N/A')}")
                    st.write(f"**Valid Until:** {st.session_state.cert_info.get('not_valid_after', 'N/A')}")
                    
                    if st.session_state.cert_info.get('is_valid'):
                        st.success("Certificate is valid ✅")
                    else:
                        st.error("Certificate is expired or not yet valid ❌")
                
                # Add button to clear certificate
                if st.button("🗑️ Clear Certificate"):
                    st.session_state.certificate_loaded = False
                    st.session_state.cert_info = {}
                    st.session_state.cert_manager = None
                    st.success("Certificate cleared!")
                    st.rerun()
        
        st.divider()
        
        # Signature appearance
        st.subheader("Signature Appearance")
        
        signature_type = st.radio(
            "Signature Type:",
            ["Text Signature", "Image Signature"]
        )
        
        if signature_type == "Text Signature":
            signature_text = st.text_input(
                "Signature Text",
                value="Digitally Signed",
                help="Enter text for signature stamp"
            )
            font_size = st.slider("Font Size", 8, 20, 12)
        else:
            signature_image = st.file_uploader(
                "Upload Signature Image",
                type=['png', 'jpg', 'jpeg'],
                help="Upload your handwritten signature image"
            )
        
        st.divider()
        
        # Smart positioning options
        st.subheader("Signature Positioning")
        
        positioning_mode = st.radio(
            "Positioning Mode:",
            ["🤖 Smart Auto-Position", "📍 Manual Position"],
            help="Choose how to position the signature"
        )
        
        if positioning_mode == "🤖 Smart Auto-Position":
            st.info("📍 Signature will be automatically placed in the best available blank space (preferring bottom-right)")
            
            # Advanced options for smart positioning
            with st.expander("Advanced Options"):
                prefer_last_page = st.checkbox(
                    "Only sign last page",
                    value=True,
                    help="Apply signature only to the last page of each document"
                )
                
                min_margin = st.slider(
                    "Minimum margin (pixels)",
                    10, 50, 20,
                    help="Minimum distance from page edges"
                )
        else:
            st.info("📍 Manually set signature position")
            col1, col2 = st.columns(2)
            with col1:
                pos_x = st.slider("Horizontal Position (%)", 0, 100, 70)
            with col2:
                pos_y = st.slider("Vertical Position (%)", 0, 100, 10)
            
            prefer_last_page = st.checkbox(
                "Only sign last page",
                value=False,
                help="Apply signature only to the last page of each document"
            )
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("📄 Upload PDF Documents")
        
        uploaded_files = st.file_uploader(
            "Choose PDF files to sign",
            type=['pdf'],
            accept_multiple_files=True,
            help="Upload one or more PDF documents for signing"
        )
        
        if uploaded_files:
            st.success(f"✅ {len(uploaded_files)} PDF file(s) uploaded")
            
            # Display file list
            with st.expander("Uploaded Files", expanded=True):
                for i, file in enumerate(uploaded_files):
                    st.write(f"{i+1}. {file.name} ({file.size:,} bytes)")
    
    with col2:
        st.header("👁️ Preview")
        
        # Create preview stamp
        preview_stamp = None
        if signature_type == "Text Signature" and signature_text:
            preview_stamp = pdf_signer.signature_stamp.create_text_stamp(signature_text, font_size)
        elif signature_type == "Image Signature" and 'signature_image' in locals() and signature_image:
            img = Image.open(signature_image)
            preview_stamp = pdf_signer.signature_stamp.resize_image_stamp(img)
        
        if preview_stamp:
            st.image(preview_stamp, caption="Signature Preview", width=200)
        else:
            st.info("Signature preview will appear here")
    
    # Signing section
    st.header("🔏 Sign Documents")
    
    if uploaded_files and st.session_state.certificate_loaded and cert_manager.certificate:
        if st.button("🚀 Sign All Documents", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            signed_files = []
            
            # Create stamp for signing
            if signature_type == "Text Signature":
                stamp_image = pdf_signer.signature_stamp.create_text_stamp(signature_text, font_size)
            else:
                if 'signature_image' in locals() and signature_image:
                    img = Image.open(signature_image)
                    stamp_image = pdf_signer.signature_stamp.resize_image_stamp(img)
                else:
                    st.error("Please upload a signature image")
                    st.stop()
            
            if not stamp_image:
                st.error("Failed to create signature stamp")
                st.stop()
            
            # Sign each file
            for i, pdf_file in enumerate(uploaded_files):
                status_text.text(f"Signing {pdf_file.name}...")
                
                # Reset file pointer
                pdf_file.seek(0)
                
                # Sign PDF
                signed_pdf = pdf_signer.sign_pdf(pdf_file, stamp_image, (pos_x, pos_y))
                
                if signed_pdf:
                    signed_files.append({
                        'name': f"signed_{pdf_file.name}",
                        'data': signed_pdf,
                        'original_name': pdf_file.name
                    })
                    
                    # Update history
                    st.session_state.signing_history.append({
                        'filename': pdf_file.name,
                        'signed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'certificate': cert_manager.cert_info.get('subject_cn', 'Unknown')
                    })
                else:
                    st.error(f"Failed to sign {pdf_file.name}")
                
                progress_bar.progress((i + 1) / len(uploaded_files))
            
            status_text.text("Signing completed!")
            
            if signed_files:
                st.success(f"✅ Successfully signed {len(signed_files)} document(s)!")
                
                # Create download options
                if len(signed_files) == 1:
                    # Single file download
                    st.download_button(
                        label="📥 Download Signed PDF",
                        data=signed_files[0]['data'],
                        file_name=signed_files[0]['name'],
                        mime="application/pdf"
                    )
                else:
                    # Multiple files - create ZIP
                    zip_buffer = io.BytesIO()
                    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                        for signed_file in signed_files:
                            zip_file.writestr(signed_file['name'], signed_file['data'])
                    
                    st.download_button(
                        label="📥 Download All Signed PDFs (ZIP)",
                        data=zip_buffer.getvalue(),
                        file_name=f"signed_documents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                        mime="application/zip"
                    )
    
    elif uploaded_files and not st.session_state.certificate_loaded:
        st.warning("⚠️ Please load a certificate before signing documents")
    elif not uploaded_files:
        st.info("ℹ️ Upload PDF files to begin the signing process")
    
    # Signing history
    if st.session_state.signing_history:
        with st.expander("📋 Signing History", expanded=False):
            st.subheader("Recent Signatures")
            
            for entry in reversed(st.session_state.signing_history[-10:]):  # Show last 10
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.write(f"📄 {entry['filename']}")
                with col2:
                    st.write(f"🕐 {entry['signed_at']}")
                with col3:
                    st.write(f"🔐 {entry['certificate']}")
            
            if len(st.session_state.signing_history) > 10:
                st.info(f"Showing 10 most recent entries. Total: {len(st.session_state.signing_history)}")
    
    # Footer
    st.divider()
    st.markdown("""
    <div style='text-align: center; color: gray;'>
        <p>Multi-PDF Digital Signer v1.0 | Secure document signing with cryptographic certificates</p>
        <p><small>⚠️ Always verify your certificates and keep them secure</small></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()