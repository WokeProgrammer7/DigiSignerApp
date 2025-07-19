import os
import streamlit as st
import fitz  # PyMuPDF
import tempfile
import shutil
import datetime
import json
from pyhanko.sign.signers import SimpleSigner, PdfSigner
from pyhanko.sign.fields import SigFieldSpec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from PIL import Image, ImageDraw, ImageFont

# --- Config ---
st.set_page_config(page_title="PDF Signer", layout="centered")
st.title("📄 Multi-PDF Digital Signer")

# --- Inputs: PDFs and optional handwritten PNG ---
pdf_files = st.file_uploader(
    "Upload PDF files", type=["pdf"], accept_multiple_files=True
)
sig_image = st.file_uploader(
    "Upload handwritten signature image (optional)", type=["png"]
)

# --- Choose signing method ---
sign_method = st.radio(
    "Select signing method", [".pfx/.p12 File", "USB DSC Token"]
)

# --- Initialize signer ---
signer = None

# --- PFX setup ---
if sign_method == ".pfx/.p12 File":
    pfx_file = st.file_uploader(
        "Upload .pfx/.p12 certificate", type=["pfx", "p12"]
    )
    pfx_pass = st.text_input(
        "Enter certificate password", type="password"
    )
    if pfx_file and pfx_pass:
        # Save uploaded PFX to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pfx") as f:
            f.write(pfx_file.read())
            pfx_path = f.name
        try:
            # Load the signer using file path and passphrase
            signer = SimpleSigner.load_pkcs12(pfx_path, pfx_pass.encode())
            # Confirm loaded
            cn = signer.signing_cert.subject.native.get('common_name')
            st.success(f"✅ Loaded signer for {cn}")
        except Exception as e:
            st.error(f"Failed to load PFX: {e}")

# --- USB Token setup ---
elif sign_method == "USB DSC Token":
    try:
        import pkcs11
        from pkcs11 import Attribute, ObjectClass
        from pyhanko.sign.pkcs11 import PKCS11Signer
    except ImportError:
        st.error(
            "USB DSC support requires the 'pkcs11' library. "
            "Use PFX option or install Visual C++ Build Tools."
        )
    else:
        st.info("🔐 Insert token & enter PIN.")
        pkcs11_path = st.text_input(
            "PKCS#11 library path", "C:/Path/To/your-pkcs11.dll"
        )
        token_pin = st.text_input("Token PIN", type="password")
        if pkcs11_path and token_pin:
            try:
                lib = pkcs11.lib(pkcs11_path)
                slot = lib.get_slots()[0]
                token = lib.get_token(slot=slot)
                session = token.open(user_pin=token_pin)
                certs = list(
                    session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})
                )
                der = certs[0].get(Attribute.VALUE)
                cert = x509.load_der_x509_certificate(der, default_backend())
                signer = PKCS11Signer(pkcs11_session=session, signing_cert=cert)
                cn = signer.signing_cert.subject.native.get('common_name')
                st.success(f"✅ USB signer loaded for {cn}")
            except Exception as e:
                st.error(f"Failed to init USB signer: {e}")

# --- Placement Settings ---
st.sidebar.subheader("Stamp Placement Settings")
def_x = st.sidebar.number_input("X offset from right (pts)", value=50)
def_y = st.sidebar.number_input("Y offset from bottom (pts)", value=70)
def_w = st.sidebar.number_input("Stamp width (pts)", value=150)
def_h = st.sidebar.number_input("Stamp height (pts)", value=50)
preview = st.checkbox("🔍 Preview placement")
history_file = os.path.join(os.getcwd(), "signature_history.json")
if not os.path.exists(history_file):
    with open(history_file, "w") as f:
        json.dump([], f)

# Helper: compute rectangle for stamping
def get_stamp_rect(page):
    w, h = page.rect.width, page.rect.height
    x0 = w - def_w - def_x
    y0 = h - def_h - def_y
    return fitz.Rect(x0, y0, x0 + def_w, y0 + def_h)

# Preview placement
if preview and pdf_files:
    first_page = fitz.open(stream=pdf_files[0].read(), filetype="pdf")[0]
    st.write(f"Stamp at: {get_stamp_rect(first_page)}")

# --- Main signing logic ---
def sign_pdfs():
    global signer
    if signer is None:
        st.error("No signer available—please configure your certificate.")
        return
    history = []
    for pdf in pdf_files:
        # Build visible stamp image
        if sig_image:
            base = Image.open(sig_image).convert("RGBA")
        else:
            cn = signer.signing_cert.subject.native.get("common_name", "Signer")
            font0 = ImageFont.load_default()
            w0, h0 = font0.getsize(cn)
            base = Image.new("RGBA", (w0, h0), (255,255,255,0))
            ImageDraw.Draw(base).text((0,0), cn, font=font0, fill=(0,0,0,180))
        # Add timestamp lines
        now = datetime.datetime.now().astimezone().strftime("%Y.%m.%d %H:%M:%S %z")
        lines = [
            f"Digitally signed by {signer.signing_cert.subject.native.get('common_name')}",
            f"Date:{now}"
        ]
        font1 = ImageFont.load_default()
        maxw = max(font1.getsize(l)[0] for l in lines)
        canvas = Image.new(
            "RGBA",
            (base.width+10+maxw, max(base.height, sum(font1.getsize(l)[1] for l in lines)+5)),
            (255,255,255,0)
        )
        canvas.paste(base, (0,0), base)
        draw = ImageDraw.Draw(canvas)
        x = base.width + 10
        y = (canvas.height - sum(font1.getsize(l)[1] for l in lines)) // 2
        for l in lines:
            draw.text((x,y), l, font=font1, fill=(0,0,0,255))
            y += font1.getsize(l)[1]
        # Save temp stamp
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            canvas.save(tmp.name)
            stamp_path = tmp.name
        # Process PDF
        tmpdir = tempfile.mkdtemp()
        inp = os.path.join(tmpdir, pdf.name)
        outp = inp.replace('.pdf','_signed.pdf')
        with open(inp,'wb') as f: f.write(pdf.read())
        doc = fitz.open(inp)
        for page in doc:
            page.insert_image(get_stamp_rect(page), filename=stamp_path)
        stamped = inp.replace('.pdf','_stamped.pdf')
        doc.save(stamped)
        # Crypto sign
        with open(stamped,'rb') as inf, open(outp,'wb') as outf:
            PdfSigner(
                signature_meta=None,
                signer=signer,
                existing_fields_only=False,
                new_field_spec=SigFieldSpec(sig_field_name='sig1')
            ).sign_pdf(inf, output=outf)
        st.success(f"Signed: {pdf.name}")
        with open(outp,'rb') as f:
            st.download_button(f"Download {pdf.name}", f, file_name=os.path.basename(outp))
        history.append({"file":pdf.name, "time":datetime.datetime.now().isoformat(), "by":signer.signing_cert.subject.native.get('common_name')})
    # Save history log
    with open(history_file,'r+') as hf:
        data=json.load(hf)
        data.extend(history)
        hf.seek(0)
        json.dump(data,hf, indent=2)
    st.info("All done.")

# Button to sign
if st.button("🚀 Sign All PDFs"):
    if not pdf_files:
        st.error("Upload PDFs first.")
    else:
        sign_pdfs()

# History view
with st.expander("History"):
    with open(history_file) as hf:
        data = json.load(hf)
    if data:
        for e in reversed(data):
            st.write(f"✅ {e['file']} at {e['time']} by {e['by']}")
    else:
        st.write("No history.")
