@"

\# 📝 DigiSignerApp - Advanced PDF Digital Signer



A comprehensive Streamlit application for digitally signing PDF documents with support for Indian Digital Signature Certificates (DSC), eMudhra certificates, and USB DSC tokens.



!\[Python](https://img.shields.io/badge/python-v3.8+-blue.svg)

!\[Streamlit](https://img.shields.io/badge/streamlit-v1.28+-red.svg)

!\[License](https://img.shields.io/badge/license-MIT-green.svg)



\## ✨ Features



\### 🔐 \*\*Certificate Support\*\*

\- \*\*eMudhra DSC\*\* (.pfx/.p12 files) - Class 2 \& Class 3

\- \*\*USB DSC Tokens\*\* (Watchdata, eMudhra, SafeNet)

\- \*\*PKCS#11 Compatible Devices\*\*

\- \*\*Certificate Validation\*\* and expiration checking



\### 🤖 \*\*Smart Signature Positioning\*\*

\- \*\*Automatic Blank Space Detection\*\* - Finds optimal placement

\- \*\*Content-Aware Positioning\*\* - Avoids text and images

\- \*\*Bottom-Right Preference\*\* - Professional document appearance

\- \*\*Manual Override\*\* - Traditional position controls available



\### 📄 \*\*PDF Processing\*\*

\- \*\*Batch Processing\*\* - Sign multiple PDFs simultaneously

\- \*\*Visual Signatures\*\* - Text or image-based stamps

\- \*\*Cryptographic Signing\*\* - Full digital signature compliance

\- \*\*Last Page Only\*\* - Option for contracts and agreements



\## 🚀 Quick Start



\### Installation

``````bash

\# Clone the repository

git clone https://github.com/WokeProgrammer7/DigiSignerApp.git

cd DigiSignerApp



\# Create virtual environment

python -m venv venv

venv\\Scripts\\activate  # Windows



\# Install dependencies

pip install -r requirements.txt



\# Run the application

streamlit run app.py

