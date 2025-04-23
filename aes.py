import base64
import os
import gradio as gr
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# AES Encryption
def encrypt_message(message):
    key = os.urandom(16)  # AES 128-bit key
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_data = base64.b64encode(iv + ciphertext).decode()
    encoded_key = base64.b64encode(key).decode()

    return encoded_key, encrypted_data

# AES Decryption
def decrypt_message(key_text, encrypted_text):
    try:
        key = base64.b64decode(key_text)
        encrypted_data = base64.b64decode(encrypted_text)

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode()
    except Exception as e:
        return f"❌ Decryption failed: {str(e)}"

# Gradio UI
with gr.Blocks(theme=gr.themes.Soft()) as demo:
    gr.Markdown(
        """
        # 🔐 AES Encryption & Decryption (128-bit)
        Securely encrypt and decrypt messages with AES-128 in CBC mode.
        """
    )

    with gr.Row():
        with gr.Column():
            with gr.Group():
                gr.Markdown("### ✉️ Sender Panel")
                msg_input = gr.Textbox(label="🔏 Message to Encrypt", placeholder="Type your secret message...")
                encrypt_btn = gr.Button("🔐 Encrypt Message")
                key_output = gr.Textbox(label="🗝️ Generated Key", interactive=False)
                encrypted_output = gr.Textbox(label="📦 Encrypted Message", interactive=False)

                encrypt_btn.click(
                    fn=encrypt_message,
                    inputs=[msg_input],
                    outputs=[key_output, encrypted_output]
                )

        with gr.Column():
            with gr.Group():
                gr.Markdown("### 📥 Receiver Panel")
                encrypted_input = gr.Textbox(label="📦 Encrypted Message", placeholder="Paste the encrypted message...")
                key_input = gr.Textbox(label="🗝️ Encryption Key", placeholder="Paste the key you received...")
                decrypt_btn = gr.Button("🧩 Decrypt")
                decrypted_output = gr.Textbox(label="📨 Decrypted Message", interactive=False)

                decrypt_btn.click(
                    fn=decrypt_message,
                    inputs=[key_input, encrypted_input],
                    outputs=[decrypted_output]
                )

    gr.Markdown("---")
    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown(
                """
                <div style='text-align: center; font-size: 14px; color: gray;'>
                    Built with ❤️ using <a href="https://gradio.app" target="_blank">Gradio</a> by GOURI BISWAS 🔐 | 
                    <a href="https://github.com/GouriBiswas" target="_blank">GitHub</a> | 
                    <a href="mailto:gouribiswas011@email@example.com">Contact</a>
                </div>
                """,
                elem_id="footer"
            )

demo.css = """
#footer a {
    color: #3b82f6;
    text-decoration: none;
    transition: color 0.2s ease;
}
#footer a:hover {
    color: #2563eb;
}
"""

demo.launch()

