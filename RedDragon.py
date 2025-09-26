import sys
import ctypes
from pathlib import Path
from tkinter import Tk, Canvas, Entry, Button, PhotoImage, font, messagebox, filedialog
import os
import struct
import random
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# -------------------- BASE DIR --------------------
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).parent

ASSETS_PATH_SPLASH = BASE_DIR / "assets" / "frame1"
ASSETS_PATH_MAIN = BASE_DIR / "assets" / "frame0"
ICON_PATH = BASE_DIR / "image_3.ico"

# -------------------- TASKBAR ICON --------------------
def set_taskbar_icon():
    """Set Windows taskbar icon for current process (must be BEFORE Tk() window)."""
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(u"RedDragon.App")

# -------------------- SAFE ICON LOADING --------------------
def set_window_icon(window):
    try:
        window.iconbitmap(str(ICON_PATH))  # Standard ICO
    except:
        try:
            icon = PhotoImage(file=str(ICON_PATH))
            window.tk.call("wm", "iconphoto", window._w, icon)
        except Exception as e:
            print("Failed to load icon:", e)

# -------------------- UTILITY --------------------
def relative_to_assets(filename: str, splash=True):
    folder = "frame1" if splash else "frame0"
    return BASE_DIR / "assets" / folder / filename

# -------------------- FILE ENCRYPTION --------------------
MAGIC = b"SENC"
VERSION = 1
KDF_PBKDF2 = 2
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERS = 300_000
selected_file = None

def derive_key_pbkdf2(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(password)

def encrypt_file(in_path: Path, out_path: Path, password: str):
    password_b = password.encode("utf-8")
    salt = os.urandom(SALT_SIZE)
    key = derive_key_pbkdf2(password_b, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    plaintext = in_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    with out_path.open("wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("B", VERSION))
        f.write(struct.pack("B", KDF_PBKDF2))
        f.write(struct.pack("B", len(salt)))
        f.write(salt)
        f.write(struct.pack("B", len(nonce)))
        f.write(nonce)
        f.write(struct.pack(">Q", len(ciphertext)))
        f.write(ciphertext)

def decrypt_file(in_path: Path, out_path: Path, password: str):
    data = in_path.read_bytes()
    offset = 0
    if data[offset:offset+4] != MAGIC: raise ValueError("Not a supported encrypted file")
    offset += 4
    version = data[offset]; offset += 1
    salt_len = data[offset+1]; salt = data[offset+2:offset+2+salt_len]; offset += 2+salt_len
    nonce_len = data[offset]; nonce = data[offset+1:offset+1+nonce_len]; offset += 1+nonce_len
    (ct_len,) = struct.unpack(">Q", data[offset: offset + 8]); offset += 8
    ciphertext = data[offset: offset + ct_len]
    key = derive_key_pbkdf2(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    out_path.write_bytes(plaintext)

# -------------------- FILE SELECTION --------------------
def select_file():
    global selected_file
    path = filedialog.askopenfilename()
    if path:
        selected_file = Path(path)
        file_btn.configure(text=f"Selected: {selected_file.name}")

def detect_file_action(file_path: Path):
    try:
        with file_path.open("rb") as f:
            header = f.read(4)
        return "decrypt" if header == MAGIC else "encrypt"
    except:
        return "encrypt"

def run_action():
    if not selected_file:
        messagebox.showerror("Error", "No file selected!")
        return
    password = entry_1.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    output_path = selected_file.parent / f"{selected_file.stem}_out{selected_file.suffix}"
    action = detect_file_action(selected_file)
    try:
        if action == "encrypt":
            encrypt_file(selected_file, output_path, password)
            messagebox.showinfo("Success", f"Encrypted -> {output_path}")
        else:
            decrypt_file(selected_file, output_path, password)
            messagebox.showinfo("Success", f"Decrypted -> {output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# -------------------- WINDOW DRAGGING --------------------
def make_window_draggable(window, widget):
    def start_move(event):
        window._x = event.x
        window._y = event.y
    def do_move(event):
        x = window.winfo_pointerx() - window._x
        y = window.winfo_pointery() - window._y
        window.geometry(f"+{x}+{y}")
    widget.bind("<ButtonPress-1>", start_move)
    widget.bind("<B1-Motion>", do_move)

# -------------------- SPLASH SCREEN --------------------
def show_splash():
    set_taskbar_icon()
    splash = Tk()
    splash.overrideredirect(True)
    splash.geometry("705x513+400+200")
    splash.configure(bg="#FFFFFF")
    set_window_icon(splash)

    canvas = Canvas(splash, bg="#FFFFFF", height=513, width=705, bd=0, highlightthickness=0)
    canvas.place(x=0, y=0)
    splash.images = {}
    for name in ["image_1","image_2","image_3"]:
        splash.images[name] = PhotoImage(file=relative_to_assets(f"{name}.png", splash=True))
    canvas.create_image(352,256,image=splash.images["image_1"])
    canvas.create_image(62,497,image=splash.images["image_2"])
    canvas.create_image(353,257,image=splash.images["image_3"])

    make_window_draggable(splash, canvas)
    splash.after(3000, lambda: (splash.destroy(), show_main()))
    splash.mainloop()

# -------------------- MAIN GUI --------------------
def show_main():
    global entry_1, file_btn
    set_taskbar_icon()
    window = Tk()
    window.overrideredirect(True)
    window.geometry("705x513+400+200")
    window.configure(bg="#FFFFFF")
    set_window_icon(window)

    canvas = Canvas(window, bg="#FFFFFF", height=513, width=705, bd=0, highlightthickness=0)
    canvas.place(x=0, y=0)
    window.images = {}
    make_window_draggable(window, canvas)

    close_btn = Button(window, text="×", font=("Arial",14,"bold"), bd=0,bg="#000716",fg="#FFFFFF",
                       command=window.destroy, highlightthickness=0, relief="flat", cursor="hand2")
    close_btn.place(x=680,y=2,width=20,height=20)

    # Load all images
    for name in ["image_1","image_2","image_3","image_4","button_1","button_2","entry_1"]:
        window.images[name] = PhotoImage(file=relative_to_assets(f"{name}.png", splash=False))
    canvas.create_image(352,256,image=window.images["image_1"])
    canvas.create_image(68,497,image=window.images["image_2"])
    canvas.create_image(352,140,image=window.images["image_4"])
    canvas.create_image(353,335,image=window.images["image_3"])
    canvas.create_image(353.5,335.5,image=window.images["entry_1"])

    # Entry and buttons
    entry_font = font.Font(family="Arial", size=14)
    entry_1 = Entry(window, bd=0, bg="#232A31", fg="#FFFFFF", highlightthickness=0,
                    font=entry_font, show="•", insertbackground="#FFFFFF")
    entry_1.place(x=114,y=318,width=479,height=33)

    file_btn = Button(window, image=window.images["button_2"], bd=0, relief="flat", highlightthickness=0,
                      activebackground="#232A31", command=select_file)
    file_btn.place(x=278,y=241,width=146,height=43.5)

    run_btn = Button(window, image=window.images["button_1"], bd=0, relief="flat", highlightthickness=0,
                     activebackground="#232A31", command=run_action)
    run_btn.place(x=279,y=403,width=148,height=45)

    canvas.create_text(101,290,anchor="nw", text="Password", fill="#FFFFFF",
                       font=("NothingFont5x7", 16*-1))

    window.mainloop()

# -------------------- START --------------------
if __name__ == "__main__":
    show_splash()
