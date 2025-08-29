import math
import os
import random
import re
import string
import sys
import tkinter as tk
from tkinter import ttk, messagebox

# -----------------------------
# Password strength evaluation
# -----------------------------

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111", "123123",
    "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein", "login",
    "football", "princess", "solo", "starwars", "passw0rd", "trustno1"
}

COMMON_PATTERNS = [
    r"qwerty", r"asdf", r"zxcv", r"12345", r"password", r"letmein", r"admin",
    r"passw0rd", r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b",
]

KEYBOARD_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
]

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    # Frequency of each character
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    # Shannon entropy per symbol (bits)
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    # Total information ~ per-symbol entropy * length
    return entropy * length


def repeated_sequences_penalty(pw: str) -> int:
    # Penalize immediate repeats like 'aaaa', 'ababab', 'xyzxyz'
    penalty = 0
    # Same char runs
    runs = re.findall(r"(.)\1{2,}", pw)
    penalty += 5 * len(runs)
    # Repeated chunks of length 2-4
    for n in range(2, 5):
        pattern = re.compile(rf"(.{{{n}}})\\1+")
        if pattern.search(pw):
            penalty += 5
    return penalty


def sequence_penalty(pw: str) -> int:
    p = 0
    low_pw = pw.lower()
    for seq in KEYBOARD_SEQUENCES:
        if any(seq[i:i+4] in low_pw for i in range(0, len(seq)-3)):
            p += 5
        if any(seq[::-1][i:i+4] in low_pw for i in range(0, len(seq)-3)):
            p += 5
    # Alpha or digit ascending sequences (e.g., abcd, 7890)
    if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|7890)", low_pw):
        p += 5
    if re.search(r"(?:abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)", low_pw):
        p += 5
    return p


def dictionary_penalty(pw: str) -> int:
    low = pw.lower()
    p = 0
    if low in COMMON_PASSWORDS:
        p += 30
    for pat in COMMON_PATTERNS:
        if re.search(pat, low):
            p += 10
    return p


def variety_score(pw: str) -> (int, list):
    suggestions = []
    sets = {
        'lowercase': any(c.islower() for c in pw),
        'uppercase': any(c.isupper() for c in pw),
        'digits': any(c.isdigit() for c in pw),
        'symbols': any(c in string.punctuation for c in pw),
    }
    score = sum(sets.values()) * 5  # up to 20
    if not sets['lowercase']:
        suggestions.append("add lowercase letters")
    if not sets['uppercase']:
        suggestions.append("add uppercase letters")
    if not sets['digits']:
        suggestions.append("add digits")
    if not sets['symbols']:
        suggestions.append("add symbols (e.g., !@#&)")
    return score, suggestions


def length_score(pw: str) -> (int, list):
    L = len(pw)
    suggestions = []
    # up to 40 points for length
    if L >= 20:
        score = 40
    elif L >= 16:
        score = 34
    elif L >= 12:
        score = 28
    elif L >= 10:
        score = 22
    elif L >= 8:
        score = 16
    elif L >= 6:
        score = 10
    else:
        score = 0
        suggestions.append("use at least 12 characters")
    if L < 12:
        suggestions.append("longer is stronger; aim for 14+")
    return score, suggestions


def estimate_strength(password: str):
    """Return (score 0–100, verdict str, suggestions [str])."""
    if not password:
        return 0, "", []

    score = 0
    suggestions = []

    # Base: length + variety
    ls, ls_sugg = length_score(password)
    vs, vs_sugg = variety_score(password)
    score += ls + vs
    suggestions += ls_sugg + vs_sugg

    # Entropy bonus (scaled)
    ent = shannon_entropy(password)
    score += min(int(ent / 2), 30)  # cap entropy bonus at 30

    # Penalties
    score -= repeated_sequences_penalty(password)
    score -= sequence_penalty(password)
    score -= dictionary_penalty(password)

    # Clamp
    score = max(0, min(100, score))

    # Verdict
    if score < 30:
        verdict = "Very Weak"
    elif score < 50:
        verdict = "Weak"
    elif score < 70:
        verdict = "Fair"
    elif score < 85:
        verdict = "Strong"
    else:
        verdict = "Very Strong"

    # Clean up suggestions
    # Remove duplicates while preserving order
    seen = set()
    cleaned = []
    for s in suggestions:
        if s and s not in seen:
            cleaned.append(s)
            seen.add(s)

    # Contextual advice
    if re.search(r"\b(?:name|user|email|phone)\b", password, re.I):
        cleaned.append("avoid personal info like names/emails")
    if any(password.lower().startswith(x) for x in ("admin", "user", "test")):
        cleaned.append("avoid common prefixes like admin/test")

    return score, verdict, cleaned[:6]


# -----------------------------
# Password generator
# -----------------------------

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        # Avoid visually confusing chars
        pools.append("!@#$%^&*()-_=+[]{};:,.?/")

    if not pools:
        return ""

    # Ensure at least one from each selected category
    pw_chars = [random.choice(pool) for pool in pools]

    # Fill remaining
    all_chars = "".join(pools)
    pw_chars += [random.choice(all_chars) for _ in range(max(0, length - len(pw_chars)))]

    # Shuffle for randomness
    random.shuffle(pw_chars)
    return "".join(pw_chars)


# -----------------------------
# GUI (Tkinter)
# -----------------------------

class PasswordTesterApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)
        self.create_widgets()
        self.password_visible = tk.BooleanVar(value=False)

    def create_widgets(self):
        self.master.title("Password Strength Tester")
        self.master.minsize(560, 380)
        try:
            self.master.iconbitmap(False, "")  # No default icon; keep try/except for cross‑platform
        except Exception:
            pass

        # Styles
        style = ttk.Style()
        # On some platforms, 'clam' allows progressbar color changes
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure("Meter.Horizontal.TProgressbar", thickness=18)

        # Input row
        input_frame = ttk.Frame(self)
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Enter password:").pack(side=tk.LEFT)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(input_frame, width=40, textvariable=self.pw_var, show="*")
        self.pw_entry.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        self.pw_entry.bind('<KeyRelease>', self.on_password_change)

        self.show_chk = ttk.Checkbutton(input_frame, text="Show", command=self.toggle_visibility)
        self.show_chk.pack(side=tk.LEFT, padx=6)

        copy_btn = ttk.Button(input_frame, text="Copy", command=self.copy_password)
        copy_btn.pack(side=tk.LEFT, padx=(6,0))

        # Strength meter
        meter_frame = ttk.Frame(self)
        meter_frame.pack(fill=tk.X)

        self.meter = ttk.Progressbar(meter_frame, orient=tk.HORIZONTAL, mode='determinate',
                                     maximum=100, length=300, style="Meter.Horizontal.TProgressbar")
        self.meter.pack(fill=tk.X, expand=True)

        self.verdict_lbl = ttk.Label(meter_frame, text="", font=("Segoe UI", 11, "bold"))
        self.verdict_lbl.pack(anchor=tk.W, pady=(6, 0))

        # Suggestions
        sugg_frame = ttk.LabelFrame(self, text="Suggestions")
        sugg_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 10))
        self.sugg_list = tk.Listbox(sugg_frame, height=6)
        self.sugg_list.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Generator controls
        gen_frame = ttk.LabelFrame(self, text="Generate a strong password")
        gen_frame.pack(fill=tk.X)

        self.len_var = tk.IntVar(value=16)
        ttk.Label(gen_frame, text="Length:").pack(side=tk.LEFT, padx=(8, 4))
        self.len_spin = ttk.Spinbox(gen_frame, from_=8, to=64, width=5, textvariable=self.len_var)
        self.len_spin.pack(side=tk.LEFT)

        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=True)
        for text, var in [("Upper", self.upper_var), ("Lower", self.lower_var), ("Digits", self.digit_var), ("Symbols", self.symbol_var)]:
            ttk.Checkbutton(gen_frame, text=text, variable=var).pack(side=tk.LEFT, padx=6)

        ttk.Button(gen_frame, text="Generate", command=self.generate_clicked).pack(side=tk.RIGHT, padx=8, pady=8)

        # Footer tips
        tip = ("Tip: Use passphrases (4–5 random words), avoid reuse, and enable 2FA where possible.")
        ttk.Label(self, text=tip, foreground="#555").pack(anchor=tk.W, pady=(8, 0))

    # ------------- Events / Actions -------------

    def toggle_visibility(self):
        current = self.pw_entry.cget('show')
        self.pw_entry.config(show='' if current == '*' else '*')

    def copy_password(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showinfo("Copy", "Nothing to copy yet.")
            return
        self.clipboard_clear()
        self.clipboard_append(pw)
        messagebox.showinfo("Copy", "Password copied to clipboard.")

    def on_password_change(self, event=None):
        pw = self.pw_var.get()
        score, verdict, suggestions = estimate_strength(pw)
        self.update_meter(score, verdict)
        self.update_suggestions(suggestions)

    def update_meter(self, score: int, verdict: str):
        self.meter['value'] = score
        # Dynamic color by score
        style = ttk.Style()
        if score < 30:
            color = '#e74c3c'  # red
        elif score < 50:
            color = '#e67e22'  # orange
        elif score < 70:
            color = '#f1c40f'  # yellow
        elif score < 85:
            color = '#2ecc71'  # green
        else:
            color = '#27ae60'  # dark green
        style.configure("Meter.Horizontal.TProgressbar", troughcolor='#eee', background=color)
        self.verdict_lbl.config(text=f"{score:3d} / 100 — {verdict}")

    def update_suggestions(self, suggestions):
        self.sugg_list.delete(0, tk.END)
        if not suggestions:
            self.sugg_list.insert(tk.END, "Looking good! Consider using a unique passphrase.")
        else:
            for s in suggestions:
                self.sugg_list.insert(tk.END, f"• {s}")

    def generate_clicked(self):
        length = max(8, min(64, int(self.len_var.get() or 16)))
        pw = generate_password(length, self.upper_var.get(), self.lower_var.get(),
                               self.digit_var.get(), self.symbol_var.get())
        if not pw:
            messagebox.showwarning("Generator", "Select at least one character set.")
            return
        self.pw_var.set(pw)
        self.on_password_change()
        # Auto-copy generated password for convenience
        self.clipboard_clear()
        self.clipboard_append(pw)


# -----------------------------
# Entry point
# -----------------------------

def main():
    root = tk.Tk()
    # Improve HiDPI rendering on Windows
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app = PasswordTesterApp(root)
    app.on_password_change()
    app.mainloop()


if __name__ == "__main__":
    random.seed(os.urandom(32))
    main()
