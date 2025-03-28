import tkinter as tk
from tkinter import messagebox
from hashlib import sha256
import json
import os

usuarios_file = "usuarios.json"

def carregar_usuarios():
    if os.path.exists(usuarios_file):
        try:
            with open(usuarios_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def salvar_usuarios(usuarios):
    try:
        with open(usuarios_file, "w") as f:
            json.dump(usuarios, f, indent=4)
    except IOError as e:
        messagebox.showerror("Erro", f"Erro ao salvar usuários: {e}")

def gerar_hash_senha(senha, salt="sistema_login"):
    return sha256((senha + salt).encode()).hexdigest()

def autenticar_usuario(nome_usuario, senha):
    usuarios = carregar_usuarios()
    senha_hash = gerar_hash_senha(senha)
    return usuarios.get(nome_usuario) == senha_hash

def login():
    nome_usuario = entry_usuario.get()
    senha = entry_senha.get()
    
    if not nome_usuario or not senha:
        messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
        return
    
    if autenticar_usuario(nome_usuario, senha):
        messagebox.showinfo("Sucesso", "Login realizado com sucesso!")
        window.destroy()
        abrir_sistema(nome_usuario)
    else:
        messagebox.showerror("Erro", "Usuário ou senha incorretos!")

def criar_interface_login():
    global window, entry_usuario, entry_senha
    window = tk.Tk()
    window.title("Sistema de Login")
    window.geometry("400x300")
    window.configure(bg="#f0f0f0")
    
    frame_login = tk.Frame(window, bg="#f0f0f0")
    frame_login.pack(pady=50)
    
    tk.Label(frame_login, text="Nome de usuário:", bg="#f0f0f0", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10)
    entry_usuario = tk.Entry(frame_login, font=("Arial", 12))
    entry_usuario.grid(row=0, column=1, padx=10, pady=10)
    
    tk.Label(frame_login, text="Senha:", bg="#f0f0f0", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=10)
    entry_senha = tk.Entry(frame_login, show="*", font=("Arial", 12))
    entry_senha.grid(row=1, column=1, padx=10, pady=10)
    
    btn_login = tk.Button(frame_login, text="Entrar", command=login, bg="#4CAF50", fg="white", font=("Arial", 12), relief="flat")
    btn_login.grid(row=2, columnspan=2, pady=20)
    btn_login.bind("<Enter>", lambda e: btn_login.config(bg="#45a049"))
    btn_login.bind("<Leave>", lambda e: btn_login.config(bg="#4CAF50"))
    
    window.mainloop()

def abrir_sistema(nome_usuario):
    system_window = tk.Tk()
    system_window.title("Sistema Principal")
    system_window.geometry("500x400")
    system_window.configure(bg="#f0f0f0") 
    
    label_bem_vindo = tk.Label(system_window, text=f"Bem-vindo, {nome_usuario}!", font=("Arial", 16), bg="#f0f0f0")
    label_bem_vindo.pack(pady=50)

    btn_configuracoes = tk.Button(system_window, text="Configurações", command=lambda: abrir_configuracoes(nome_usuario), bg="#4CAF50", fg="white", font=("Arial", 12), relief="flat")
    btn_configuracoes.pack(pady=20)
    
    system_window.mainloop()

def abrir_configuracoes(nome_usuario):
    config_window = tk.Tk()
    config_window.title("Configurações")
    config_window.geometry("500x400")
    config_window.configure(bg="#f0f0f0")
    
    label_titulo = tk.Label(config_window, text="Configurações de Usuário", font=("Arial", 16), bg="#f0f0f0")
    label_titulo.pack(pady=30)

    tk.Label(config_window, text="Nova Senha:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
    entry_nova_senha = tk.Entry(config_window, show="*", font=("Arial", 12))
    entry_nova_senha.pack(pady=5)

    def atualizar_senha():
        nova_senha = entry_nova_senha.get()
        if nova_senha:
            usuarios = carregar_usuarios()
            senha_hash = gerar_hash_senha(nova_senha)
            usuarios[nome_usuario] = senha_hash
            salvar_usuarios(usuarios)
            messagebox.showinfo("Sucesso", "Senha alterada com sucesso!")
        else:
            messagebox.showerror("Erro", "Por favor, preencha o campo de senha.")
    
    btn_atualizar_senha = tk.Button(config_window, text="Alterar Senha", command=atualizar_senha, bg="#FF9800", fg="white", font=("Arial", 12), relief="flat")
    btn_atualizar_senha.pack(pady=10)

    btn_fechar = tk.Button(config_window, text="Fechar", command=config_window.destroy, bg="#f44336", fg="white", font=("Arial", 12), relief="flat")
    btn_fechar.pack(pady=20)

    config_window.mainloop()

def primeira_execucao():
    return not os.path.exists(usuarios_file)

def executar_assistente_configuracao():
    window_assistente = tk.Tk()
    window_assistente.title("Configuração Inicial")
    window_assistente.geometry("500x400")
    window_assistente.configure(bg="#f0f0f0")
    
    tk.Label(window_assistente, text="Bem-vindo ao sistema!\nPor favor, configure o usuário administrador.", font=("Arial", 14), bg="#f0f0f0").pack(pady=20)
    
    tk.Label(window_assistente, text="Nome de usuário:", font=("Arial", 12), bg="#f0f0f0").pack()
    entry_admin_usuario = tk.Entry(window_assistente, font=("Arial", 12))
    entry_admin_usuario.pack()
    
    tk.Label(window_assistente, text="Senha:", font=("Arial", 12), bg="#f0f0f0").pack()
    entry_admin_senha = tk.Entry(window_assistente, show="*", font=("Arial", 12))
    entry_admin_senha.pack()
    
    def finalizar_configuracao():
        usuario = entry_admin_usuario.get()
        senha = entry_admin_senha.get()
        
        if usuario and senha:
            usuarios = carregar_usuarios()
            senha_hash = gerar_hash_senha(senha)
            usuarios[usuario] = senha_hash
            salvar_usuarios(usuarios)
            messagebox.showinfo("Sucesso", "Configuração inicial concluída!")
            window_assistente.destroy()
        else:
            messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
    
    tk.Button(window_assistente, text="Concluir", command=finalizar_configuracao, bg="#4CAF50", fg="white", font=("Arial", 12), relief="flat").pack(pady=20)
    
    window_assistente.mainloop()

if primeira_execucao():
    executar_assistente_configuracao()

criar_interface_login()