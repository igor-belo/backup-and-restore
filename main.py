import tkinter as tk
from tkinter import StringVar, BooleanVar, filedialog, messagebox
from PIL import Image, ImageTk
import subprocess
import threading
import os
import psycopg2
import ttkbootstrap as tb 
import base64
import io

# Configurações fixas
PG_RESTORE_PATH = r'C:\Program Files (x86)\PostgreSQL\11\bin\pg_restore.exe'
PG_HOST = 'localhost'
PG_PORT = '5432'


def listar_bases(user, password):
    try:
        conn = psycopg2.connect(
            dbname='postgres',
            user=user,
            password=password,
            host=PG_HOST,
            port=PG_PORT
        )
        cur = conn.cursor()
        cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres')")
        bases = [row[0] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return bases
    except Exception as e:
        messagebox.showerror("Erro ao listar bases", str(e))
        return []


class App(tb.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Backup & Restore")
        self.geometry("800x620")
        self.icon_setup()  # Chama a função de ícone

        self.frames = {}

        self.PG_USER = tk.StringVar()
        self.PG_PASSWORD = tk.StringVar()

        for F in (MainMenu, RestoreScreen, BackupScreen):
            frame = F(self, self.PG_USER, self.PG_PASSWORD)
            self.frames[F] = frame
            frame.place(relwidth=1, relheight=1)

        self.show_frame(MainMenu)

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()
        if hasattr(frame, "atualizar_bases"):
            frame.atualizar_bases()

    def icon_setup(self):
        # Substitua o valor abaixo pelo seu código base64
        icon_base64 = '''iVBORw0KGgoAAAANSUhEUgAAAIgAAACICAYAAAA8uqNSAAAACXBIWXMAAAsTAAALEwEAmpwYAAAFJmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgOS4xLWMwMDIgNzkuYTZhNjM5NiwgMjAyNC8wMy8xMi0wNzo0ODoyMyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25zLmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIDI1LjEyICgyMDI0MDcyMi5tLjI3MDggN2UwZTVjZSkgIChXaW5kb3dzKSIgeG1wOkNyZWF0ZURhdGU9IjIwMjQtMDctMjNUMjE6NDA6NTgtMDM6MDAiIHhtcDpNb2RpZnlEYXRlPSIyMDI0LTA3LTIzVDIxOjQyOjMwLTAzOjAwIiB4bXA6TWV0YWRhdGFEYXRlPSIyMDI0LTA3LTIzVDIxOjQyOjMwLTAzOjAwIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpkZTY0ZDQyNi0xZDJjLTY0NGQtOGMxZC1mMWVh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'''

        image_data = base64.b64decode(icon_base64)
        image = Image.open(io.BytesIO(image_data))
        icon = ImageTk.PhotoImage(image)
        self.iconphoto(False, icon)


class MainMenu(tb.Frame):
    def __init__(self, master, PG_USER, PG_PASSWORD):
        super().__init__(master)
        self.PG_USER = PG_USER
        self.PG_PASSWORD = PG_PASSWORD

        tb.Label(self, text="Backup and Restore", font=("Roboto", 20)).pack(pady=50)

        tb.Label(self, text="Usuário:").pack()
        tb.Entry(self, textvariable=self.PG_USER, width=30).pack(pady=5)

        tb.Label(self, text="Senha:").pack()
        tb.Entry(self, textvariable=self.PG_PASSWORD, show="*", width=30).pack(pady=5)

        tb.Button(self, text="Restore", bootstyle="primary-outline", width=30,
                  command=lambda: master.show_frame(RestoreScreen)).pack(pady=(40,10))
        tb.Button(self, text="Backup", bootstyle="primary-outline", width=30,
                  command=lambda: master.show_frame(BackupScreen)).pack(pady=10)

        tb.Label(self, text="Developed by igorbelo.sup.shop", font=("Roboto", 10, "italic"), bootstyle="info").pack(pady=(40, 0))


class RestoreScreen(tb.Frame):
    def __init__(self, master, PG_USER, PG_PASSWORD):
        super().__init__(master)
        self.PG_USER = PG_USER
        self.PG_PASSWORD = PG_PASSWORD

        tb.Label(self, text="Restaurar Backup PostgreSQL", font=("Roboto", 18, "bold")).pack(pady=50)

        tb.Label(self, text="Selecione a Base de Dados:").pack()
        self.combo_dbname = tb.Combobox(self, width=50, state="readonly", bootstyle="primary")
        self.combo_dbname.pack(pady=5)

        tb.Label(self, text="Arquivo de Backup:").pack()

        frame_arquivo = tb.Frame(self)
        frame_arquivo.pack(pady=15)

        self.entry_arquivo = tb.Entry(frame_arquivo, width=40)
        self.entry_arquivo.pack(side=tk.LEFT, padx=5)

        tb.Button(frame_arquivo, text="Selecionar", command=self.selecionar_arquivo, bootstyle="secondary").pack(side=tk.LEFT)

        self.btn_restaurar = tb.Button(self, text="Restaurar Backup", command=self.restaurar_backup, bootstyle="primary")
        self.btn_restaurar.pack(pady=15)

        self.barra_progresso = tb.Progressbar(self, mode='indeterminate', length=330, bootstyle="info-solid")
        self.barra_progresso.pack(pady=15)

        self.label_status = tb.Label(self, text="", font=("Roboto", 10))
        self.label_status.pack(pady=15)

        tb.Button(self, text="Voltar", command=lambda: master.show_frame(MainMenu), bootstyle="secondary").pack(pady=10)

    def atualizar_bases(self):
        user = self.PG_USER.get()
        password = self.PG_PASSWORD.get()
        self.combo_dbname.set('')
        self.combo_dbname['values'] = listar_bases(user, password)

    def selecionar_arquivo(self):
        caminho = filedialog.askopenfilename(filetypes=[("Backups PostgreSQL", "*.bcir *.backup")])
        if caminho:
            self.entry_arquivo.delete(0, tk.END)
            self.entry_arquivo.insert(0, caminho)

    def restaurar_backup(self):
        dbname = self.combo_dbname.get().strip()
        backup_file = self.entry_arquivo.get().strip()

        if not dbname or not backup_file:
            messagebox.showerror("Erro", "Selecione a base de dados e o arquivo de backup.")
            return

        role_name = f"ALTERDATA_GROUP_{dbname}"

        comando = [
            PG_RESTORE_PATH,
            '--host', PG_HOST,
            '--port', PG_PORT,
            '--username', self.PG_USER.get(),
            '--dbname', dbname,
            '--clean',
            '--role', role_name,
            '--verbose',
            backup_file
        ]

        env = os.environ.copy()
        env['PGPASSWORD'] = self.PG_PASSWORD.get()

        self.barra_progresso.start(10)
        self.label_status.config(text="Restaurando...")

        def run_restore():
            try:
                processo = subprocess.Popen(
                    comando,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                for linha in processo.stdout:
                    print(linha.strip())
                    self.label_status.config(text=linha.strip())
                    self.label_status.update()

                processo.wait()
                self.barra_progresso.stop()
                if processo.returncode == 0:
                    self.label_status.config(text="Backup restaurado com sucesso!")
                    messagebox.showinfo("Sucesso", "Backup restaurado com sucesso!")
                else:
                    self.label_status.config(text="Erro na restauração.")
                    messagebox.showerror("Erro", "Erro ao restaurar o backup. Verifique os logs.")
            except Exception as e:
                self.barra_progresso.stop()
                self.label_status.config(text="Erro na execução.")
                messagebox.showerror("Erro", str(e))

        threading.Thread(target=run_restore).start()


class BackupScreen(tb.Frame):
    def __init__(self, master, user_var, pass_var):
        super().__init__(master)

        self.user_var = user_var
        self.pass_var = pass_var
        self.pg_versions = {
            "9.5": "C:/Program Files/PostgreSQL/9.5/bin",
            "9.6": "C:/Program Files/PostgreSQL/9.6/bin"
        }

        self.pg_version = StringVar(value="9.5")
        self.selected_base = StringVar()
        self.backup_format = StringVar(value="custom")
        self.schema = StringVar(value="ishop")
        self.tables_only = BooleanVar(value=False)
        self.tables_names = StringVar()
        self.output_path = StringVar()

        # Título
        tb.Label(self, text="Backup do PostgreSQL", font=("Roboto", 18, "bold")).pack(pady=20)

        # Versão do PostgreSQL
        tb.Label(self, text="Versão do PostgreSQL:").pack()
        frame_pg = tb.Frame(self)
        frame_pg.pack(pady=5)
        tb.Radiobutton(frame_pg, text="9.5", variable=self.pg_version, value="9.5").pack(side=tk.LEFT, padx=5)
        tb.Radiobutton(frame_pg, text="9.6", variable=self.pg_version, value="9.6").pack(side=tk.LEFT, padx=5)

        # Base de dados
        tb.Label(self, text="Base de dados:").pack(pady=5)
        self.combo_base = tb.Combobox(self, textvariable=self.selected_base, width=40)
        self.combo_base.pack(pady=5)

        # Formato do backup
        tb.Label(self, text="Formato do backup:").pack(pady=5)
        self.combo_format = tb.Combobox(self, values=["custom", "plain"], textvariable=self.backup_format, width=40, state="readonly")
        self.combo_format.pack(pady=5)
        self.combo_format.bind("<<ComboboxSelected>>", self.atualizar_opcoes)

        # Schema
        tb.Label(self, text="Schema:").pack()
        frame_schema = tb.Frame(self)
        frame_schema.pack(pady=5)
        tb.Radiobutton(frame_schema, text="ishop", variable=self.schema, value="ishop").pack(side=tk.LEFT, padx=5)
        tb.Radiobutton(frame_schema, text="wshop", variable=self.schema, value="wshop").pack(side=tk.LEFT, padx=5)
        tb.Radiobutton(frame_schema, text="spice", variable=self.schema, value="spice").pack(side=tk.LEFT, padx=5)
        self.radio_completo = tb.Radiobutton(frame_schema, text="Completo", variable=self.schema, value="completo")
        self.radio_completo.pack(side=tk.LEFT, padx=5)

        # Tabelas específicas
        tb.Checkbutton(self, text="Backup apenas de tabelas específicas", variable=self.tables_only, command=self.atualizar_entrada_tabelas).pack(pady=5)
        self.entry_tables = tb.Entry(self, textvariable=self.tables_names, width=43)
        self.entry_tables.pack(pady=5)

        # Caminho do arquivo
        tb.Label(self, text="Arquivo de destino:").pack()
        frame_arquivo = tb.Frame(self)
        frame_arquivo.pack(pady=5)
        tb.Entry(frame_arquivo, textvariable=self.output_path, width=30).pack(side=tk.LEFT, padx=5)
        tb.Button(frame_arquivo, text="Selecionar", command=self.selecionar_arquivo, bootstyle="secondary").pack(side=tk.LEFT)

        # Barra de progresso
        self.barra_progresso = tb.Progressbar(self, mode='indeterminate', length=290, bootstyle="info-solid")
        self.barra_progresso.pack(pady=15)
        self.label_status = tb.Label(self, text="", font=("Roboto", 10))
        self.label_status.pack(pady=15)

        # Botão de iniciar
        tb.Button(self, text="Iniciar Backup", bootstyle="default", command=self.iniciar_backup).pack(pady=10)

        # Botão de voltar
        tb.Button(self, text="Voltar", command=lambda: master.show_frame(MainMenu), bootstyle="secondary").pack(pady=10)

    def atualizar_bases(self):
        bases = listar_bases(self.user_var.get(), self.pass_var.get())
        self.combo_base['values'] = bases

    def selecionar_arquivo(self):
        extension = ".sql" if self.backup_format.get() == "plain" else ".backup"
        path = filedialog.asksaveasfilename(
            defaultextension=extension,
            filetypes=[("Backup files", f"*{extension}"), ("All files", "*.*")]
        )
        if path:
            self.output_path.set(path)

    def atualizar_opcoes(self, event=None):
        """Atualiza as opções de schema e tabelas com base no formato de backup selecionado."""
        if self.backup_format.get() == "plain":
            self.radio_completo.config(state="disabled")
        else:
            self.radio_completo.config(state="normal")

    def atualizar_entrada_tabelas(self):
        """Habilita ou desabilita a entrada de tabelas com base na checkbox."""
        if self.tables_only.get():
            self.entry_tables.config(state="normal")
        else:
            self.entry_tables.config(state="disabled")

    def iniciar_backup(self):
        self.barra_progresso.start()  # Inicia a barra de progresso
        self.label_status.config(text="Iniciando o backup...")

        pg_bin_path = self.pg_versions.get(self.pg_version.get())
        pg_dump_path = os.path.join(pg_bin_path, "pg_dump.exe")
        output_file = self.output_path.get().replace("/", "\\")

        base = self.selected_base.get()
        schema = self.schema.get()
        user = self.user_var.get()
        passwd = self.pass_var.get()

        cmd = [pg_dump_path]

        cmd += ['--host=localhost', f'--username={user}']

        if schema != "completo":
            role = f"ALTERDATA_GROUP_{base}"
            cmd += [f'--role={role}', f'--schema={schema}']

        if self.tables_only.get() and self.tables_names.get():
            for table in self.tables_names.get().split(','):
                table = table.strip()
                if schema != "completo":
                    cmd += [f'--table={schema}.{table}']
                else:
                    cmd += [f'--table={table}']

        fmt = self.backup_format.get()

        if fmt == "plain":
            cmd += ['--data-only', '--column-inserts', '--inserts']  # Options for plain format
            cmd += [f'--file={output_file}', '-F', 'p', base]  # Save as .sql
        else:
            cmd += [f'--format={fmt}', '--blobs', '--verbose']
            cmd += [f'--file={output_file}', '-F', 'c', base]  # Save as .backup

        env = os.environ.copy()
        env['PGPASSWORD'] = passwd

        def run():
            try:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                subprocess.run(cmd, env=env, check=True)
                self.barra_progresso.stop()
                self.label_status.config(text="Backup realizado com sucesso!")
                messagebox.showinfo("Sucesso", "Backup realizado com sucesso!")
            except subprocess.CalledProcessError as e:
                self.barra_progresso.stop()
                self.label_status.config(text="Erro ao realizar backup")
                messagebox.showerror("Erro", f"Erro ao realizar backup:\n{e}")
            except Exception as e:
                self.barra_progresso.stop()
                self.label_status.config(text="Erro inesperado")
                messagebox.showerror("Erro inesperado", str(e))

        threading.Thread(target=run).start()


if __name__ == "__main__":
    app = App()
    app.mainloop()