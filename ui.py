import tkinter as tk
from tkinter import ttk, messagebox
from core import gen_password, get_history, check_strength

def run_app():
    def generate():
        try:
            length = int(length_var.get())
            result.set(gen_password(length, digits_var.get(),symbols_var.get()))
            strength_var.set(check_strength(result.get()))

        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def copy():
        root.clipboard_clear()
        root.clipboard_append(result.get())

    def show_history():
        win = tk.Toplevel(root)
        win.title("История")
        for pwd in get_history():
            ttk.Label(win, text=pwd).pack()

    root = tk.Tk()
    root.title("AWPassword generator")
    root.geometry("280x220")

    result = tk.StringVar()
    length_var = tk.StringVar(value="16")
    digits_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)
    strength_var = tk.StringVar()



    ttk.Label(root, text="Длина").pack()
    ttk.Entry(root, textvariable=length_var).pack()

    ttk.Checkbutton(root, text="Цифры", variable=digits_var).pack()
    ttk.Checkbutton(root, text="Символы", variable=symbols_var).pack()

    ttk.Entry(root, textvariable=result, width=30).pack(pady=5)

    ttk.Button(root, text="Сгенерировать", command=generate).pack()
    ttk.Button(root, text="Копировать", command=copy).pack()
    ttk.Button(root, text="История", command=show_history).pack()

    ttk.Label(root, textvariable=strength_var).pack()


    root.mainloop()