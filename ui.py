import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from core import gen_password, get_history, check_strength, save_history, load_history, clear_history

def run_app():
    def generate():
        try:
            length = int(float(length_var.get()))
            

            result.set(gen_password(length, digits_var.get(),symbols_var.get()))
            strength_var.set(check_strength(result.get()))

        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))

    def copy():
        root.clipboard_clear()
        root.clipboard_append(result.get())

    def show_history():
        win = tk.Toplevel(root)
        win.title("История")
        for pwd in get_history():
            ttk.Label(win, text=pwd).pack()

    def save():
        filename = filedialog.asksaveasfilename()  # ascs → asks (опечатка)
        if filename:
            save_history(filename)

    def load():
        filename = filedialog.askopenfilename()
        if filename:
            load_history(filename)
    
    def clear():
        clear_history()


    root = tk.Tk()
    root.title("AWPassword generator")
    root.geometry("240x260")

    result = tk.StringVar()
    length_var = tk.StringVar(value="16")
    digits_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)
    strength_var = tk.StringVar()
    length_label_var = tk.IntVar(value=16)


    ttk.Label(root, text="Длина").pack()
    ttk.Scale(root, from_=4, to=32, variable=length_var, orient="horizontal",
            command=lambda v: length_label_var.set(int(float(v)))).pack()
    ttk.Label(root, textvariable=length_label_var).pack()



    ttk.Checkbutton(root, text="Цифры", variable=digits_var).pack()
    ttk.Checkbutton(root, text="Символы", variable=symbols_var).pack()

    ttk.Entry(root, textvariable=result, width=30).pack(pady=5)

    ttk.Button(root, text="Сгенерировать", command=generate).pack()
    ttk.Button(root, text="Копировать", command=copy).pack()
    ttk.Button(root, text="История", command=show_history).pack()

    ttk.Button(root, text="Экспортировать", command=save).pack()
    ttk.Button(root, text="Импорт", command=load).pack()

    ttk.Button(root, text="Очистить историю", command=clear).pack()


    ttk.Label(root, textvariable=strength_var).pack()


    root.mainloop()