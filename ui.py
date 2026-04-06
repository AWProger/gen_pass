import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from core import PasswordManager

manager = PasswordManager()

def run_app():

    def generate():
        try:
            length = int(float(length_var.get()))
            

            result.set(manager.gen_password(length, digits_var.get(), symbols_var.get(), site_var.get(), login_var.get(), email_var.get()))

            strength_var.set(manager.check_strength(result.get()))

        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))

    def copy():
        root.clipboard_clear()
        root.clipboard_append(result.get())

    def show_history():
        win = tk.Toplevel(root)
        win.title("История")
        
        text = tk.Text(win, width=50, height=20)
        text.pack()
        
        for pwd in manager.get_history():
            text.insert("end", f"ID:      {pwd['id']}\n")
            text.insert("end", f"Дата:    {pwd['created']}\n")
            text.insert("end", f"Сайт:    {pwd['site']}\n")
            text.insert("end", f"Емайл:   {pwd['email']}\n")
            text.insert("end", f"Логин:   {pwd['login']}\n")
            text.insert("end", f"Пароль:  {pwd['password']}\n")
            text.insert("end", "-" * 40 + "\n")
        
        text.config(state="disabled")  # запретить редактирование

    def save():
        filename = filedialog.asksaveasfilename()  # ascs → asks (опечатка)
        if filename:
            manager.save_history(filename)

    def load():
        filename = filedialog.askopenfilename()
        if filename:
            manager.load_history(filename)
    
    def clear():
        manager.clear_history()

    def delete_record():
        manager.delete_by_id(id_var.get())

    def edit_record():
        manager.edit_by_id(id_var.get(), site=site_var.get(), login=login_var.get(), email=email_var.get())

    def show_search():
        win = tk.Toplevel(root)
        win.title("Результаты поиска")
        for pwd in manager.search(search_var.get()):
            ttk.Label(win, text=f"Дата:    {pwd['created']}").pack(anchor="w")
            ttk.Label(win, text=f"Сайт:    {pwd['site']}").pack(anchor="w")
            ttk.Label(win, text=f"Емайл:   {pwd['email']}").pack(anchor="w")
            ttk.Label(win, text=f"Логин:   {pwd['login']}").pack(anchor="w")
            ttk.Label(win, text=f"Пароль:  {pwd['password']}").pack(anchor="w")
            ttk.Separator(win, orient="horizontal").pack(fill="x", pady=5)

    root = tk.Tk()
    root.title("AWPassword generator")
    root.geometry("200x560")

    result = tk.StringVar()
    length_var = tk.StringVar(value="16")
    digits_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)
    strength_var = tk.StringVar()
    length_label_var = tk.IntVar(value=16)

    site_var = tk.StringVar()
    email_var = tk.StringVar()
    login_var = tk.StringVar()

    search_var = tk.StringVar()
    id_var = tk.StringVar()

    ttk.Label(root, text="Сайт").pack()
    ttk.Entry(root, textvariable=site_var).pack()
    ttk.Label(root, text="Емайл").pack()
    ttk.Entry(root, textvariable=email_var).pack()
    ttk.Label(root, text="Логин").pack()
    ttk.Entry(root, textvariable=login_var).pack()
    ttk.Label(root, text="Длина").pack()
    ttk.Scale(root, from_=4, to=32, variable=length_var, orient="horizontal",
            command=lambda v: length_label_var.set(int(float(v)))).pack()
    ttk.Label(root, textvariable=length_label_var).pack()

    ttk.Checkbutton(root, text="Цифры", variable=digits_var).pack()
    ttk.Checkbutton(root, text="Символы", variable=symbols_var).pack()

    ttk.Entry(root, textvariable=result, width=30).pack(pady=5)
    ttk.Button(root, text="Сгенерировать", command=generate).pack()

    ttk.Entry(root, textvariable=search_var).pack()
    ttk.Button(root, text="Поиск", command=show_search).pack()

    ttk.Label(root, text="ID для удаления/редактирования").pack()
    ttk.Entry(root, textvariable=id_var).pack()
    ttk.Button(root, text="Удалить", command=delete_record).pack()
    ttk.Button(root, text="Редактировать", command=edit_record).pack()

    ttk.Button(root, text="Копировать", command=copy).pack()
    ttk.Button(root, text="История", command=show_history).pack()

    ttk.Button(root, text="Экспортировать", command=save).pack()
    ttk.Button(root, text="Импорт", command=load).pack()

    ttk.Button(root, text="Очистить историю", command=clear).pack()

    ttk.Label(root, textvariable=strength_var).pack()

    root.mainloop()