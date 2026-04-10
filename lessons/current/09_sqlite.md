# Урок 9 — База данных SQLite

## Статус: В ПРОЦЕССЕ

## Зачем SQLite вместо JSON
- JSON — просто текст, медленный поиск при большом количестве записей
- SQLite — полноценная БД в одном файле, быстрый поиск, индексы, транзакции
- Не нужен отдельный сервер

## Основные SQL команды

### Создание таблицы
```sql
CREATE TABLE IF NOT EXISTS passwords (
    id TEXT PRIMARY KEY,
    site TEXT,
    login TEXT,
    email TEXT,
    password TEXT,
    created TEXT
);
```

### CRUD операции
```sql
-- Create
INSERT INTO passwords VALUES ('uuid', 'google.com', 'user', 'user@mail.com', 'pass', '2026-04-08');

-- Read
SELECT * FROM passwords;
SELECT * FROM passwords WHERE site LIKE '%google%';

-- Update
UPDATE passwords SET site = 'new.com' WHERE id = 'uuid';

-- Delete
DELETE FROM passwords WHERE id = 'uuid';
```

## SQLite в Python
```python
import sqlite3

conn = sqlite3.connect("passwords.db")  # создаём/открываем файл БД
cursor = conn.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS passwords (...)")
conn.commit()   # сохраняем изменения
conn.close()    # закрываем соединение
```

## Задание
Переписать PasswordManager чтобы использовал SQLite вместо списка self.history
