# Тестирование (unittest)

## Структура теста
```python
import unittest
from core import PasswordManager

class TestPasswordManager(unittest.TestCase):

    def setUp(self):                    # вызывается перед каждым тестом
        self.manager = PasswordManager()

    def test_password_length(self):     # название должно начинаться с test_
        pwd = self.manager.gen_password(16)
        self.assertEqual(len(pwd), 16)  # проверяем что длина = 16

    def test_history(self):
        self.manager.gen_password(16)
        self.assertEqual(len(self.manager.get_history()), 1)

    def test_short_password(self):
        with self.assertRaises(ValueError):   # ожидаем ValueError
            self.manager.gen_password(3)

if __name__ == "__main__":
    unittest.main()
```

## Методы проверки
```python
assertEqual(a, b)      # a == b
assertNotEqual(a, b)   # a != b
assertTrue(x)          # x is True
assertFalse(x)         # x is False
assertIsNone(x)        # x is None
assertIn(a, b)         # a in b
assertRaises(Error)    # функция бросает ошибку
```

## Запуск
```bash
python -m unittest test_core.py
```
