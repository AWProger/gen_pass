import unittest
from core import PasswordManager

class TestPasswordManager(unittest.TestCase):
    
    def setUp(self):
        self.manager = PasswordManager()
    
    def test_password_length(self):
        pwd = self.manager.gen_password(16)
        self.assertEqual(len(pwd), 16)
    def test_history(self):
        self.manager.gen_password(16)
        self.assertEqual(len(self.manager.get_history()), 1)

    def test_short_password(self):
        with self.assertRaises(ValueError):
            self.manager.gen_password(3)

if __name__ == "__main__":
    unittest.main()