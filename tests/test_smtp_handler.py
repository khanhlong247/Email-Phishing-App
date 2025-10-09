import unittest
from core.smtp_handler import SpamFilterHandler
# Add mock SMTP session and envelope for testing
# This is a placeholder; implement mocks as needed

class TestSMTPHandler(unittest.TestCase):
    def test_handle_RCPT_protected(self):
        handler = SpamFilterHandler()
        # Mock server, session, envelope
        # self.assertEqual(handler.handle_RCPT(...), "250 OK")

if __name__ == '__main__':
    unittest.main()