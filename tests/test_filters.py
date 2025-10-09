import unittest
from filters.network import check_network_filters
from filters.content import check_content_filters
from filters.ml_classifier import classify_with_ml

class TestFilters(unittest.TestCase):
    def test_network_clean(self):
        self.assertTrue(check_network_filters('8.8.8.8'))  # Google DNS, should be clean

    def test_content_spam(self):
        self.assertTrue(check_content_filters('Buy viagra now!'))

    def test_ml_spam(self):
        prob = classify_with_ml('Free money click here')
        self.assertGreater(prob, 0.5)  # Assuming model detects it

if __name__ == '__main__':
    unittest.main()