import unittest
from main import core_calculation

class TestApp(unittest.TestCase):
    def test_core_calculation(self):

       #Pass
        self.assertEqual(core_calculation(10, 5), 15)

    def test_core_calculation_negative(self):

        #Pass
        self.assertEqual(core_calculation(-1, 1), 0)

if __name__ == "__main__":
    unittest.main()
