import unittest

from auditkit import __version__


class TestPackage(unittest.TestCase):
    def test_version_format(self):
        parts = __version__.split(".")

        self.assertTrue(len(parts) >= 2)
        self.assertTrue(parts[0].isdigit())
        self.assertTrue(parts[1].isdigit())


if __name__ == "__main__":
    unittest.main()
