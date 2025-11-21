from os import walk
import threading
import unittest
from urllib.parse import urlparse

from libs.checker import ProxyChecker

class ProxyCheckerTest(unittest.TestCase):
    def setUp(self):
        self.checker = ProxyChecker()
        self.assertIsInstance(self.checker, ProxyChecker)

    def test_should_add_valid_proxy(self):
        self.assertEqual(len(self.checker.get_pending()), 0)

        result = self.checker.add("socks5://127.0.0.1:8080" )

        self.assertTrue(result)
        self.assertEqual(len(self.checker.get_pending()), 1)

    def test_should_not_add_invalid_proxy(self):
        self.assertEqual(len(self.checker.get_pending()), 0)

        result = self.checker.add("socks5://127.0.0.1" )

        self.assertFalse(result)
        self.assertEqual(len(self.checker.get_pending()), 0)

    def test_should_remove_valid_proxy(self):
        self.assertTrue(
            self.checker.add("socks5://127.0.0.1:8080")
        )
        self.assertEqual(len(self.checker.get_pending()), 1)

        self.assertTrue(self.checker.remove("socks5://127.0.0.1:8080"))
        self.assertEqual(len(self.checker.get_pending()), 0)

    def test_should_not_remove_invalid_proxy(self):
        self.assertTrue(
            self.checker.add("socks5://127.0.0.1:8080")
        )
        self.assertEqual(len(self.checker.get_pending()), 1)

        self.assertFalse(self.checker.remove("socks5://127.0.0.1"))
        self.assertEqual(len(self.checker.get_pending()), 1)

    def test_should_parse_proper_proxy(self):
        results = ProxyChecker._parse_proxy("socks5://127.0.0.1:8080")
        self.assertEqual(len(results),6)

    def test_should_normalize_proxy(self):
        parsed = urlparse("SOCKS5://127.0.0.1:8080")
        normalized = ProxyChecker._normalize_proxy(parsed)
        self.assertEqual(normalized, "socks5://127.0.0.1:8080")

    def test_should_return_valid_and_invalid_proxies(self):
        self.checker.add("socks5://127.0.0.1:8080")
        self.checker.add("socks5://127.0.0.1")

        self.checker._finalize("socks5://127.0.0.1:8080", True)
        self.checker._finalize("socks5://127.0.0.1", False)

        valid = self.checker.get_valid()
        invalid = self.checker.get_invalid()

        self.assertIn("socks5://127.0.0.1:8080", valid)
        self.assertIn("socks5://127.0.0.1", invalid)


    def test_should_not_parse_improper_proxy(self):
        results = ProxyChecker._parse_proxy("socks5://127.0.0.1")
        self.assertIsNone(results)

    def test_should_return_0_port(self):
        [scheme, addr, port] = ProxyChecker._split_proxy("socks5://127.0.0.1")

        self.assertEqual(scheme, "socks5")
        self.assertEqual(addr, "127.0.0.1")
        self.assertEqual(port, 0) 

    def test_should_split_valid_proxy(self):
        [scheme, addr, port] = ProxyChecker._split_proxy("socks5://127.0.0.1:8080")

        self.assertEqual(scheme, "socks5")
        self.assertEqual(addr, "127.0.0.1")
        self.assertEqual(port,8080) 

    def test_should_return_blank_addr(self):
        [scheme, addr, port] = ProxyChecker._split_proxy("https://")

        self.assertEqual(scheme, "https")
        self.assertEqual(addr, "")
        self.assertEqual(port, 0) 

    def test_should_not_remove_non_existent_proxy(self):
        self.assertFalse(self.checker.remove("socks5://127.0.0.1:999"))
        self.assertEqual(len(self.checker.get_pending()), 0)

    def test_should_handle_thread_safety(self):
        def add_proxy(id: int):
            result = self.checker.add(f"socks5://127.0.0.1:{8080 + id}")

            if not result:
                print("Failed to add proxy")

        threads = [threading.Thread(target=add_proxy, args=(i,)) for i in range(100)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(self.checker.get_pending()), 100)

if __name__ == "__main__":
    unittest.main()
