"""Scope bypass via a percent-encoded host (parser differential).

urlparse keeps `%XX` in the hostname as written, but requests/urllib3, urllib
and curl percent-decode the host before connecting. So
`http://adm%69n.example.com/` matched the in-scope `example.com` rule (it ends
in `.example.com`) and missed the `admin.example.com` deny rule, while the
request actually goes to `admin.example.com`. The gate must fail closed.
"""
import unittest

from scope import Scope, _host_of


class PercentEncodedHostTests(unittest.TestCase):
    def test_percent_encoded_host_fails_closed(self):
        for url in ("http://adm%69n.example.com/",
                    "https://%61dmin.example.com/x",
                    "http://ADM%49N.example.com:8080/",
                    "adm%69n.example.com"):
            with self.subTest(url=url):
                self.assertEqual(_host_of(url), "")

    def test_encoded_excluded_host_is_not_in_scope(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["admin.example.com"])
        for url in ("http://adm%69n.example.com/", "https://%61dmin.example.com/x"):
            with self.subTest(url=url):
                self.assertFalse(s.in_scope_host(url))
                self.assertIsNotNone(s.reject_reason(url))

    def test_ipv6_zone_and_plain_hosts_still_resolve(self):
        self.assertEqual(_host_of("http://[fe80::1%25eth0]/"), "fe80::1")
        self.assertEqual(_host_of("https://www.example.com/p?q=%41"), "www.example.com")
        self.assertEqual(_host_of("https://u%40x:p@www.example.com/"), "www.example.com")


if __name__ == "__main__":
    unittest.main()
