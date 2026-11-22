import unittest

from dns_enum.helpers.asset_classifier import (
    classify,
    is_cdn_cname,
    is_unclassified,
    shared_addresses,
)


class TestAssetClassifier(unittest.TestCase):
    def test_shared_addresses(self):
        hosts = [
            {"host": "a.x.com", "ips": ["1.1.1.1"]},
            {"host": "A.x.com.", "ips": ["2.2.2.2"]},
            {"host": "b.x.com", "ips": ["1.1.1.1"]},
        ]
        self.assertEqual(shared_addresses(hosts), {"1.1.1.1"})

    def test_cdn_cname(self):
        self.assertTrue(is_cdn_cname(["abc.edgekey.net."]))
        self.assertTrue(is_cdn_cname(["x.cdn.cloudflare.net"]))
        self.assertFalse(is_cdn_cname(["notfastly.net"]))
        self.assertFalse(is_cdn_cname([]))

    def test_classify(self):
        web = classify({"host": "Shop.X.com.", "ips": ["1.1.1.1"]}, {"1.1.1.1"})
        self.assertEqual(
            web,
            {
                "asset_category": "WEB_APPLICATION",
                "asset_subcategory": "WEBSITE",
                "asset_url": "https://shop.x.com",
            },
        )
        host = classify({"host": "vpn.x.com", "ips": ["9.9.9.9"]}, {"1.1.1.1"})
        self.assertEqual(
            host, {"asset_category": "HOST", "asset_subcategory": "SERVER"}
        )

    def test_unclassified(self):
        self.assertTrue(is_unclassified(None))
        self.assertTrue(is_unclassified({"asset_category": "HOST"}))
        self.assertTrue(is_unclassified({"asset_category": "GENERIC_ASSET"}))
        self.assertFalse(
            is_unclassified({"asset_category": "HOST", "asset_subcategory": "SERVER"})
        )
        self.assertFalse(is_unclassified({"asset_category": "WEB_APPLICATION"}))


if __name__ == "__main__":
    unittest.main()
