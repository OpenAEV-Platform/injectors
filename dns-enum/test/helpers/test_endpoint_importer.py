import unittest
from unittest.mock import MagicMock

from dns_enum.helpers.endpoint_importer import (
    EndpointImporter,
    build_endpoint_input,
    dedupe_hosts,
    external_reference,
)


def _host(name, ips):
    return {"host": name, "ips": ips, "records": {"A": ips}}


class TestEndpointImporter(unittest.TestCase):
    def test_external_reference_is_stable(self):
        self.assertEqual(
            external_reference("WWW.Example.com."), "dns-enum:www.example.com"
        )
        self.assertEqual(
            external_reference("www.example.com"), external_reference("WWW.EXAMPLE.COM")
        )

    def test_dedupe_hosts_keeps_first_and_skips_unresolved(self):
        hosts = [
            _host("www.example.com", ["1.1.1.1"]),
            _host("WWW.example.com", ["2.2.2.2"]),
            _host("cname.example.com", []),
        ]
        self.assertEqual(dedupe_hosts(hosts), [hosts[0]])

    def test_build_endpoint_input(self):
        endpoint = build_endpoint_input(_host("www.example.com", ["1.1.1.1"]), "tag-1")
        self.assertEqual(
            endpoint,
            {
                "asset_name": "www.example.com",
                "asset_hostname": "www.example.com",
                "asset_external_reference": "dns-enum:www.example.com",
                "asset_description": "Discovered by DNS enumeration",
                "asset_internet_facing": True,
                "asset_ips": ["1.1.1.1"],
                "asset_tags": ["tag-1"],
            },
        )
        self.assertNotIn(
            "asset_tags", build_endpoint_input(_host("a.b.c", ["1.1.1.1"]), None)
        )

    def test_import_upserts_each_host_once_with_tag(self):
        api = MagicMock()
        api.tag.upsert.return_value = {"tag_id": "tag-1"}
        api.endpoint.upsert.side_effect = [
            {"asset_id": "asset-1"},
            {"asset_id": "asset-2"},
        ]
        hosts = [
            _host("a.example.com", ["1.1.1.1"]),
            _host("A.example.com", ["1.1.1.1"]),
            _host("b.example.com", ["2.2.2.2"]),
        ]
        result = EndpointImporter(api, MagicMock()).import_hosts(
            hosts, "discovered:dns"
        )
        api.tag.upsert.assert_called_once_with(
            {"tag_name": "discovered:dns", "tag_color": "#00897b"}
        )
        self.assertEqual(api.endpoint.upsert.call_count, 2)
        sent = [
            call.args[0]["asset_external_reference"]
            for call in api.endpoint.upsert.call_args_list
        ]
        self.assertEqual(sent, ["dns-enum:a.example.com", "dns-enum:b.example.com"])
        self.assertEqual(result["asset_ids"], ["asset-1", "asset-2"])
        self.assertEqual(result["failed"], [])
        api.http_put.assert_not_called()

    def test_rerun_returning_the_same_asset_creates_no_duplicate_id(self):
        api = MagicMock()
        api.tag.upsert.return_value = {"tag_id": "tag-1"}
        api.endpoint.upsert.return_value = {"asset_id": "asset-1"}
        importer = EndpointImporter(api, MagicMock())
        first = importer.import_hosts([_host("a.example.com", ["1.1.1.1"])], "t")
        second = importer.import_hosts([_host("a.example.com", ["1.1.1.1"])], "t")
        self.assertEqual(first["asset_ids"], ["asset-1"])
        self.assertEqual(second["asset_ids"], ["asset-1"])
        refs = {
            c.args[0]["asset_external_reference"]
            for c in api.endpoint.upsert.call_args_list
        }
        self.assertEqual(refs, {"dns-enum:a.example.com"})

    def test_failures_are_reported_and_tag_failure_is_tolerated(self):
        api = MagicMock()
        api.tag.upsert.side_effect = RuntimeError("boom")
        api.endpoint.upsert.side_effect = [
            RuntimeError("down"),
            {"asset_id": "asset-2"},
        ]
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [_host("a.example.com", ["1.1.1.1"]), _host("b.example.com", ["2.2.2.2"])],
            "t",
        )
        self.assertNotIn("asset_tags", api.endpoint.upsert.call_args_list[1].args[0])
        self.assertEqual(result["failed"], ["a.example.com"])
        self.assertEqual(result["asset_ids"], ["asset-2"])

    def test_asset_group_members_are_merged(self):
        api = MagicMock()
        api.tag.upsert.return_value = {"tag_id": "tag-1"}
        api.endpoint.upsert.side_effect = [
            {"asset_id": "asset-1"},
            {"asset_id": "asset-2"},
        ]
        api.http_get.return_value = {"asset_group_assets": ["asset-0", "asset-1"]}
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [_host("a.example.com", ["1.1.1.1"]), _host("b.example.com", ["2.2.2.2"])],
            "t",
            "group-1",
        )
        api.http_get.assert_called_once_with("/asset_groups/group-1")
        api.http_put.assert_called_once_with(
            "/asset_groups/group-1/assets",
            post_data={"asset_group_assets": ["asset-0", "asset-1", "asset-2"]},
        )
        self.assertIsNone(result["asset_group_error"])

    def test_asset_group_already_complete_is_not_written(self):
        api = MagicMock()
        api.tag.upsert.return_value = {"tag_id": "tag-1"}
        api.endpoint.upsert.return_value = {"asset_id": "asset-1"}
        api.http_get.return_value = {"asset_group_assets": ["asset-1"]}
        EndpointImporter(api, MagicMock()).import_hosts(
            [_host("a.example.com", ["1.1.1.1"])], "t", "group-1"
        )
        api.http_put.assert_not_called()


if __name__ == "__main__":
    unittest.main()
