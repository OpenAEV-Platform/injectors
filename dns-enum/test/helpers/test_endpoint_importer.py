import unittest
from unittest.mock import MagicMock

from dns_enum.helpers.endpoint_importer import (
    EndpointImporter,
    build_endpoint_input,
    dedupe_hosts,
    external_reference,
    in_scope,
)


def _host(name, ips):
    return {"host": name, "ips": ips, "records": {"A": ips}}


class TestEndpointImporter(unittest.TestCase):
    def test_several_tags_are_upserted_and_set(self):
        api = MagicMock()
        api.tag.upsert.side_effect = [{"tag_id": "t1"}, {"tag_id": "t2"}]
        api.endpoint.upsert.return_value = {"asset_id": "asset-1"}
        EndpointImporter(api, MagicMock()).import_hosts(
            [_host("a.example.com", ["1.1.1.1"])],
            ["ext", "internet"],
            classify_assets=False,
        )
        self.assertEqual(api.tag.upsert.call_count, 2)
        self.assertEqual(
            api.endpoint.upsert.call_args.args[0]["asset_tags"], ["t1", "t2"]
        )

    def test_in_scope(self):
        self.assertTrue(in_scope("a.example.com", ["example.com"]))
        self.assertTrue(in_scope("Example.com.", ["example.com"]))
        self.assertFalse(in_scope("badexample.com", ["example.com"]))

    def test_stale_endpoints_are_own_in_scope_and_unresolved(self):
        api = MagicMock()
        api.http_post.return_value = {
            "content": [
                {
                    "asset_id": "1",
                    "asset_name": "a.example.com",
                    "asset_external_reference": "dns-enum:a.example.com",
                },
                {
                    "asset_id": "2",
                    "asset_name": "old.example.com",
                    "asset_external_reference": "dns-enum:old.example.com",
                },
                {
                    "asset_id": "3",
                    "asset_name": "x.other.org",
                    "asset_external_reference": "dns-enum:x.other.org",
                },
                {
                    "asset_id": "4",
                    "asset_name": "collector",
                    "asset_external_reference": "collector:old.example.com",
                },
            ],
            "last": True,
        }
        stale = EndpointImporter(api, MagicMock()).stale_endpoints(
            [_host("a.example.com", ["1.1.1.1"]), _host("c.example.com", [])],
            ["example.com"],
        )
        self.assertEqual([asset["asset_id"] for asset in stale], ["2"])
        sent = api.http_post.call_args.kwargs["post_data"]["filterGroup"]["filters"][0]
        self.assertEqual(sent["operator"], "starts_with")
        self.assertEqual(sent["values"], ["dns-enum:"])

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


def _search_api(assets):
    """An API whose asset search answers from `assets` (filter on one key, eq)."""
    api = MagicMock()
    api.tag.upsert.return_value = {"tag_id": "tag-1"}
    upserted = {}

    def search(path, post_data):
        assert path == "/assets/search"
        flt = post_data["filterGroup"]["filters"][0]
        key, values = flt["key"], flt["values"]
        if key == "asset_ips":
            hits = [a for a in assets if set(a.get("asset_ips") or []) & set(values)]
        else:
            hits = [a for a in assets if a.get(key) in values]
        return {"content": hits, "last": True}

    def upsert(endpoint):
        ref = endpoint["asset_external_reference"]
        upserted[ref] = endpoint
        return {"asset_id": "id-" + ref}

    api.http_post.side_effect = search
    api.endpoint.upsert.side_effect = upsert
    return api, upserted


class TestClassifiedImport(unittest.TestCase):
    def test_shared_address_names_become_web_applications(self):
        api, upserted = _search_api([])
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [
                _host("a.example.com", ["10.0.0.1"]),
                _host("b.example.com", ["10.0.0.1"]),
                _host("solo.example.com", ["10.0.0.2"]),
            ],
            "t",
        )
        a = upserted["dns-enum:a.example.com"]
        self.assertEqual(a["asset_category"], "WEB_APPLICATION")
        self.assertEqual(a["asset_subcategory"], "WEBSITE")
        self.assertEqual(a["asset_url"], "https://a.example.com")
        solo = upserted["dns-enum:solo.example.com"]
        self.assertEqual(solo["asset_category"], "HOST")
        self.assertEqual(solo["asset_subcategory"], "SERVER")
        self.assertNotIn("asset_url", solo)
        self.assertEqual(result["web_applications"], 2)
        self.assertEqual(result["attached"], [])

    def test_cdn_cname_is_a_web_application(self):
        api, upserted = _search_api([])
        host = {
            "host": "cdn.example.com",
            "ips": ["3.3.3.3"],
            "records": {"A": ["3.3.3.3"], "CNAME": ["d1.cloudfront.net."]},
        }
        EndpointImporter(api, MagicMock()).import_hosts([host], "t")
        self.assertEqual(
            upserted["dns-enum:cdn.example.com"]["asset_category"], "WEB_APPLICATION"
        )

    def test_existing_classification_is_never_overwritten(self):
        api, upserted = _search_api(
            [
                {
                    "asset_id": "x",
                    "asset_external_reference": "dns-enum:a.example.com",
                    "asset_category": "NETWORK_DEVICE",
                },
                {
                    "asset_id": "y",
                    "asset_external_reference": "dns-enum:b.example.com",
                    "asset_category": "HOST",
                },
            ]
        )
        EndpointImporter(api, MagicMock()).import_hosts(
            [
                _host("a.example.com", ["10.0.0.1"]),
                _host("b.example.com", ["10.0.0.1"]),
            ],
            "t",
        )
        self.assertNotIn("asset_category", upserted["dns-enum:a.example.com"])
        # HOST without subcategory is the platform default: filled.
        self.assertEqual(
            upserted["dns-enum:b.example.com"]["asset_category"], "WEB_APPLICATION"
        )

    def test_name_on_an_existing_server_is_attached_not_duplicated(self):
        api, upserted = _search_api(
            [
                {
                    "asset_id": "srv-1",
                    "asset_name": "mail-server",
                    "asset_external_reference": None,
                    "asset_ips": ["10.0.0.9"],
                }
            ]
        )
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [_host("mail.example.com", ["10.0.0.9"])], "t", "group-1"
        )
        self.assertEqual(upserted, {})
        self.assertEqual(result["asset_ids"], ["srv-1"])
        self.assertEqual(result["attached"], ["mail.example.com -> mail-server"])

    def test_own_assets_on_the_address_do_not_count_as_existing(self):
        api, upserted = _search_api(
            [
                {
                    "asset_id": "old",
                    "asset_external_reference": "dns-enum:other.example.com",
                    "asset_ips": ["10.0.0.9"],
                }
            ]
        )
        EndpointImporter(api, MagicMock()).import_hosts(
            [_host("mail.example.com", ["10.0.0.9"])], "t"
        )
        self.assertIn("dns-enum:mail.example.com", upserted)

    def test_rerun_changes_no_classification(self):
        hosts = [
            _host("a.example.com", ["10.0.0.1"]),
            _host("b.example.com", ["10.0.0.1"]),
        ]
        api, first = _search_api([])
        EndpointImporter(api, MagicMock()).import_hosts(hosts, "t")
        stored = [
            {"asset_id": "id-" + ref, **endpoint} for ref, endpoint in first.items()
        ]
        api2, second = _search_api(stored)
        result = EndpointImporter(api2, MagicMock()).import_hosts(hosts, "t")
        # The same endpoints, and no classification field: the platform's upsert
        # keeps a stored category when the input omits it.
        self.assertEqual(set(first), set(second))
        for endpoint in second.values():
            self.assertNotIn("asset_category", endpoint)
            self.assertNotIn("asset_url", endpoint)
        self.assertEqual(result["attached"], [])

    def test_option_off_sends_no_classification(self):
        api, upserted = _search_api([])
        EndpointImporter(api, MagicMock()).import_hosts(
            [_host("a.example.com", ["10.0.0.1"])], "t", classify_assets=False
        )
        # Only the address check runs: no lookup of the existing endpoints.
        keys = {
            c.kwargs["post_data"]["filterGroup"]["filters"][0]["key"]
            for c in api.http_post.call_args_list
        }
        self.assertEqual(keys, {"asset_ips"})
        self.assertNotIn("asset_category", upserted["dns-enum:a.example.com"])

    def test_shared_address_name_on_a_classified_foreign_asset_is_attached(self):
        # Three names share the address of an asset a collector created and already
        # classified: none is upserted (the platform would match the collector's asset
        # on hostname + IP and rename or reclassify it), all are attached to it.
        collector_asset = {
            "asset_id": "ovh-1",
            "asset_name": "ww-onedev-control-001",
            "asset_hostname": "control-001.onedev.ww.example.com",
            "asset_external_reference": "ovh:ns-123",
            "asset_category": "HOST",
            "asset_subcategory": "SERVER",
            "asset_ips": ["10.0.0.7"],
        }
        api, upserted = _search_api([collector_asset])
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [
                _host("control-001.onedev.ww.example.com", ["10.0.0.7"]),
                _host("metis.onedev.ww.example.com", ["10.0.0.7"]),
                _host("hubble.onedev.example.com", ["10.0.0.7"]),
                _host("validation.onedev.example.com", ["10.0.0.7"]),
            ],
            "t",
        )
        self.assertEqual(upserted, {})
        api.endpoint.upsert.assert_not_called()
        self.assertEqual(result["asset_ids"], ["ovh-1"])
        self.assertEqual(len(result["attached"]), 4)
        self.assertTrue(
            all(
                line.endswith("-> ww-onedev-control-001") for line in result["attached"]
            )
        )
        self.assertEqual(result["web_applications"], 0)
        # The collector's asset is never written: same name, same category.
        self.assertEqual(collector_asset["asset_name"], "ww-onedev-control-001")
        self.assertEqual(collector_asset["asset_category"], "HOST")

    def test_foreign_asset_is_protected_with_classification_off(self):
        api, upserted = _search_api(
            [
                {
                    "asset_id": "srv-1",
                    "asset_name": "mail-server",
                    "asset_external_reference": None,
                    "asset_ips": ["10.0.0.9"],
                }
            ]
        )
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [_host("mail.example.com", ["10.0.0.9"])], "t", classify_assets=False
        )
        self.assertEqual(upserted, {})
        self.assertEqual(result["asset_ids"], ["srv-1"])

    def test_foreign_asset_on_a_second_address_is_found(self):
        api, upserted = _search_api(
            [
                {
                    "asset_id": "srv-2",
                    "asset_name": "edge",
                    "asset_ips": ["2001:db8::1"],
                }
            ]
        )
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [_host("edge.example.com", ["10.0.0.3", "2001:db8::1"])], "t"
        )
        self.assertEqual(upserted, {})
        self.assertEqual(result["asset_ids"], ["srv-2"])

    def test_address_lookup_failure_skips_the_host(self):
        api, upserted = _search_api([])

        def search(path, post_data):
            key = post_data["filterGroup"]["filters"][0]["key"]
            if key == "asset_ips":
                raise RuntimeError("timeout")
            return {"content": [], "last": True}

        api.http_post.side_effect = search
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [_host("a.example.com", ["10.0.0.1"])], "t"
        )
        self.assertEqual(upserted, {})
        self.assertEqual(result["skipped"], ["a.example.com"])
        self.assertEqual(result["asset_ids"], [])

    def test_name_alone_on_its_address_is_counted_as_a_server(self):
        api, upserted = _search_api([])
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [
                _host("a.example.com", ["10.0.0.1"]),
                _host("b.example.com", ["10.0.0.1"]),
                _host("solo.example.com", ["10.0.0.2"]),
            ],
            "t",
        )
        self.assertEqual(result["web_applications"], 2)
        self.assertEqual(result["servers"], 1)
        self.assertEqual(
            upserted["dns-enum:solo.example.com"]["asset_subcategory"], "SERVER"
        )

    def test_lookup_failure_imports_without_classification(self):
        api, upserted = _search_api([])

        def search(path, post_data):
            key = post_data["filterGroup"]["filters"][0]["key"]
            if key == "asset_external_reference":
                raise RuntimeError("403")
            return {"content": [], "last": True}

        api.http_post.side_effect = search
        result = EndpointImporter(api, MagicMock()).import_hosts(
            [_host("a.example.com", ["10.0.0.1"])], "t"
        )
        self.assertEqual(result["lookup_error"], "403")
        self.assertNotIn("asset_category", upserted["dns-enum:a.example.com"])


if __name__ == "__main__":
    unittest.main()
