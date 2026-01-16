class HTTPHelpers:
    @staticmethod
    def parse_headers(headers_str):
        if isinstance(headers_str, list):
            return headers_str
        headers_list = []
        for kv in headers_str.split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                headers_list.append({"key": k.strip(), "value": v.strip()})
        return headers_list

    @staticmethod
    def parse_parts(parts_str):
        if isinstance(parts_str, list):
            return parts_str
        parts_list = []
        for kv in parts_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                parts_list.append({"key": k.strip(), "value": v.strip()})
        return parts_list

    @staticmethod
    def request_data_parts_body(request_data):
        parts = HTTPHelpers.parse_parts(
            request_data["injection"]["inject_content"]["parts"]
        )
        keys = list(map(lambda p: p["key"], parts))
        values = list(map(lambda p: p["value"], parts))
        return dict(zip(keys, values))

    @staticmethod
    def response_parsing(response):
        return {
            "url": response.url,
            "code": response.status_code,
            "status": "SUCCESS",
            "message": response.text
            or f"No response body (HTTP {response.status_code})",
        }
