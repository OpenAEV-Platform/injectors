# Private list of signature types that NetExec creates for any target.
# These correspond to pyoaev.signatures.types.SignatureTypes values and are all
# network-category: the injector uses NetworkInjectorConfig, which automatically
# compiles source/target IP fields together with start_date and end_date.
NETEXEC_SIGNATURE_TYPES: frozenset[str] = frozenset(
    {
        "source_ipv4_address",
        "target_ipv4_address",
        "target_ipv6_address",
        "target_hostname_address",
        "start_date",
        "end_date",
        "protocols_tested",
        "protocols_succeeded",
    }
)
