from typing import List

from contracts.nmap_constants import (FIN_SCAN_CONTRACT,
                                      TCP_CONNECT_SCAN_CONTRACT,
                                      TCP_SYN_SCAN_CONTRACT)


class NmapCommandBuilder:
    @staticmethod
    def build_args(contract_id: str, targets: List[str]) -> List[str]:
        args = ["nmap", "-Pn"]

        if contract_id == TCP_SYN_SCAN_CONTRACT:
            args.append("-sS")
        elif contract_id == TCP_CONNECT_SCAN_CONTRACT:
            args.append("-sT")
        elif contract_id == FIN_SCAN_CONTRACT:
            args.append("-sF")
        args = args + ["-oX", "-"]

        for target in targets:
            args += [target]

        return args
