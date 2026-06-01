import subprocess


class NmapProcess:
    @staticmethod
    def nmap_execute(args):
        return subprocess.run(args, check=True, capture_output=True)
