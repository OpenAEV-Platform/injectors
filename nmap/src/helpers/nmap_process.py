import subprocess


class NmapProcess:

    @staticmethod
    def nmap_execute(args):
        return subprocess.run(args, check=True, capture_output=True)

    @staticmethod
    def js_execute(args, input):
        return subprocess.run(args, input=input.stdout, capture_output=True)
