import subprocess


class NucleiProcess:

    @staticmethod
    def nuclei_update_templates():
        subprocess.run(["nuclei", "-update-templates"], check=True)

    @staticmethod
    def nuclei_version():
        subprocess.run(["nuclei", "-version"], capture_output=True, check=True)

    @staticmethod
    def nuclei_execute(args, input_data, timeout=None):
        # timeout is a hard ceiling for the whole scan: when it fires,
        # subprocess.run kills the process and raises TimeoutExpired (carrying
        # the partial stdout/stderr). Without it a hung Nuclei run blocks the
        # single-threaded consumer forever and the inject never gets a terminal
        # trace.
        return subprocess.run(
            args,
            input=input_data,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
