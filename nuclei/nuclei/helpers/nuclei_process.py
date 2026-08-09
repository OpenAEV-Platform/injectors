import subprocess


class NucleiProcess:

    @staticmethod
    def nuclei_update_templates(timeout=None):
        # timeout is a hard ceiling for the template refresh. The refresh holds
        # the writer side of the templates lock, so a hung "nuclei
        # -update-templates" would otherwise block every scan (reader) forever -
        # before a scan's own subprocess timeout could even start. When it fires,
        # subprocess.run kills the process and raises TimeoutExpired, and the
        # caller releases the lock so scanning degrades to best-effort.
        subprocess.run(["nuclei", "-update-templates"], check=True, timeout=timeout)

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
