import subprocess


class NucleiProcess:

    @staticmethod
    def nuclei_update_templates():
        subprocess.run(["nuclei", "-update-templates"], check=True)

    @staticmethod
    def nuclei_version():
        subprocess.run(["nuclei", "-version"], capture_output=True, check=True)

    @staticmethod
    def nuclei_execute(args, input_data):
        return subprocess.run(args, input=input_data, capture_output=True, check=True)
