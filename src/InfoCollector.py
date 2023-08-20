import hashlib
import platform
import subprocess
import uuid
import psutil
import socket
import time
import datetime


class SystemInfoCollector:
    def __init__(self):
        self.system_info = {}

    ### System Info Functions ###
    def get_pc_name(self):
        return platform.node()

    def get_os_version(self):
        return platform.system() + " - " + platform.release()

    def get_system_uptime(self):
        uptime_seconds = round(time.time() - psutil.boot_time())
        uptime = datetime.timedelta(seconds=uptime_seconds)
        return str(uptime)

    def get_display_resolution(self):
        system = platform.system()

        if system == "Windows":
            try:
                import win32api

                width = win32api.GetSystemMetrics(0)
                height = win32api.GetSystemMetrics(1)
                return f"{width}x{height}"
            except Exception as e:
                print("Error retrieving display resolution:", str(e))
        elif system == "Linux":
            try:
                output = subprocess.check_output(["xrandr"], encoding="utf-8")
                lines = output.strip().split("\n")
                for line in lines:
                    if "*" in line:
                        resolution = line.split()[0]
                        return resolution
            except Exception as e:
                print("Error retrieving display resolution:", str(e))
        else:
            print("Unsupported operating system:", system)

        return None

    def get_ram_info(self):
        ram_total = psutil.virtual_memory().total
        ram_used = psutil.virtual_memory().used
        ram_percent_used = (ram_used / ram_total) * 100
        return "{:.2f} GiB / {:.2f} GiB ({:.2f}%)".format(
            ram_total / (1024 ** 3), ram_used / (1024 ** 3), ram_percent_used
        )

    def get_disk_usage(self):
        disk_usage = psutil.disk_usage('/')
        total_space = round(disk_usage.total / (1024 ** 3), 2)
        used_space = round(disk_usage.used / (1024 ** 3), 2)
        free_space = round(disk_usage.free / (1024 ** 3), 2)
        return {
            "Total Disk Space": f"{total_space} GB",
            "Used Disk Space": f"{used_space} GB",
            "Free Disk Space": f"{free_space} GB"
        }
    ### System Info Functions ###


    ### Hardware Info Functions ###
    def get_cpu_hash(self):
        if platform.system() == "Windows":
            cmd = "wmic cpu get ProcessorId /format:value"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            return hashlib.md5(output.encode()).hexdigest()
        elif platform.system() == "Linux":
            try:
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                    cpu_id = cpuinfo.strip().split(":")[1].replace(" ", "")
                    return hashlib.md5(cpu_id.encode()).hexdigest()
            except Exception as e:
                print("Error retrieving CPU information:", str(e))

        return None

    def get_gpu_info(self):
        gpu_info = []
        system = platform.system()

        if system == "Windows":
            try:
                import wmi

                w = wmi.WMI()
                for gpu in w.Win32_VideoController():
                    gpu_info.append(gpu.Name or "Unknown GPU")

                if not gpu_info:
                    gpu_info.append("Integrated Graphics")
            except Exception as e:
                print("Error retrieving GPU information:", str(e))
        elif system == "Linux":
            try:
                lspci_output = subprocess.check_output(["lspci", "-v"], encoding="utf-8")
                devices = lspci_output.strip().split("\n\n")
                for device in devices:
                    if "VGA compatible controller" in device:
                        lines = device.strip().split("\n")
                        for line in lines:
                            if "Device" in line:
                                gpu_info.append(line.split(":")[1].strip() or "Unknown GPU")

                if not gpu_info:
                    gpu_info.append("Integrated Graphics")
            except Exception as e:
                print("Error retrieving GPU information:", str(e))
        else:
            print("Unsupported operating system:", system)

        return gpu_info

    def get_bios_info(self):
        system = platform.system()
        if system == "Windows":
            try:
                import wmi

                w = wmi.WMI()
                for bios in w.Win32_BIOS():
                    bios_info = {
                        "BIOS Serial Number": bios.SerialNumber.strip(),
                        "BIOS Version": bios.SMBIOSBIOSVersion.strip()
                    }
                    return bios_info
            except Exception as e:
                print("Error retrieving BIOS information: Does this script have permissions?")
        elif system == "Linux":
            try:
                with open("/sys/class/dmi/id/product_serial", "r") as f:
                    bios_serial = f.read().strip()
                with open("/sys/class/dmi/id/bios_version", "r") as f:
                    bios_version = f.read().strip()
                bios_info = {
                    "BIOS Serial Number": bios_serial,
                    "BIOS Version": bios_version
                }
                return bios_info
            except Exception as e:
                print("Error retrieving BIOS information: Does this script have permissions?")
        else:
            print("Unsupported platform: " + system)
    ### Hardware Info Functions ###


    ### Network Info Functions ###
    def get_local_ip(self):
        try:
            # Create a temporary socket to connect to a known external host
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except Exception as e:
            print("Error retrieving local IP address:", str(e))

        return None


    def get_public_ip(self):
        try:
            output = subprocess.check_output(['nslookup', 'myip.opendns.com', 'resolver1.opendns.com'])
            public_ip = output.decode().strip().split()[-1]
            return public_ip
        except Exception as e:
            print("Error retrieving public IP address:", str(e))
    
        return None

    def get_mac_address(self):
        return ":".join(hex(uuid.getnode())[2:].zfill(12)[i: i + 2] for i in range(0, 12, 2))
    ### Network Info Functions ###


    ### Output Info ###
    def collect_system_info(self):
        # General Sys Info
        self.system_info["Computer Name"] = self.get_pc_name()
        self.system_info["OS Version"] = self.get_os_version()
        self.system_info["Uptime"] = self.get_system_uptime()
        self.system_info["Screen Resolution"] = self.get_display_resolution()
        self.system_info["System Memory"] = self.get_ram_info()
        self.system_info["Disk Usage"] = self.get_disk_usage()

        # Hardware Info
        self.system_info["CPU Hash"] = self.get_cpu_hash()
        self.system_info["GPU Info"] = self.get_gpu_info()
        self.system_info["BIOS Info"] = self.get_bios_info()

        # Get network information
        self.system_info["Network Interface(s)"] = list(psutil.net_if_stats().keys())
        self.system_info["Local IPv4"] = self.get_local_ip()
        self.system_info["Public IP"] = self.get_public_ip()
        self.system_info["MAC Address"] = self.get_mac_address()

    def print_system_info(self, keys=None):
        category_headers = {
            "General Sys Info": ["Computer Name", "OS Version", "Uptime", "Screen Resolution", "System Memory", "Disk Usage"],
            "Hardware Info": ["CPU Hash", "GPU Info", "BIOS Info"],
            "Network Information": ["Network Interface(s)", "Local IPv4", "Public IP", "MAC Address"]
        }

        for category, category_keys in category_headers.items():
            category_used = False  # Flag to track if any item in the category is used

            # Check if any item in the category is used
            for key in category_keys:
                if key in self.system_info and (keys is None or key in keys or "ALL" in map(str.upper, keys)):
                    category_used = True
                    break

            # Print the category name if any item is used
            if category_used:
                print(f": -- {category} -- :")

                # Print the entries
                for key, value in self.system_info.items():
                    if keys is None or key in keys or "ALL" in map(str.upper, keys):
                        if key in category_keys:
                            if isinstance(value, dict):
                                print(f"{key}:")
                                for sub_key, sub_value in value.items():
                                    print(sub_key + ":", sub_value)
                            else:
                                print(key + ":", value)

                print()  # Print a newline after each category
    ### Output Info ###


if __name__ == "__main__":
    collector = SystemInfoCollector()
    collector.collect_system_info()
    
    # Specify the keys you want to print
    keys_to_print = ["all"] # You can also specify specific keys like just ["OS Version"]
    collector.print_system_info(keys_to_print)
