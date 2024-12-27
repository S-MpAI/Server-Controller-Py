import os
import importlib
from venv import EnvBuilder
import subprocess
import sys
import re
import datetime


def printLOGO(CL):
    art = r'''[cyan]
     ____                              ____            _             _ _
    / ___|  ___ _ ____   _____ _ __   / ___|___  _ __ | |_ _ __ ___ | | | ___ _ __
    \___ \ / _ \ '__\ \ / / _ \ '__| | |   / _ \| '_ \| __| '__/ _ \| | |/ _ \ '__|
     ___) |  __/ |   \ V /  __/ |    | |__| (_) | | | | |_| | | (_) | | |  __/ |
    |____/ \___|_|    \_/ \___|_|     \____\___/|_| |_|\__|_|  \___/|_|_|\___|_|
        [r][yellow]by https://github.com/S-MpAI [r][white]| [r][green]ver: [0.1][r] | [r][green]LICENSE: MIT[r]
    '''
    placeholders = {
        '[cyan]': CL.cyan,
        '[r]': CL.r,
        '[yellow]': CL.yellow,
        '[white]': CL.white,
        '[green]': CL.green,
    }

    for placeholder, color_code in placeholders.items():
        art = art.replace(placeholder, color_code)

    print(art)


class ModuleLauncher:
    def __init__(self):
        self.modules = ["paramiko", "colorama", 'PIL']
        self.venv_path = self.is_venv() if self.is_venv() != None else 'v'
        self.venv_related = False
        self.virtual(True)
    
    def is_venv(self):
        return os.environ.get('VIRTUAL_ENV')
    
    def is_installed(self, module):
        try:
            importlib.import_module(module)
            return True
        except ModuleNotFoundError:return False

    def install(self):
        self.out = False
        to_install = []
        for package in self.modules:
            if not self.is_installed(package):
                to_install.append(package)
        if len(to_install) != 0:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *to_install])
            for package in to_install:
                try:
                    importlib.import_module(package)
                except ImportError as err:
                    print(f"{type(err).__name__}:{str(err)}")
                    print(f"[{package}] Ошибка с импортом. Возможно, установка прошла некорректно.")
                    self.out = False
        self.out = True
            
        
    
    def virtual(self, install_modules=False):
        """Checks for virtual environment and optionally installs modules within it."""
        if not os.path.exists(self.venv_path):
            print(f"Virtual environment not found at {self.venv_path}. Creating a new one...")
            EnvBuilder().create(self.venv_path)

        if not self.is_venv() and self.venv_related:
            activate_script = os.path.join(self.venv_path, 'bin', 'activate')
            if os.path.exists(activate_script):
                subprocess.run([activate_script]) 
            else:
                print(f"Activation script not found at {activate_script}.")

        if install_modules:
            self.install() 

ML = ModuleLauncher()
if ML.out:
    import paramiko
    import re
    import sys
    import subprocess
    import colorama
    try:
        from colorama import Fore, Style, init
        colorama_error = False
    except:colorama_error = True
else:
    sys.exit('Иди нахуй')


def _cls():
    os.system('clear')

init(autoreset=True)
class ColorLauncher:
    def __init__(self, colorama_module_error=False):
        self.colorama_module_error = colorama_module_error
        if not self.colorama_module_error:
            self.white = Style.BRIGHT + Fore.WHITE
            self.r = Style.RESET_ALL
            self.green = Style.BRIGHT + Fore.GREEN
            self.red = Style.BRIGHT + Fore.RED
            self.cyan = Style.BRIGHT + Fore.CYAN
            self.black = Style.BRIGHT + Fore.BLACK
            self.yellow = Style.BRIGHT + Fore.YELLOW
        else:
            self.r = ''
            self.green = ''
            self.red = ''
            self.cyan = ''
            self.black = ''
            self.yellow = ''
            self.white = ''

    def has_datetime(self, _):
        try:
            datetime.strptime(_, "%Y-%m-%d %H:%M:%S")
            return True
        except (ValueError, TypeError):
            return False

    def get_color(self, _):
        if _ in ['●', 'loaded', 'enabled', 'LISTEN', 'green']:
            return self.green
        elif _ in ['○', 'unloded', 'disabled', 'red']:
            return self.red
        elif _ in ['time', 'tcp', 'tcp6', 'udp', 'udp6', 'PID_Program_name']:
            return self.cyan
        elif _ in ['None', None]:
            return self.black
        else:
            return self.cyan if self.has_datetime(_) else self.yellow

CL = ColorLauncher(colorama_error)
printLOGO(CL)

class RemoteModuleManager:
    def __init__(self, RemoteServiceManager):
        self.modules = []
        self.RemoteServiceManager = RemoteServiceManager
        self.status = [
            {"name": "neofetch", "status": None},
            {"name": "net-tools", "status": None},
            {"name": "netstat", "status": None},
        ]

    def get_system_type(self):
        """Определяет тип системы (Debian/Arch)"""
        command = "cat /etc/os-release"
        stdout, stderr = self.RemoteServiceManager.execute_command(command)

        if stderr:
            print(f"Ошибка определения типа системы: {stderr.strip()}")
            return None

        if "ID=arch" in stdout:
            return "arch"
        elif "ID=debian" in stdout or "ID=ubuntu" in stdout:
            return "debian"
        else:
            print("Неизвестный тип системы.")
            return None

    def install(self, module):
        system_type = self.get_system_type()

        if system_type == "debian":
            # Установка на Debian-подобных системах
            command = f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {module}"
        elif system_type == "arch":
            # Установка на Arch Linux
            command = f"sudo pacman -S --noconfirm {module}"
        else:
            print(f"Ошибка: поддержка установки на этой системе отсутствует.")
            return False

        stdout, stderr = self.RemoteServiceManager.execute_command(command)

        if stderr and "WARNING:" not in stderr:
            print(f"Ошибка установки модуля {module}: {stderr.strip()}")
            return False
        out = "successfully installed" in stdout.lower() or not stderr
        if not out:
            print(f"Ошибка: {stderr}")
        return out

    def check(self):
        to_install = []
        for command in self.status:
            module_name = command["name"]
            stdout, stderr = self.RemoteServiceManager.execute_command(f"which {module_name}")

            if stderr:
                print(f"Ошибка при проверке статуса модуля {module_name}: {stderr.strip()}")
                command["status"] = f"error: {stderr.strip()}"
            elif stdout.strip():
                command["status"] = "installed"
                print(f"{CL.cyan}[RemoteModuleManager]:{CL.r} {CL.yellow}[{module_name}]{CL.r} {CL.green}установлен.{CL.r}")
            else:
                command["status"] = "not installed"
                to_install.append(module_name)

        for module in to_install:
            success = self.install(module)
            if success:
                print(f"{CL.cyan}[RemoteModuleManager]:{CL.r} {CL.yellow}[{module}]{CL.r} {CL.green}установлен.{CL.r}")
            else:
                print(f"{CL.cyan}[RemoteModuleManager]:{CL.r} {CL.yellow}[{module}]{CL.r} {CL.red}ошибка при установке: {success}{CL.r}")

        return self.status
        

class AntiMalware:
    def __init__(self, RemoteServiceManager):
        self.modules = [
            {"name": "ClamAV", 'commands': {
                "install": "sudo apt update && sudo apt install clamav clamav-daemon",
                "which": "which clamscan",
                "scan": "clamscan -r /",
                "update": "sudo freshclam",
                "update_file": "/var/lib/clamav/daily.cvd",
                "scan_log": "/var/log/clamav/scan.log",
                "supported": True,
                "installed" : None
            }},
            {"name": "SophosAntivirus", 'commands': {
                "install": "mkdir SophosAntivirusInstall && cd SophosAntivirusInstall && wget [installUrl] && tar -xvf sophos-av-linux.tgz && cd sophos-av && sudo ./install.sh",
                "which": "which savscan",
                "scan": "/opt/sophos-av/bin/savscan /",
                "update": "/opt/sophos-av/bin/savupdate",
                "update_file": None, 
                "scan_log": None,  
                "supported": False,
                "installed" : None
            }}
        ]
        self.RemoteServiceManager = RemoteServiceManager
        self.is_installed("ClamAV")
        self.is_installed("SophosAntivirus")

    def is_installed(self, name):
        """Проверяет, установлен ли антивирус и сохраняет результат в self.modules."""
        module_index = next((i for i, m in enumerate(self.modules) if m['name'].lower() == name.lower()), None)
        if module_index is None:
            return False, f"Модуль {name} не найден."

        module = self.modules[module_index]
        command = module['commands']['which']
        out, err = self.RemoteServiceManager.execute_command(command)
        is_installed = bool(out.strip())
        self.modules[module_index]['commands']["installed"] = is_installed  

        return is_installed, err.strip()


    def install(self, name):
        """Устанавливает антивирус."""
        module = self.get_module_info(name)
        if not module:
            return f"Модуль {name} не найден."
        if not module['commands']['supported']:
            return f"Установка {name} не поддерживается."

        command = module['commands']['install']
        out, err = self.RemoteServiceManager.execute_command(command)
        return out, err

    def scan(self, name, path="/"):
        """Запускает сканирование системы."""
        module = self.get_module_info(name)
        if not module:
            return f"Модуль {name} не найден."

        command = module['commands']['scan'].replace("/", path)
        out, err = self.RemoteServiceManager.execute_command(command)
        if not err and module['commands']['scan_log']:
            with open(module['commands']['scan_log'], 'a') as log_file:
                log_file.write(f"Last scan: {datetime.datetime.now()}\n")
        return out, err

    def update(self, name):
        """Обновляет базы антивируса."""
        module = self.get_module_info(name)
        if not module:
            return f"Модуль {name} не найден."

        command = module['commands']['update']
        out, err = self.RemoteServiceManager.execute_command(command)
        return out, err

    def get_last_update(self, name):
        """Возвращает дату последнего обновления баз данных."""
        module = self.get_module_info(name)
        if not module:
            return f"Модуль {name} не найден."

        update_file = module['commands'].get('update_file')
        if update_file and os.path.exists(update_file):
            return datetime.datetime.fromtimestamp(os.path.getmtime(update_file))
        return "Информация об обновлении недоступна."

    def get_last_scan(self, name):
        """Возвращает дату последнего сканирования."""
        module = self.get_module_info(name)
        if not module:
            return f"Модуль {name} не найден."

        scan_log = module['commands'].get('scan_log')
        if scan_log and os.path.exists(scan_log):
            with open(scan_log, 'r') as log_file:
                lines = log_file.readlines()
                for line in reversed(lines):
                    if "Last scan:" in line:
                        try:
                            return datetime.datetime.strptime(line.split(":", 1)[1].strip(), "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            continue
        return "Информация о сканировании недоступна."

    def compare_last_update_and_scan(self, name):
        """Сравнивает даты последнего обновления баз данных и последнего сканирования."""
        last_update = self.get_last_update(name)
        last_scan = self.get_last_scan(name)

        if isinstance(last_update, str) or isinstance(last_scan, str):
            return f"Не удалось определить даты: обновление - {last_update}, сканирование - {last_scan}."

        if last_scan < last_update:
            return "Базы данных обновлялись после последнего сканирования. Рекомендуется выполнить новое сканирование."
        return "Сканирование выполнено после последнего обновления баз данных."

    def get_supported_modules(self):
        """Возвращает список поддерживаемых антивирусов."""
        return [module['name'] for module in self.modules if module['commands']['supported']]
    
    def get_installed_modules(self):
        """Возвращает список поддерживаемых антивирусов."""
        return [module['name'] for module in self.modules if module['commands']['installed']]

    def get_module_info(self, name):
        """Возвращает информацию о модуле по имени."""
        for module in self.modules:
            if module['name'].lower() == name.lower():
                return module
        return None


class RemoteServiceManager:
    def __init__(self, hostname, username, password=None, port=22, key_file=None, is_local=False, custom_username = None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.key_file = key_file
        self.client = None
        self.is_local = is_local
        self.custom_username = custom_username if custom_username != None else f"{username}@{hostname}"
    
    def connect(self):
        """Подключиться к удаленному серверу по SSH"""
        if self.hostname == None:
            print(f'\n{'-'*30}\n{CL.red}[!] Ошибка! \n{CL.cyan}Хост не может быть пустым!{CL.r}\n{'-'*30}\n')
            sys.exit(1)
        elif self.username == None:
            print(f'{CL.red}[!] Ошибка! \n{CL.cyan}Имя пользователя не может быть пустым!{CL.r}')
            sys.exit(1)

        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.key_file:
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_file
                )
            else:
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.password
                )
            print(f"{CL.cyan}[RemoteServiceManager]:{CL.r} {CL.green}Подключение к {self.custom_username} успешно!{CL.r}")
        except paramiko.ssh_exception.NoValidConnectionsError as err:
            print(f'{CL.red}[!] Скрипт не смог подключиться к системе {CL.green}{self.custom_username}\n{CL.cyan}Проверьте хост.{CL.r}')
            sys.exit(1)
        except paramiko.ssh_exception.AuthenticationException as err:
            if 'Authentication failed.' in str(err):
                print(f'{CL.red}[!] Скрипт не смог подключиться к системе {CL.green}{self.custom_username}\n{CL.cyan}Неправильный логин или пароль.{CL.r}')
            else:
                print(f'{CL.red}[!] Скрипт не смог подключиться к системе {CL.green}{self.custom_username}\n{CL.cyan}{type(err).__name__}: {str(err)}{CL.r}')
            sys.exit(1)
        except Exception as e:
            if str(type(e).__name__) == "paramiko":
                print(f'{CL.red}[!] Скрипт не смог подключиться к системе {CL.green}{self.custom_username}\n{CL.cyan}{type(err).__name__}: {str(err)}{CL.r}')
            else:
                print(f"\n{'-'*30}{CL.red}\nКритическая ошибка при подключении к системе {CL.green}{self.custom_username}{CL.r}\n{CL.cyan}{type(e).__name__}: {CL.r}{CL.red}{str(e)}\n{CL.r}{'-'*30}\n")
            sys.exit(1)
    
    def disconnect(self):
        """Отключиться от удаленного сервера"""
        if self.client:
            self.client.close()
            print(f"Отключено от {self.hostname}")
    
    def execute_command(self, command):
        """Выполнить команду на удаленном сервере и вернуть результат"""
        if self.is_local == False:
            if self.client:
                try:
                    stdin, stdout, stderr = self.client.exec_command(command)
                except paramiko.ssh_exception.SSHException as err:
                    if 'SSH session not active' in str(err):
                        print(f'{CL.red}[!] Скрипт не смог выполнить команду {CL.green}{self.hostname}\n{CL.cyan}Соединение было прервано.{CL.r}')
                    else:
                        print(f'{CL.red}[!] Скрипт не смог выполнить команду {CL.green}{self.hostname}\n{CL.cyan}{type(err).__name__}: {str(err)}{CL.r}')
                    self.client = None
                    return '', '', ''
                return stdout.read().decode(), stderr.read().decode()
            return "", "SSH-клиент не подключен"
        else:
            out, err = None, None
            try:
                result = subprocess.run(command, shell=True, text=True, capture_output=True)
                out = result.stdout.strip()
                err = result.stderr.strip() 
            except Exception as e:
                print(f"Неожиданная ошибка: {e}")
                err = str(e)
            return out, err

import concurrent.futures
class ServiceCommandExplorer:
    def __init__(self, SSHClient):
        self.ssh_client = SSHClient
        self.RMManager = RemoteModuleManager(self.ssh_client)
        self.RMManager.check()

        self.AM = AntiMalware(SSHClient)
        try:
            is_installed, error = self.AM.is_installed("ClamAV")
            if is_installed:
                print(f"{CL.cyan}[AntiMalware]:{CL.r} На вашей системе найден антивирус {CL.green}ClamAV{CL.r}.")
                update_out, update_err = self.AM.update(name="ClamAV")
                if not update_err:
                    print(f"{CL.cyan}[AntiMalware]:{CL.r} {CL.green}[ClamAV]{CL.r} База данных была автоматически обновлена.")
                else:
                    print(f"{CL.cyan}[AntiMalware]:{CL.r} Ошибка обновления базы данных: {update_err}")
                # scan_out, scan_err = self.AM.scan(name="ClamAV", path="/")
                # if not scan_err:
                #     print(f"{CL.cyan}[AntiMalware]:{CL.r} {CL.red}[ClamAV] Сканирование системы завершено.{CL.r}")
                # else:
                #     print(f"{CL.cyan}[AntiMalware]:{CL.r} Ошибка при сканировании: {scan_err}")
            else:
                print(f"{CL.cyan}[AntiMalware]:{CL.r} {CL.red}Антивирус{CL.r} {CL.green}ClamAV{CL.r} {CL.red}не установлен.{CL.r}")
                if error:
                    print(f"Ошибка при проверке установки: {error}")

        except Exception as e:
            print(f"{CL.cyan}[AntiMalware]:{CL.r} Произошла ошибка: {e}")


    
    def get_port_information_desc(self, port, inf= None):
        try:
            port = str(port).split(":")
            port = port[-1]
            port = int(port)
        except: return ''


        if port == 5000:
            if inf and 'league of legends' not in inf.lower():
                return f"[Possible Backdoor]"
            else:
                return f"[League of Legends]"
        if port == 10086:
            if inf and 'v2ray' not in inf.lower():
                return f"[Possible Backdoor]"
            else:
                return f"[v2ray]"
        
        
        if port == 1242:
            if inf and 'ArchiSteamFa' not in inf:
                return f"[Possible Backdoor]"
            else:
                return f"[ArchiSteamFarm]"

        
        if port == 9993:
            if inf and 'zerotier-one' not in inf.lower():
                return f"[Possible Backdoor]"
            else:
                return f"[Zerotier]"



        # ИНСТРУМЕНТЫ
        if port == 53:return f"[DNS]"
        elif port == 22: return f"[SSH]"
        elif port == 80: return f"[HTTP]"
        elif port == 443:return f"[HTTPS]"
        elif port == 25: return f"[SMTP]"
        elif port == 21: return f"[FTP]"
        elif port == 3389: return f"[RDP]"
        elif port == 23: return '[Telnet Daemon]'
        elif port == 3306: return '[MySQL Server]'
        elif port == 1433: return '[MSSQL Server]'
        elif port == 1243: return '[SubSeven]'
        elif port == 1080: return '[1080]'
        elif port == 500: return '[ISAKMP]'
        elif port == 445: return '[Microsoft DS]'
        elif port == 194: return '[IRC]'
        elif port == 143: return '[IMAP]'
        elif port == 139: return '[NETBIOS-SSN]'
        elif port == 138: return '[NETBIOS-DGM]'
        elif port == 110: return '[POP3]'
        # ИГРЫ
        elif port == 27015: return '[STEAM]'
        elif (2456 <= port <= 2458):return '[Valheim]'
        elif port == 7777: return '[Terraria/SCP]'
        elif port == 25565: return '[Minecraft]'
        elif (88 <= port <= 90): return '[Xbox Live]'
        elif port == 1802: return "[Baldur's Gate, Neverwinter Nights]"
        elif port == 3724: return '[World of Warcraft]'
        elif port == 5000: return '[League of Legends]'
        # БЕКДОРЫ
        elif port == 4444: return '[Possible Backdoor] [Metasploit]'
        elif port == 12345: return '[Possible Backdoor] [NetBus]'
        elif port == 31337: return '[Possible Backdoor] [Back Orifice]'
        elif port == 5555: return '[Possible Backdoor] [ADB]'
        elif (6666 <= port <= 6669): return '[Possible Backdoor] [IRC-based Trojans]'
        elif port == 10000: return '[Possible Backdoor] [Webmin]'
        elif port == 31337: return '[Possible Backdoor] [Back Orifice]'
        elif port == 30003: return '[Possible Backdoor] [Lamers Death]'
        elif port == 27374: return '[Possible Backdoor] [SubSeven]'
        elif port == 21544: return '[Possible Backdoor] [GirlFriend]'
        elif port == 12348: return '[Possible Backdoor] [BioNet]'
        else: return ''
    
    def list_user_or_root_processes(self):
        command = "ls /etc/systemd/system/"
        stdout, stderr = self.ssh_client.execute_command(command)
        if stderr:
            print(f"Ошибка при получении списка служб: {stderr.strip()}")
            return []
        blocklisted_services = {'vmtoolsd.service', 'iscsi.service', 'display-manager.service', 'chrome-remote-desktop.service'}
        return [
            service for service in stdout.splitlines()
            if service.endswith(".service") and not service.startswith("dbus-") and service not in blocklisted_services
        ]

    def remove_ansi_escape_sequences(self, text):
        ansi_escape_pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape_pattern.sub('', text)
    
    def convert_to_gb(self, memory_str):
        used, total = memory_str.split(' / ')
        used_mb = float(used.replace('MiB', '').strip())
        total_mb = float(total.replace('MiB', '').strip())
        used_gb = round(used_mb / 1024, 2)
        total_gb = round(total_mb / 1024, 2)
        
        return f"{used_gb}GB / {total_gb}GB"
    
    def get_neofetch(self):
        command = "neofetch"
        stdout, stderr = self.ssh_client.execute_command(command)
        if stderr:
            print(f"Ошибка при получении neofetch: {stderr.strip()}")
            return None
        info = {}
        stdout = self.remove_ansi_escape_sequences(stdout)
        lines = stdout.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if "@" in line and "root" in line:
                info['user_host'] = line
            elif "OS:" in line:
                info['os'] = line.split("OS:", 1)[1].strip()
            elif "Host:" in line:
                info['host'] = line.split("Host:", 1)[1].strip()
            elif "Kernel:" in line:
                info['kernel'] = line.split("Kernel:", 1)[1].strip()
            elif "Uptime:" in line:
                info['uptime'] = line.split("Uptime:", 1)[1].strip()
            elif "Packages:" in line:
                info['packages'] = line.split("Packages:", 1)[1].strip()
            elif "Shell:" in line:
                info['shell'] = line.split("Shell:", 1)[1].strip()
            elif "Resolution:" in line:
                info['resolution'] = line.split("Resolution:", 1)[1].strip()
            elif "CPU:" in line:
                info['cpu'] = line.split("CPU:", 1)[1].strip()
            elif "GPU:" in line:
                info['gpu'] = line.split("GPU:", 1)[1].strip()
            elif "Memory:" in line:
                info['opmemory'] = self.convert_to_gb(line.split("Memory:", 1)[1].strip())
        return info
    
    def get_service_journal(self, service):
        """Получить журнал службы на удаленном сервере"""
        command = f"journalctl -u {service} -n 10"
        stdout, stderr = self.ssh_client.execute_command(command)
        if stderr:
            print(f"Ошибка при получении журнала службы {service}: {stderr.strip()}")
            return None
        return stdout.strip().split('\n')
    
    def get_port_information(self, port=None):
        command = 'sudo netstat -tulnp'
        stdout, stderr = self.ssh_client.execute_command(command)
        if stderr:
            if (str(stderr.strip()) == 'sudo: netstat: command not found'):
                self.RMManager.check()
            print(f"Ошибка при получении статуса порта {port}: {stderr.strip()}")
            return None
        out = []
        indx = 0
        splt = stdout.split('\n')[2:]
        State = None
        for li in splt:
            if (port == None) or (str(port) in str(li)):
                s1 = li.split()
                _len_s1 = len(s1)
                
                if (len(s1) == 7) or (len(s1) == 8):
                    State = s1[5]
                    PID_Program_name = s1[6]
                elif len(s1) == 6:
                    State = None
                    PID_Program_name = s1[5]
                
                if len(s1) != 0:
                    dt = {
                        "Proto" : s1[0],
                        "Recv-Q" : s1[1],
                        "Send_Q" : s1[2],
                        "Local_Address" : f"{s1[3]}",
                        'Foreign_Address': s1[4],
                        "State" : State,
                        "PID_Program_name": PID_Program_name,
                    }
                    out.append(dt)
        return out

    def get_service_details(self, service):
        """Получить детали службы на удаленном сервере"""
        if '@' in str(service):
            service = service[:service.find('@')]
        name_service = service
        command = f"systemctl status {service}"
        stdout, stderr = self.ssh_client.execute_command(command)
        if stdout:
            data = stdout.strip()
            len_d = len(data.replace('     ', '').split('\n'))
            d1 = data.replace('     ', '').split('\n')[0]
            d2 = data.replace('     ', '').split('\n')[1].replace(';', '').replace('(', '').replace(')', '')
            d3 = data.replace('     ', '').split('\n')[2]
            status_color = d1.split(' ')[0]
            title = name_service
            loaded_status = d2.split(' ')[1]
            loaded_path = d2.split(' ')[2].split(',')[0]
            autorun_status = d2.split(' ')[3]
            preset_status = d2.split(' ')[5]
            active_status = d3.split(' ')[1]
            
            active_information = d3.split(' ')[2]
            try:
                service_start_time = ' '.join(d3.split(' ')[3:6]) 
                if d3.split(' ')[1] == "since":
                    service_start_time = ' '.join(d3.split(' ')[2:5])  
                else:
                    for line in data.split('\n'):
                        line = line.replace('     ', '').split('\n')
                        for _ in line:
                            if "since" in _ and "Notice" not in _:
                                service_start_time = _.split('since')[-1].replace('UTC', '').split(';')[0]
                                service_start_time = service_start_time[5:]
                                break
                if active_information != '(dead)':
                    main_pid = data.replace('     ', '').split('\n')[3].replace('   ', '')
                    tasks = data.replace('     ', '').split('\n')[4].replace(' ', '')
                    memory = data.replace('     ', '').split('\n')[5]
                    cpu = data.replace('     ', '').split('\n')[6].replace('   ', '')
                else:
                    service_start_time = None
                    main_pid = None
                    tasks = None
                    memory = None
                    cpu = None
            except IndexError: 
                service_start_time = None
                main_pid = None
                tasks = None
                memory = None
                cpu = None


                        
            return {
                "output_status" : 'ok',
                "status_color": status_color,
                "title" : title,
                "loaded_status" :  loaded_status,
                "loaded_path" : loaded_path,
                "autorun_status" : autorun_status,
                "preset_status" : preset_status,
                "active_status" : active_status,
                "active_information" : active_information,
                "service_start_time" : service_start_time,
                "main_pid" : main_pid,
                "tasks" : tasks,
                "memory" : memory,
                "cpu" : cpu,
            }
        return {
            "output_status" : 'error',
            "error": f"{stderr}",
            "stdout" : f"{stdout}"
        }

class Main():
    def __init__(self, hostname=None, username=None, password=None, key_file=None, custom_username = None):
        self.r = Style.RESET_ALL
        self.osName = sys.platform
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_file = key_file
        if self.osName == 'linux':
            self.ssh_client = RemoteServiceManager(hostname, username, password, key_file=key_file, is_local=True, custom_username = custom_username)
            self.state = f'Локально'
        else:
            self.ssh_client = RemoteServiceManager(hostname, username, password, key_file=key_file, is_local=False, custom_username = custom_username)
            self.ssh_client.connect()
            self.state = f'{self.ssh_client.custom_username}'
        
        self.explorer = ServiceCommandExplorer(self.ssh_client)
        self.clr = f"{CL.green}" if self.state != "Локально" else f"{CL.red}"

        
    
    def delete_color(self, s):
        return s.replace(CL.green, '').replace(CL.red, '')

    def get_index(self, inputInt):
        if inputInt < 10:
            return 5
        elif inputInt < 100 and inputInt >= 9:
            return 4
        else:
            return 3
    
    def has_datetime(self, value):
        """Проверяет, содержит ли строка дату и время в формате YYYY-MM-DD HH:MM:SS."""
        pattern = r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b"
        return bool(re.search(pattern, value))
    
    def get_color(self, _):
        if (_ == '●') or (_ == 'loaded') or (_ == 'enabled') or (_ == 'LISTEN') or (_ == 'green'):
            return CL.green
        elif (_ == '○') or (_ == 'unloded') or (_ == 'disabled') or (_ == 'red'):
            return CL.red
        elif (_ == 'time') or (_ == 'tcp') or (_ == 'tcp6') or (_ == 'udp') or (_ == 'udp6') or (_ == 'PID_Program_name'):
            return CL.cyan
        elif (_ == 'None') or (_ == None):
            return CL.black
        else:
            if self.has_datetime(_):
                return CL.cyan
            else:
                return CL.yellow

    
    def cls(self):
        # os.system('cls' if os.name=='nt' else 'clear')
        pass
     
    def printNeofetchTable(self):
        self.neofetch = self.explorer.get_neofetch()
        print(f"┌{'─'*61}┐")
        print(f"│ {' '*22} {self.state} {' '*22} │")
        print(f"├{'─'*13}┬{'─'*47}┤")
        for _ in self.neofetch:
            print(f'''│ {_.title()}{' '* (11-len(_))} │ {self.neofetch[_]}{' '* (45-len(self.neofetch[_]))} │''')
        print(f"└{'─'*13}┴{'─'*47}┘")
        


    

    def printTable(self):
        # self.cls()
        self.get_service_list = self.explorer.list_user_or_root_processes()
        ind = 0
        print(f"┌{'─'*7}{'─'*5}{'─'*30}{'─'*17}{'─'*14}{'─'*22}┐")
        print(f"│ {' '*39} {self.clr}{self.state}{CL.r}{' '*(54-len(self.state))}│")# {' '*39} │")
        print(f"├{'─'*7}┬{'─'*3}┬{'─'*30}┬{'─'*16}┬{'─'*13}┬{'─'*21}┤")
        print(f"│ Index │{' '*3}│{' '*11} Title {' '*11} │ {' '*1}Load Status {' '*1} │ {' '*1} AutoRun {' '*1} │ {' '*1}ServiceStartTime {' '*1} │ ")
        print(f"├{'─'*7}┼{'─'*3}┼{'─'*30}┼{'─'*16}┼{'─'*13}┼{'─'*21}┤")
        for service in self.get_service_list:
            ind = ind + 1
            service = self.explorer.get_service_details(service)
            if service['output_status'] != 'ok':
                print(f"Error Status: {service['error']}")
                break
            print(f'''│{" "*self.get_index(ind)}{ind} │ {self.get_color(service['status_color'])}{service['status_color']}{self.r} │ {service['title']}{' '* (28-len(service['title']))} │ {self.get_color(service['loaded_status'])}{service['loaded_status']}{' '* (14-len(service['loaded_status']))}{self.r} │ {self.get_color(service['autorun_status'])}{service['autorun_status']}{self.r}{' '* (11-len(service['autorun_status']))} │ {self.get_color(service['service_start_time'])}{service['service_start_time']}{' '* (20-len(str(service['service_start_time'])))}{self.r}│''')
        print(f"└{'─'*7}┴{'─'*3}┴{'─'*30}┴{'─'*16}┴{'─'*13}┴{'─'*21}┘")
    
    def printPorts(self):
        # self.cls()
        self.get_port_list = self.explorer.get_port_information()
        if (self.get_port_list == None):
            print(self.get_port_list)
            return
        ind = 0
        print(f"┌{'─'*7}┬{'─'*8}┬{'─'*8}┬{'─'*27}┬{'─'*32}┬{'─'*22}┬{'─'*13}┐")
        print(f"│ Index │ Proto  │ State  │{' '*3} PID / Program_name {' '*3} │ {' '*9}LocalAddress{' '*9} │ {' '*2}Foreign_Address{' '*3} │{' '*0}Recv-Q/Send-Q{' '*0}│ ")
        print(f"├{'─'*7}┼{'─'*8}┼{'─'*8}┼{'─'*27}┼{'─'*32}┼{'─'*22}┼{'─'*13}┤")
        for port in self.get_port_list:
            ind = ind + 1
            d1 = ' '*(5-len(port['Proto']))
            d2 = ' '*(6-len(str(port['State'])))
            d3 = ' '*(25-len(str(port['PID_Program_name'])))
            out = self.explorer.get_port_information_desc(str(port['Local_Address']), str(port['PID_Program_name']))
            d4 = ' '*(30-len(str(port['Local_Address'])))
            d4 = d4.replace(' ', '', len(str(out))) + out
            d5 = ' '*(20-len(str(port['Foreign_Address'])))
            d6 = ' '*(10-len(str(port['Recv-Q'])+str(port['Send_Q'])))
            print(f'''│{" "*self.get_index(ind)}{ind} │  {self.get_color(port['Proto'])}{port['Proto']}{self.r}{d1} │ {self.get_color(port['State'])}{port['State']}{self.r}{d2} │ {self.get_color('PID_Program_name')}{port['PID_Program_name']}{self.r}{d3} │ {self.get_color('green')}{port['Local_Address']}{self.r}{d4} │ {self.get_color('red')}{port['Foreign_Address']}{d5}{self.r} │ {port['Recv-Q']}/{port['Send_Q']}{d6} │''')
        print(f"└{'─'*7}┴{'─'*8}┴{'─'*8}┴{'─'*27}┴{'─'*32}┴{'─'*22}┴{'─'*13}┘")


    
    def start(self):
        self.cls()
        self.printTable()
        ten_val = 'Запустить сканирование системы'
        ten_val_bool = False
        if len(self.explorer.AM.get_installed_modules()) == 0:
            ten_val = f"[НЕДОСТУПНО] {ten_val} (нет антивирусов)"
            ten_val_bool = True
        while True:
            try:
                out = int(input(f'''
[1] Обновить таблицу SERVICE.
[2] Показать таблицу PORT
[3] Показать всю информацию об системе
[4] Очистить все журналы
[5] Перезагрузить Daemon 
[6] Изменить параметр автозагрузки.
[7] Изменить статус (active/inactive)
[8] Получить последний вывод
[9] Консоль (ввод/вывод)
[10] {ten_val}
[11] Закрыть приложение.

Выберите нужное вам действие
>>> '''))
        
                if out == 1:
                    self.printTable()
                elif out == 2:
                    self.printPorts()
                elif out == 3:
                    self.printNeofetchTable()
                elif out == 4:
                    self.set_daemon_reload()
                elif out == 5:
                    self.delete_all_journals()
                elif out == 6:
                    self.edit_autostart()
                elif out == 7:
                    self.edit_status()
                elif out == 8:
                    self.get_journal()
                elif out == 9:
                    self.get_console()
                elif out == 10:
                    if ten_val_bool == True:
                        continue
                    else:self.start_scan()
                elif out == 11:
                    sys.exit(1)
                else:
                    print("Выбранное действие не существует.")
            except KeyboardInterrupt:break
            except ValueError:
                print("Введите число!")
                continue
            except Exception as e:
                print(f"Ошибка: {type(e).__name__}: {e}")
                continue
    
    def edit_autostart(self):
        self.cls()
        self.printTable()
        self.get_service_list = self.explorer.list_user_or_root_processes()
        a = {}
        for i, service in enumerate(self.get_service_list):
            a[str(i+1)] = service
        isNorm = False
        while isNorm == False:
            try:
                out = int(input('''
Введите индекс нужного вам .service файла, иначе 0.
[.] >>> '''))
                if out == 0:
                    break
                else:
                    try:
                        service = a[str(out)]
                        service = self.explorer.get_service_details(service)
                        if service['autorun_status'] == 'disabled':
                            service['autorun_status'] = 'enable'
                        else:
                            service['autorun_status'] = 'disable'
                        self.edit_service(service)
                        isNorm = True
                    except Exception as e:
                        print(f"Ошибка: {type(e).__name__}: {e}")
                        print(f"Служба с индексом {out} не найдена.")
                        continue
            except:
                print("Введите число!")
                continue
        self.cls()
        self.printTable()
    
    def print_port_status(self):
        self.cls()

    
    def edit_status(self):
        self.cls()
        self.printTable()
        self.get_service_list = self.explorer.list_user_or_root_processes()
        a = {}
        for i, service in enumerate(self.get_service_list):
            a[str(i+1)] = service
        # print(a)
        isNorm = False
        while isNorm == False:
            try:
                out = int(input('''
Введите индекс нужного вам .service файла, иначе 0.
[.] >>> '''))
                if out == 0:
                    break
                else:
                    try:
                        service = a[str(out)]
                        service = self.explorer.get_service_details(service)
                        print(service)
                        if service['service_start_time'] == None:
                            self.ssh_client.execute_command(f'systemctl start {service["title"]}')
                        else:
                            self.ssh_client.execute_command(f'systemctl stop {service["title"]}')
                        isNorm = True
                    except Exception as e:
                        print(f"Ошибка: {type(e).__name__}: {e}")
                        print(f"Служба с индексом {out} не найдена.")
                        continue
            except:
                print("Введите число!")
                continue
        self.cls()
        self.printTable()
    
    def set_daemon_reload(self):
        self.cls()
        self.ssh_client.execute_command(f'systemctl daemon-reload')
        self.printTable()
    
    def delete_all_journals(self):
        self.cls()
        self.ssh_client.execute_command(f'sudo journalctl --rotate && sudo journalctl --vacuum-time=1s')
        self.printTable()
    
    def start_scan(self):
        print(f"{CL.cyan}[AntiMalware]:{CL.r} {CL.yellow}[ClamAV] Запущено сканирование системы.{CL.r}")
        scan_out, scan_err = self.explorer.AM.scan(name="ClamAV", path="/")
        if not scan_err:
            print(scan_out)
            print(f"{CL.cyan}[AntiMalware]:{CL.r} {CL.green}[ClamAV] Сканирование системы завершено.{CL.r}")
        else:
            print(f"{CL.cyan}[AntiMalware]:{CL.r} {CL.red}[ClamAV]Ошибка при сканировании: {scan_err}{CL.r}")
        
    
    def get_journal(self):
        self.cls()
        self.printTable()
        self.get_service_list = self.explorer.list_user_or_root_processes()
        a = {}
        for i, service in enumerate(self.get_service_list):
            a[str(i+1)] = service
        isNorm = False
        while isNorm == False:
            try:
                out = int(input('''
Введите индекс нужного вам .service файла, иначе 0.
[.] >>> '''))
                if out == 0:
                    break
                else:
                    try:
                        service = a[str(out)]
                        data = self.explorer.get_service_journal(service)
                        for _ in data:
                            print(_)
                        isNorm = True
                    except Exception as e:
                        print(f"Ошибка: {type(e).__name__}: {e}")
                        print(f"Служба с индексом {out} не найдена.")
                        continue
            except:
                print("Введите число!")
                continue
        print()
        self.printTable()
    
    def get_console(self):
        keyb = False
        while keyb == False:
            try:
                command = input(">>> ")
                if command.lower() == "exit":
                    print("Exiting console...")
                    keyb = True
                    break
                stdout, stderr = self.ssh_client.execute_command(command)
                if (str(stdout) != '') or stdout != None:
                    print(f"{CL.cyan}{stdout}{CL.r}")
                if (str(stderr) != '') or stderr != None:
                    print(f"{CL.red}{stderr}{CL.r}")
            except KeyboardInterrupt:
                keyb = True
                break
            except:pass
        self.printTable()
    
    def edit_service(self, service):
        value, service_name = service['autorun_status'], service['title'] 
        out = self.ssh_client.execute_command(f'systemctl {value} {service_name}')



if __name__ == "__main__":
    try:
        from SSHServerConnector import Account
        installed = True
    except: installed = False

    if installed:
        ACC = Account(Main)
        ACC.start()
    else:
        hostname = None
        username = None
        password = None
        key_file = None
        custom_username = None
        M = Main(hostname, username, password, key_file, custom_username)
        M.start()
