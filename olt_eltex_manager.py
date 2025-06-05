import sys
import time
import re
import logging
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QComboBox,
    QPushButton, QLabel, QLineEdit, QTextEdit, QMessageBox,
    QTabWidget, QHBoxLayout, QGridLayout
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
import paramiko


# Настройка логгирования
LOG_FILENAME = "olt_connector.log"
logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class SSHClient:
    def __init__(self, host, port=22, username="admin", password="password", timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.username = username
        self.password = password
        self.client = None
        self.shell = None
        self.output_area = None  # Для вывода в GUI
        self.connect()

    def set_output_area(self, output_area):
        """Привязывает текстовое поле GUI к клиенту"""
        self.output_area = output_area

    def _log(self, message):
        """Логгирует сообщение в консоль, файл и GUI"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"[{timestamp}] {message}"
        print(full_message)
        logging.debug(message)
        if self.output_area:
            self.output_area.append(full_message)

    def connect(self):
        """Устанавливает SSH-соединение и ждет приглашения командной строки"""
        try:
            self._log(f"Подключение к {self.host}:{self.port}...")
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            self.shell = self.client.invoke_shell()
            self._log("Соединение установлено")

            # Ждём приглашения
            if not self._wait_for_prompt(prompt="#", timeout=10) and not self._wait_for_prompt(prompt=">", timeout=5):
                raise ConnectionError("Не удалось определить приглашение после входа по SSH")
            else:
                self._log("Аутентификация успешна")
        except Exception as e:
            raise ConnectionError(f"Connection failed: {str(e)}")

    def _read_all(self, timeout=2):
        """Читает всё, что есть в буфере с улучшенной логикой"""
        output = ""
        start_time = time.time()
        
        # Сначала читаем всё, что есть сразу
        while self.shell.recv_ready():
            data = self.shell.recv(65535).decode('utf-8', 'ignore')
            output += data
            time.sleep(0.1)
        
        # Затем ждем новых данных до таймаута
        while time.time() - start_time < timeout:
            if self.shell.recv_ready():
                data = self.shell.recv(65535).decode('utf-8', 'ignore')
                output += data
                # Сбросить таймер при получении данных
                start_time = time.time()
            else:
                time.sleep(0.1)
        
        self._log(f"[Прочитано {len(output)} символов]")
        return output

    def _wait_for_prompt(self, prompt="#", timeout=10):
        """Ждет появления указанного приглашения"""
        buffer = ""
        start_time = time.time()
        while time.time() < start_time + timeout:
            if self.shell.recv_ready():
                data = self.shell.recv(9999).decode('utf-8', 'ignore')
                buffer += data
                if prompt in buffer or ">" in buffer:
                    self._log(f"[Найдено приглашение]:\n{buffer}")
                    return True
            time.sleep(0.2)
        self._log(f"[ОШИБКА] Приглашение не найдено за {timeout} секунд")
        return False

    def _send(self, command):
        """Отправляет команду через SSH"""
        self.shell.send(command + "\r\n")  # CR+LF — стандарт для сетевых устройств
        self._log(f"[ОТПРАВЛЕНО]: {command}")
        time.sleep(0.5)

    def send_command(self, command, wait_time=2):
        """Отправляет команду и получает ответ"""
        try:
            self._send(command)
            response = self._read_all(timeout=wait_time)
            return response
        except Exception as e:
            raise RuntimeError(f"Ошибка команды: {str(e)}")

    def logout(self):
        """Разлогинивается с OLT"""
        try:
            self._send("exit")
            time.sleep(1)
            self._log("Выполнен выход с OLT")
        except:
            pass

    def close(self):
        """Закрывает соединение"""
        if self.client:
            self.client.close()
            self._log("Соединение закрыто")


class OLTApp(QWidget):
    def __init__(self):
        super().__init__()
        self.ssh = None
        self.current_ip = None
        self.cached_config = None
        self.cached_config_olt = None
        self.last_ont_interface = None  # Последний найденный интерфейс ONT
        self.initUI()

    def initUI(self):
        self.setWindowTitle('OLT Eltex Manager (SSH)')
        self.setGeometry(300, 300, 900, 750)  # Увеличим размер окна
        main_layout = QVBoxLayout()

        # Создаем вкладки
        self.tabs = QTabWidget()
        
        # Вкладка 1: Поиск ONT
        self.tab_search = QWidget()
        tab_search_layout = QVBoxLayout()
        
        # IP-выбор и подключение
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("Выберите OLT:"))
        
        self.ip_combo = QComboBox()
        self.ip_combo.addItems([
            "10.10.1.105",
            "10.10.1.108",
            "10.10.1.109",
            "10.10.1.110",
            "10.10.1.111",
            "10.10.1.112"
        ])
        ip_layout.addWidget(self.ip_combo)
        
        self.connect_btn = QPushButton("Подключиться")
        self.connect_btn.clicked.connect(self.connect_to_olt)
        ip_layout.addWidget(self.connect_btn)
        
        tab_search_layout.addLayout(ip_layout)
        
        self.status_label = QLabel("Статус: Не подключено")
        tab_search_layout.addWidget(self.status_label)
        
        # Поиск ONT
        tab_search_layout.addWidget(QLabel("Введите серийный номер ONT:"))
        self.serial_input = QLineEdit()
        self.serial_input.setPlaceholderText("Пример: ELTX6203512C")
        tab_search_layout.addWidget(self.serial_input)
        
        self.search_btn = QPushButton("Найти конфигурацию")
        self.search_btn.clicked.connect(self.find_ont_config)
        self.search_btn.setEnabled(False)
        tab_search_layout.addWidget(self.search_btn)
        
        # Вывод для вкладки поиска
        self.search_output = QTextEdit()
        self.search_output.setReadOnly(True)
        self.search_output.setPlaceholderText("Здесь будет отображена информация о поиске...")
        tab_search_layout.addWidget(self.search_output)
        
        self.tab_search.setLayout(tab_search_layout)
        self.tabs.addTab(self.tab_search, "Поиск ONT")
        
        # Вкладка 2: Командная строка
        self.tab_cmd = QWidget()
        tab_cmd_layout = QVBoxLayout()
        
        # Панель быстрых команд
        self.fast_commands_layout = QGridLayout()
        self._create_fast_commands()
        tab_cmd_layout.addLayout(self.fast_commands_layout)
        
        tab_cmd_layout.addWidget(QLabel("Введите команду:"))
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Пример: show interface ont 0/6")
        tab_cmd_layout.addWidget(self.cmd_input)
        
        self.execute_btn = QPushButton("Выполнить")
        self.execute_btn.clicked.connect(self.execute_command)
        tab_cmd_layout.addWidget(self.execute_btn)
        
        self.cmd_output = QTextEdit()
        self.cmd_output.setReadOnly(True)
        self.cmd_output.setPlaceholderText("Здесь будет отображен результат выполнения команды...")
        tab_cmd_layout.addWidget(self.cmd_output)
        
        self.tab_cmd.setLayout(tab_cmd_layout)
        self.tabs.addTab(self.tab_cmd, "Командная строка")
        
        main_layout.addWidget(self.tabs)
        
        # Кнопка разлогинивания
        self.logout_btn = QPushButton("Разлогиниться (Exit)")
        self.logout_btn.clicked.connect(self.logout)
        main_layout.addWidget(self.logout_btn)

        self.setLayout(main_layout)
        
        # Настройка шрифтов для основных рабочих областей
        self.set_fonts()

    def _create_fast_commands(self):
        """Создает кнопки быстрого доступа к командам"""
        # Общие команды
        common_commands = [
            ("show running-config", "show running-config"),
            ("show ont 0-3 offline", "show interface ont 0-3 offline"),
            ("show ont 0-3 unactivated", "show interface ont 0-3 unactivated")
        ]
        
        # Команды для конкретного интерфейса ONT
        ont_commands = [
            ("show ont online", "show interface ont {} online"),
            ("show ont state", "show interface ont {} state"),
            ("show ont offline", "show interface ont {} offline"),
            ("show ont ports", "show interface ont {} ports"),
            ("show mac", "show mac interface ont {}")
        ]
        
        # Добавляем общие команды
        for i, (btn_text, cmd) in enumerate(common_commands):
            btn = QPushButton(btn_text)
            btn.setToolTip(cmd)
            btn.clicked.connect(lambda _, c=cmd: self._set_command(c))
            self.fast_commands_layout.addWidget(btn, 0, i)
        
        # Добавляем команды для интерфейса ONT
        for i, (btn_text, cmd_template) in enumerate(ont_commands):
            btn = QPushButton(btn_text)
            btn.setToolTip(cmd_template)
            btn.clicked.connect(lambda _, t=cmd_template: self._set_ont_command(t))
            self.fast_commands_layout.addWidget(btn, 1, i)

    def _set_command(self, command):
        """Устанавливает команду в поле ввода"""
        self.cmd_input.setText(command)
        self.cmd_output.append(f"> {command}")  # Добавляем команду в историю

    def _set_ont_command(self, command_template):
        """Устанавливает команду для конкретного интерфейса ONT"""
        if self.last_ont_interface:
            command = command_template.format(self.last_ont_interface)
            self.cmd_input.setText(command)
            self.cmd_output.append(f"> {command}")
        else:
            QMessageBox.warning(self, "Ошибка", 
                               "Сначала найдите ONT во вкладке 'Поиск ONT', чтобы определить интерфейс")

    def set_fonts(self):
        """Устанавливает увеличенный шрифт для основных рабочих областей"""
        # Больший шрифт для областей вывода
        output_font = QFont()
        output_font.setPointSize(12)  # Увеличенный размер
        
        # Применяем к областям вывода
        self.search_output.setFont(output_font)
        self.cmd_output.setFont(output_font)
        
        # Больший шрифт для поля ввода команд
        input_font = QFont()
        input_font.setPointSize(11)  # Увеличенный размер для ввода
        
        # Применяем к полям ввода
        self.cmd_input.setFont(input_font)
        self.serial_input.setFont(input_font)  # Также для поля ввода серийника
        
        # Шрифт для кнопок быстрого доступа
        btn_font = QFont()
        btn_font.setPointSize(10)
        for i in range(self.fast_commands_layout.count()):
            widget = self.fast_commands_layout.itemAt(i).widget()
            if isinstance(widget, QPushButton):
                widget.setFont(btn_font)

    def _log_gui(self, message, tab="search"):
        """Вывод сообщения в соответствующую вкладку"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        
        if tab == "search":
            self.search_output.append(formatted)
        elif tab == "cmd":
            self.cmd_output.append(formatted)

    def connect_to_olt(self):
        ip = self.ip_combo.currentText()
        self.current_ip = ip
        self.status_label.setText(f"Статус: Подключение к {ip}...")
        self.search_output.clear()
        self._log_gui(f"Попытка подключения к {ip}...")
        QApplication.processEvents()

        try:
            if self.ssh:
                self.ssh.close()
            self.ssh = SSHClient(ip)
            self.ssh.set_output_area(self.search_output)
            self._log_gui("Соединение установлено")
            self.status_label.setText(f"Статус: OK (Подключено к {ip})")
            self.search_btn.setEnabled(True)
            self.execute_btn.setEnabled(True)
            self.logout_btn.setEnabled(True)
        except Exception as e:
            self.status_label.setText(f"Статус: FAIL - {str(e)}")
            self._log_gui(f"Ошибка подключения: {str(e)}")
            if self.ssh:
                self.ssh.close()
            self.ssh = None
            self.search_btn.setEnabled(False)
            self.execute_btn.setEnabled(False)
            self.logout_btn.setEnabled(False)

    def find_ont_config(self):
        serial = self.serial_input.text().strip()
        if not serial:
            QMessageBox.warning(self, "Ошибка", "Введите серийный номер ONT")
            return
        if not self.ssh:
            QMessageBox.warning(self, "Ошибка", "Сначала подключитесь к OLT")
            return

        try:
            self.search_output.clear()
            self._log_gui("Получение конфигурации...")
            QApplication.processEvents()
            
            # Используем кеширование конфигурации
            if not self.cached_config or self.cached_config_olt != self.current_ip:
                self._log_gui("Загрузка конфигурации OLT...")
                config = self.ssh.send_command("show running-config")
                self.cached_config = config
                self.cached_config_olt = self.current_ip
                self._log_gui(f"Конфигурация загружена и закеширована ({len(config)} символов)")
            else:
                self._log_gui("Используется закешированная конфигурация")

            if "interface ont" not in self.cached_config:
                self._log_gui("Ошибка: не удалось получить конфигурацию оборудования")
                self._log_gui("Попробуйте переподключиться к OLT")
                return

            # Разбивка на блоки конфигурации
            block_pattern = r'(interface\s+ont\s+\d+/\d+\b[\s\S]*?)(?=^interface\s+ont|\Z)'
            blocks = re.findall(block_pattern, self.cached_config, re.MULTILINE | re.IGNORECASE)
            self._log_gui(f"Найдено {len(blocks)} блоков ONT")
            
            # Ищем точное совпадение
            exact_serial = f'serial "{serial}"'
            found = False
            
            for block in blocks:
                if exact_serial in block and "profile ports" in block:
                    cleaned = self.clean_output(block)
                    self.search_output.clear()
                    self._log_gui(f"Найдена конфигурация для {serial}:\n")
                    self._log_gui(cleaned)
                    found = True
                    
                    # Извлекаем интерфейс ONT
                    match = re.search(r'interface\s+ont\s+(\d+/\d+)', block)
                    if match:
                        self.last_ont_interface = match.group(1)
                        self._log_gui(f"Установлен последний интерфейс ONT: {self.last_ont_interface}")
                    break
            
            if not found:
                self._log_gui(f"\nКонфигурация для {serial} не найдена!")
                # Поиск частичных совпадений
                result_blocks = []
                for block in blocks:
                    if re.search(f'serial ".*{re.escape(serial)}.*"', block) and "profile ports" in block:
                        result_blocks.append(block)
                
                if result_blocks:
                    self._log_gui("\nВозможные совпадения:")
                    for block in result_blocks:
                        self._log_gui(self.clean_output(block) + "\n")
                else:
                    self._log_gui("\nСовпадений не найдено")
                    
        except Exception as e:
            self._log_gui(f"\nОшибка: {str(e)}")
            logging.exception("Ошибка при поиске конфигурации ONT")

    def clean_output(self, text):
        """Очищает escape-символы и лишние символы"""
        if not text:
            return ""
        # Удаление управляющих последовательностей
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        # Удаление возвратов каретки
        text = re.sub(r'\r\n?', '\n', text)
        # Удаление лишних пробелов
        text = re.sub(r'\n\s+\n', '\n\n', text)
        return text.strip()

    def execute_command(self):
        """Выполняет произвольную команду на OLT"""
        if not self.ssh:
            QMessageBox.warning(self, "Ошибка", "Сначала подключитесь к OLT")
            return
            
        command = self.cmd_input.text().strip()
        if not command:
            QMessageBox.warning(self, "Ошибка", "Введите команду")
            return
            
        try:
            self.cmd_output.append(f"> {command}")
            response = self.ssh.send_command(command)
            cleaned = self.clean_output(response)
            self.cmd_output.append(cleaned)
        except Exception as e:
            self.cmd_output.append(f"Ошибка: {str(e)}")

    def logout(self):
        """Разлогинивается с OLT"""
        if self.ssh:
            try:
                self.ssh.logout()
                self.status_label.setText("Статус: Не подключено")
                self._log_gui("Выполнен выход с OLT", "search")
                self._log_gui("Выполнен выход с OLT", "cmd")
            except Exception as e:
                self._log_gui(f"Ошибка при выходе: {str(e)}", "search")
            
            self.search_btn.setEnabled(False)
            self.execute_btn.setEnabled(False)
            self.ssh = None

    def closeEvent(self, event):
        if self.ssh:
            self.ssh.close()
        event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = OLTApp()
    ex.show()
    sys.exit(app.exec_())
