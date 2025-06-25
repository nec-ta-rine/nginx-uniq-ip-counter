import paramiko
import logging
import requests
from datetime import datetime
from dateutil.parser import parse
from collections import defaultdict
import time
import os

# Конфигурация логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Конфигурация
REMOTE_HOST = os.environ.get('REMOTE_HOST')  # адрес удаленного хоста
REMOTE_USER = os.environ.get('REMOTE_USER')      # имя пользователя
PRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH')  # Путь к приватному ключу, убедиться, что права 600 и владелец root, чтобы внутри контейнера тоже был root
LOG_FILE_PATH = os.environ.get('LOG_FILE_PATH')  # Путь к файлу логов Nginx
PUSHGATEWAY_URL = os.environ.get('PUSHGATEWAY_URL') # URL pushgateway

# Список IP-адресов для исключения
EXCLUDED_IPS = {'<ip>', '<ip>'}  # адреса, которые нужно игнорировать, чтобы не учитывать в статистике, например

# выражение (URL или его часть) для фильтрации, тот случай, когда nginx проксирует несколько сайтов, но нужны посетители конкретных
FILTER_URL = os.environ.get('FILTER_URL')

# Путь к файлу для хранения позиции
POSITION_FILE_PATH = 'position.txt'

def get_last_position():
    # Получить последнюю позицию из файла.
    if os.path.exists(POSITION_FILE_PATH):
            try:
                with open(POSITION_FILE_PATH, 'r') as pos_file:
                    position = pos_file.read().strip()
                    return int(position) if position.isdigit() else 0  # Возвращаем 0, если содержимое не является числом
            except (IOError, ValueError) as e:
                logging.error(f"Ошибка при чтении позиции из файла: {e}")
                return 0  # Возвращаем 0 в случае ошибки
    return 0  # Возвращаем 0, если файл не найден

def save_last_position(position):
    try:
        # Сохранить текущую позицию в файл.
        with open(POSITION_FILE_PATH, 'w') as pos_file:
            pos_file.write(str(position))
    except Exception as e:
        logging.error(f"Ошибка при сохранении позиции: {e}")


def get_unique_ips_per_minute():
    unique_ips = defaultdict(set)
            
    # Подключение к удаленному хосту по SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Загружаем приватный ключ
    private_key = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_PATH)

    # Подключаемся с использованием ключа
    try:
        ssh.connect(REMOTE_HOST, username=REMOTE_USER, pkey=private_key)
        logging.info(f"Успешное подключение по SSH к {REMOTE_HOST} как {REMOTE_USER}.")
    except Exception as e:
        logging.error(f"Ошибка при подключении по SSH к {REMOTE_HOST}: {e}")
        return unique_ips  # Возвращаем пустой словарь, если подключение не удалось

    # Чтение логов Nginx
    with ssh.open_sftp() as sftp:
        try:
            logging.info("Подключение к SFTP установлено.")
            log_file = sftp.file(LOG_FILE_PATH, 'r')
            last_position = get_last_position() # Получаем последнюю позицию

            logging.info(f"Последняя позиция: {last_position}")

            # Проверяем, не изменился ли файл (например, по размеру)
            current_size = log_file.stat().st_size
            logging.info(f"Текущий размер файла: {current_size}")

            if last_position > current_size:
                # Если последняя позиция больше текущего размера файла,
                # это значит, что файл был ротирован. Сбрасываем позицию.
                logging.warning("Файл был ротирован. Сбрасываем позицию.")
                last_position = 0

            log_file.seek(last_position)  # Устанавливаем позицию чтения

            for line in log_file:
                try:
                    logging.debug(f"Обработка строки: {line.strip()}")
                    # Предполагаем, что формат строки лога:
                    # <ip> - - [<date>] "<request>" <status> <size> "referer"
                    # Разбиваем строку по пробелам для извлечения основных частей
                    parts = line.split('"')
                    if len(parts) < 5: # Проверяем минимальное количество частей
                        logging.debug("Пропускаем строку из-за неверного формата.")
                        continue  # Если строка не содержит ожидаемого формата, пропускаем

                    initial_parts = parts[0].split() # Разбиваем начальную часть по пробелам
                    ip_address = initial_parts[0]  # Извлекаем IP-адрес
                    date_str = initial_parts[3].lstrip('[').rstrip(']')  # Извлекаем дату
                    referer = parts[3].strip()  # Извлекаем referer из предпоследнего элемента

                    timestamp = parse(date_str, fuzzy=True) # Используем dateutil.parser.parse
                   # timestamp = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S %z')

                    logging.debug(f"IP: {ip_address}, Дата: {timestamp}, Referer: {referer}")

                    # Проверяем, не находится ли IP в списке исключений и соответствует ли referer
                    if ip_address not in EXCLUDED_IPS and FILTER_URL in referer:
                      # Группируем IP по минутам
                      minute_key = timestamp.replace(second=0, microsecond=0)
                      unique_ips[minute_key].add(ip_address)
                      logging.info(f"Уникальный IP добавлен: {ip_address} для минуты {minute_key}")
                except Exception as e:
                    logging.error(f"Ошибка при обработке строки: {line}. Ошибка: {e}")

            # Сохраняем текущую позицию после завершения чтения
            save_last_position(log_file.tell())
            logging.info(f"Новая позиция сохранена: {log_file.tell()}")

        except FileNotFoundError:
            logging.error(f"Файл {LOG_FILE_PATH} не найден.")
        except Exception as e:
            logging.error(f"Ошибка при работе с SFTP: {e}")

    ssh.close()
    logging.info("Соединение SFTP закрыто.")

    result = {minute: len(ips) for minute, ips in unique_ips.items()}

    # Логируем результат перед возвратом
    logging.info(f"Уникальные IP-адреса за минуту: {result}")

    return result

def push_metrics_to_pushgateway(unique_ips):
    # Формируем данные для отправки
    data = ""

    if not unique_ips:
        # Отправляем метрику с нулевым значением, если нет данных
        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S') # Текущее время UTC
        data = f'nginx_unique_ips{{minute="{now}"}} 0\n'
        logging.warning("Нет данных из логов, отправлена нулевая метрика.")
    else:
        for minute, count in unique_ips.items():
            # Преобразуем время в строку в формате, который понимает Prometheus
            minute_str = minute.strftime('%Y-%m-%dT%H:%M:%S')
            data += f'nginx_unique_ips{{minute="{minute_str}"}} {count}\n'

    # Отправляем данные в Pushgateway
    try:
        response = requests.put(f'{PUSHGATEWAY_URL}/metrics/job/nginx_unique_ips', data=data)
        if response.status_code == 200:
            logging.info("Метрики успешно отправлены в Pushgateway.")
        else:
            logging.error(f"Ошибка при отправке метрик в Pushgateway: {response.status_code} {response.text}")
    except Exception as e:
        logging.error(f"Ошибка при выполнении запроса к Pushgateway: {e}")

if __name__ == '__main__':
    while True:
        unique_ips_per_minute = get_unique_ips_per_minute() # Получаем уникальные IP-адреса
        push_metrics_to_pushgateway(unique_ips_per_minute)
        time.sleep(60)  # Ждем минуту перед следующей итерацией

