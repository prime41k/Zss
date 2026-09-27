# ZSS Zero State Snapshot v4

Локальный версионатор файлов для Termux Linux macOS
Один файл zss.py без зависимостей кроме стандартной библиотеки Python
Хранит историю изменений текстовых файлов откатывает сравнивает чистит старьё
Никакого Git никаких серверов никаких pip install

Зачем это нужно

Писалось под задачу откатывать изменения в py файлах прямо с телефона
Git избыточен когда нужен один снапшот перед правкой
ZSS делает одно действие track и даёт инструменты работы с историей
Работает на Android Termux Linux macOS
На Windows не работает из за fcntl

Установка

Кинь zss.py в проект
Всё
Никаких requirements.txt

Быстрый старт

import zss

with zss.create_timemachine() as tm
    stats = tm.track()
    print(f"Проверено {stats.checked} сохранено {stats.saved}")

    history = tm.history("main.py" limit=5)
    for entry in history
        print(entry["timestamp"] entry["size"] entry["hash"][:8])

    try
        tm.rollback("main.py" "before_refactor")
    except zss.RollbackError as e
        print(f"Откат не удался {e}")

    tm.add_tag("main.py" history[-1]["timestamp"] "stable")

    for line in tm.diff("main.py" "2026-09-01_14-00-00_000000" "2026-09-01_14-23-45_123456")
        print(line end="")

    tm.clean("main.py" keep=50)
    tm.purge_missing()
    print(tm.get_stats())

Архитектура v4

LRUCache
Потокобезопасный кэш индексов на OrderedDict с RLock
Двойная валидация TTL плюс mtime файла
move_to_end вместо pop next iter

FileLock
Обёртка над fcntl flock
Два режима exclusive для записи shared для чтения
FD создаётся внутри контекстного менеджера а не хранится в self
Безопасно для многопоточности

IndexManager
Управляет JSON индексами версии 4
stage_save откладывает запись flush пишет пачкой в конце track
Автоматическая миграция индексов v1 v2 v3
save_now для немедленной записи при rollback и add_tag

VersionStore
Хранит снапшоты с расширением ztxt или txt
Streaming hash через BLAKE2b чанками по 64KB
Генератор read_version_lines для diff без загрузки в память
Lazy decompression пробует оба расширения

TimeMachine
Координирует все компоненты
Context manager с автоматическим flush при выходе
Обработка SIGTERM SIGINT для корректного завершения
Shared lock для чтения exclusive для записи

API

create_timemachine(root extensions keep_default cache_ttl max_cache_size compress block_on_secrets)
Создаёт экземпляр TimeMachine
root куда складывать данные по умолчанию zss_data
extensions какие файлы отслеживать по умолчанию py
keep_default сколько версий хранить при чистке по умолчанию 100
cache_ttl время жизни кэша в секундах по умолчанию 1.0
max_cache_size максимум индексов в LRU по умолчанию 128
compress сжимать ли версии через zlib по умолчанию True
block_on_secrets блокировать сохранение при обнаружении секретов по умолчанию False

track(paths=None)
Сканирует файлы сохраняет изменённые
Batch save индексов один flush на всю пачку
Возвращает TrackStats(checked saved errors) как NamedTuple
Берёт exclusive lock один раз на все файлы

history(filename limit=10)
Возвращает список последних версий файла
Использует shared lock для параллельного чтения
Каждая запись VersionEntry TypedDict с timestamp hash size compressed lines path tags

add_tag(filename timestamp tag)
Привязывает имя к версии
Немедленная запись индекса через save_now
Raises ZSSError если timestamp не найден

rollback(filename target)
Атомарный откат к версии по timestamp или тегу
Бэкап текущего состояния перед перезаписью
Восстанавливает из бэкапа если запись упала
Raises RollbackError при неудаче вместо возврата строки

diff(filename ts1 ts2)
Unified diff между двумя версиями
Генератор строк без загрузки файлов в память
Читает версии построчно через read_version_lines

clean(filename keep=None max_age_minutes=60)
Удаляет старые версии оставляет последние keep
Чистит tmp файлы старше max_age_minutes
Возвращает dict с versions_deleted tmp_cleaned kept

purge_missing(known_files=None)
Удаляет индексы и версии для удалённых файлов
Если known_files None сам сканирует дерево
Возвращает dict с deleted orphaned_indices

get_stats()
Статистика хранилища
Возвращает dict с tracked saved rollbacks errors total_versions total_size_mb

Производительность

Тест на проекте 500 py файлов 2MB кода
Первый track 1.2 секунды создание индексов
Повторный track без изменений 0.25 секунды кэш плюс streaming hash
Track с 10 изменёнными файлами 0.35 секунды batch save
Diff больших файлов константная память благодаря генераторам
Shared lock позволяет читать историю параллельно с трекингом

Ограничения

Только текстовые файлы
Бинарники определяются по нулевому байту в первых 8KB
UTF 16 с BOM определяется без BOM нет

Нет инкрементального хранения
Каждая версия полная копия файла
Delta storage не реализован

Нет ветвления
Только линейная история
Branch merge cherry pick нет

Нет сетевого режима
Только локальная файловая система
NFS SMB облака не тестированы

Timestamp с микросекундами
При сохранении чаще 10 раз в секунду возможны коллизии
На практике не встречал но теоретически возможно

Примеры использования

Бэкап перед рефакторингом

import zss

with zss.create_timemachine() as tm
    tm.track()
    h = tm.history("main.py" limit=1)
    if h
        tm.add_tag("main.py" h[0]["timestamp"] "before_refactor")

    try
        tm.rollback("main.py" "before_refactor")
    except zss.RollbackError as e
        print(f"Не удалось откатить {e}")

Отслеживание в реальном времени

import zss
import time

with zss.create_timemachine() as tm
    while True
        stats = tm.track()
        if stats.saved > 0
            print(f"Сохранено {stats.saved} изменений")
        time.sleep(5)

Поиск когда появилась функция

import zss

with zss.create_timemachine() as tm
    for entry in tm.history("main.py" limit=100)
        for line in tm._store.read_version_lines(
            __import__("pathlib").Path("main.py").resolve()
            entry["timestamp"]
        )
            if "def new_feature" in line
                print(f"Функция появилась в {entry['timestamp']}")
                break

Очистка хлама

import zss
from pathlib import Path

with zss.create_timemachine() as tm
    for py_file in Path(".").rglob("*.py")
        tm.clean(str(py_file) keep=20)
    result = tm.purge_missing()
    print(f"Удалено {result['deleted']} объектов")
    print(tm.get_stats())

Known issues

KeyboardInterrupt внутри track
Лок освободится корректно через контекстный менеджер
Может остаться tmp файл чистится при следующем clean

Символические ссылки игнорируются
Сделано намеренно чтобы не ходить по круговым ссылкам

Права доступа
Нет прав на чтение файл пропускается
Нет прав на запись в хранилище исключение

Повреждённые индексы
Создаётся новый с нуля
Старые версии остаются но теряется связь
Миграция v1 v2 v3 автоматическая

FAQ

Почему не Git
Git требует инициализации staging коммитов
ZSS делает одно действие track

Почему не cp file file.bak
Неудобно искать версию нет истории нет diff нет автоочистки

Можно ли использовать с другими языками
Да параметр extensions настраивается
js ts go rs что угодно текстовое

Что если файл удалён
ZSS не заметит индекс и версии останутся
Вызови purge_missing для очистки

Что если два процесса работают одновременно
Запись синхронизируется exclusive lock
Чтение параллельное через shared lock

Можно ли зашифровать версии
Нет делай на уровне файловой системы fscrypt ecryptfs

Почему BLAKE2b а не SHA256
BLAKE2b быстрее в 3 5 раз на больших файлах
Для версионирования коллизии не критичны

Changelog

v4.0 текущая
Breaking change rollback рейзит RollbackError вместо возврата строки
Breaking change INDEX_VERSION повышен до 4 автоматическая миграция
Потокобезопасный LRU на OrderedDict с RLock
Shared lock для чтения history diff get_stats
Streaming hash BLAKE2b чанками 64KB
Streaming diff через генератор без загрузки в память
Batch save индексов stage_save плюс flush
Context manager с авто flush
Обработка SIGTERM SIGINT
Типизация TypedDict NamedTuple
Валидация timestamp через datetime.strptime
Бэкап перед rollback с восстановлением при ошибке

v3.0
Сжатие zlib теги детекция секретов
Микросекунды в timestamp генераторы в diff
Один лок на пачку файлов в track

v2.0
Модульная архитектура миграция индексов v1 v2
Атомарная запись через os.replace

v1.0
Первый релиз базовое версионирование кэш локи

Лицензия

Делай что хочешь
Код написан для личных нужд если пригодился рад
Никаких гарантий если сломает данные сам виноват

Контакты

Не пиши
Нашёл баг чини сам код открытый
Не можешь починить значит не твой уровень
