# OSINT Telegram Bot — Maigret + SpiderFoot

Telegram-бот для работы с открытыми источниками:

- **Maigret 0.6.5** — поиск публичных профилей по username.
- **SpiderFoot 4.0** — сбор открытой информации по доменам, IP и другим разрешённым целям.

## Команды

- `/start` — справка
- `/username example` — поиск публичных профилей через Maigret
- `/scan example.com` — запуск SpiderFoot
- `/cancel` — остановить свой текущий процесс

## Переменные окружения

Обязательно:

```env
BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
```

Рекомендуется ограничить доступ к боту:

```env
ALLOWED_USER_IDS=123456789,987654321
```

Дополнительно:

```env
MAX_CONCURRENT_SCANS=1
SCAN_TIMEOUT_SECONDS=300
RATE_LIMIT_SECONDS=30
REPORT_TTL_HOURS=24
```

## Запуск через Docker

```bash
docker build -t osint-telegram-bot .
docker run --rm \
  -e BOT_TOKEN="YOUR_TOKEN" \
  -e ALLOWED_USER_IDS="YOUR_TELEGRAM_ID" \
  osint-telegram-bot
```

Во время сборки Docker устанавливает Maigret 0.6.5 из PyPI и загружает официальный SpiderFoot 4.0 с GitHub. Они устанавливаются в отдельные virtualenv, потому что их зависимости конфликтуют.

## Amvera

В корне уже есть `Dockerfile`, поэтому проект можно подключить к Amvera как Git-репозиторий и выбрать Docker-сборку. После подключения добавь `BOT_TOKEN` и, желательно, `ALLOWED_USER_IDS` в переменные окружения приложения.

Боту не нужен веб-порт: он работает через Telegram long polling. Для длительного хранения отчётов можно подключить постоянное хранилище; по умолчанию локальные отчёты старше `REPORT_TTL_HOURS` удаляются при запуске.

## Безопасность

- токен не хранится в репозитории;
- команды запускаются без shell-интерпретации;
- ввод username/target валидируется;
- loopback/private/link-local/reserved IP-адреса отклоняются;
- есть ограничение частоты запусков и параллелизма;
- пользователь может остановить только свой текущий процесс.

Используй инструмент только для открытых данных и целей, которые тебе разрешено проверять.
