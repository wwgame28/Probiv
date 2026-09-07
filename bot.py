import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import FSInputFile, LabeledPrice, Message, PreCheckoutQuery

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
OUT = DATA / "reports"
DB_PATH = DATA / "payments.sqlite3"
OUT.mkdir(parents=True, exist_ok=True)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(x.strip()) for x in os.getenv("ADMIN_IDS", "8196658213").split(",")
    if x.strip().isdigit()
}
ALLOWED_USER_IDS = {
    int(x.strip()) for x in os.getenv("ALLOWED_USER_IDS", "").split(",")
    if x.strip().isdigit()
}
MAX_CONCURRENT = max(1, int(os.getenv("MAX_CONCURRENT_SCANS", "1")))
TIMEOUT = max(30, int(os.getenv("SCAN_TIMEOUT_SECONDS", "300")))
RATE_LIMIT = max(0, int(os.getenv("RATE_LIMIT_SECONDS", "30")))
REPORT_TTL_HOURS = max(1, int(os.getenv("REPORT_TTL_HOURS", "24")))
PRICE_STARS = max(1, int(os.getenv("PRICE_STARS", "50")))
MAX_GIFT_CREDITS = max(1, int(os.getenv("MAX_GIFT_CREDITS", "1000")))
SUPPORT_TEXT = os.getenv(
    "SUPPORT_TEXT",
    "По вопросам оплаты и работы бота обратитесь к владельцу бота.",
).strip()

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("osint-bot")

dp = Dispatcher()
sem = asyncio.Semaphore(MAX_CONCURRENT)
last_run: dict[int, float] = {}
running: dict[int, asyncio.subprocess.Process] = {}
active_users: set[int] = set()
pending_input: dict[int, str] = {}

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{2,64}")
TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,253}")
ORDER_TTL_SECONDS = 24 * 3600


def db_connect() -> sqlite3.Connection:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    with db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                argument TEXT NOT NULL,
                amount INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                paid_at INTEGER,
                fulfilled_at INTEGER,
                telegram_payment_charge_id TEXT UNIQUE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                free_credits INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_orders_user_status "
            "ON orders(user_id, status, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_username "
            "ON users(username COLLATE NOCASE)"
        )


def register_user(user) -> None:
    if not user:
        return
    now = int(time.time())
    username = (user.username or "").strip().lstrip("@").lower() or None
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO users (user_id, username, free_credits, created_at, updated_at)
            VALUES (?, ?, 0, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                updated_at = excluded.updated_at
            """,
            (user.id, username, now, now),
        )


def get_credits(user_id: int) -> int:
    with db_connect() as conn:
        row = conn.execute(
            "SELECT free_credits FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return int(row["free_credits"]) if row else 0


def consume_credit(user_id: int) -> bool:
    with db_connect() as conn:
        cur = conn.execute(
            """
            UPDATE users
            SET free_credits = free_credits - 1, updated_at = ?
            WHERE user_id = ? AND free_credits > 0
            """,
            (int(time.time()), user_id),
        )
    return cur.rowcount == 1


def refund_credit(user_id: int) -> None:
    with db_connect() as conn:
        conn.execute(
            """
            UPDATE users
            SET free_credits = free_credits + 1, updated_at = ?
            WHERE user_id = ?
            """,
            (int(time.time()), user_id),
        )


def add_credits_by_username(username: str, amount: int):
    normalized = username.strip().lstrip("@").lower()
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT user_id, username, free_credits
            FROM users
            WHERE username = ? COLLATE NOCASE
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (normalized,),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """
            UPDATE users
            SET free_credits = free_credits + ?, updated_at = ?
            WHERE user_id = ?
            """,
            (amount, int(time.time()), row["user_id"]),
        )
        return {
            "user_id": row["user_id"],
            "username": row["username"],
            "credits": int(row["free_credits"]) + amount,
        }


def admin_stats() -> dict[str, int]:
    with db_connect() as conn:
        users = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        paid = conn.execute(
            "SELECT COUNT(*) AS n FROM orders WHERE status IN ('paid','fulfilled')"
        ).fetchone()["n"]
        fulfilled = conn.execute(
            "SELECT COUNT(*) AS n FROM orders WHERE status = 'fulfilled'"
        ).fetchone()["n"]
    return {"users": int(users), "paid": int(paid), "fulfilled": int(fulfilled)}


def create_order(user_id: int, chat_id: int, command: str, argument: str) -> str:
    order_id = uuid.uuid4().hex
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO orders (
                order_id, user_id, chat_id, command, argument,
                amount, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (order_id, user_id, chat_id, command, argument, PRICE_STARS, int(time.time())),
        )
    return order_id


def get_order(order_id: str):
    with db_connect() as conn:
        return conn.execute(
            "SELECT * FROM orders WHERE order_id = ?",
            (order_id,),
        ).fetchone()


def mark_order_paid(order_id: str, charge_id: str) -> bool:
    with db_connect() as conn:
        try:
            cur = conn.execute(
                """
                UPDATE orders
                SET status = 'paid', paid_at = ?, telegram_payment_charge_id = ?
                WHERE order_id = ? AND status = 'pending'
                """,
                (int(time.time()), charge_id, order_id),
            )
        except sqlite3.IntegrityError:
            return False
    return cur.rowcount == 1


def mark_order_fulfilled(order_id: str) -> None:
    with db_connect() as conn:
        conn.execute(
            """
            UPDATE orders
            SET status = 'fulfilled', fulfilled_at = ?
            WHERE order_id = ? AND status = 'paid'
            """,
            (int(time.time()), order_id),
        )


def latest_paid_order(user_id: int):
    with db_connect() as conn:
        return conn.execute(
            """
            SELECT * FROM orders
            WHERE user_id = ? AND status = 'paid'
            ORDER BY paid_at DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()


def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


def allowed(message: Message) -> bool:
    if not message.from_user:
        return False
    return (
        is_admin(message.from_user.id)
        or not ALLOWED_USER_IDS
        or message.from_user.id in ALLOWED_USER_IDS
    )


def normalize_username(value: str) -> str:
    return value.strip().lstrip("@")


def valid_username(value: str) -> bool:
    return bool(USERNAME_RE.fullmatch(normalize_username(value)))


def valid_target(value: str) -> bool:
    if not TARGET_RE.fullmatch(value):
        return False

    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host or host == "localhost" or host.endswith(".localhost"):
        return False

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True

    return not is_unsafe_ip(ip)


def is_unsafe_ip(ip) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


async def target_resolves_public(value: str) -> bool:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if not host:
        return False
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
    except socket.gaierror:
        return False

    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    for address in addresses:
        try:
            if is_unsafe_ip(ipaddress.ip_address(address)):
                return False
        except ValueError:
            return False
    return True


def rate_ok(uid: int) -> bool:
    now = time.monotonic()
    if now - last_run.get(uid, 0) < RATE_LIMIT:
        return False
    last_run[uid] = now
    return True


def cleanup_reports() -> None:
    cutoff = time.time() - REPORT_TTL_HOURS * 3600
    for path in OUT.iterdir():
        try:
            if path.stat().st_mtime < cutoff:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
        except OSError:
            log.exception("Failed to cleanup report path: %s", path)


async def cleanup_loop() -> None:
    while True:
        try:
            cleanup_reports()
        except Exception:
            log.exception("Periodic report cleanup failed")
        await asyncio.sleep(3600)


async def run_cmd(args: list[str], cwd: Path, uid: int, timeout: int = TIMEOUT):
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    running[uid] = proc
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, out.decode("utf-8", "replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "Время выполнения истекло."
    except asyncio.CancelledError:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise
    finally:
        running.pop(uid, None)


async def send_output(message: Message, text: str) -> None:
    safe = html.escape(text[-3500:] if text else "Нет вывода.")
    await message.answer(f"<pre>{safe}</pre>", parse_mode="HTML")


async def send_payment_invoice(
    message: Message,
    bot: Bot,
    command: str,
    argument: str,
) -> None:
    uid = message.from_user.id
    if not rate_ok(uid):
        await message.answer("Подожди немного перед созданием следующего счёта.")
        return

    order_id = create_order(uid, message.chat.id, command, argument)
    label = "Поиск username" if command == "username" else "OSINT-сканирование"

    await bot.send_invoice(
        chat_id=message.chat.id,
        title="OSINT-запрос",
        description=f"{label}: {argument}. После оплаты запрос запустится автоматически.",
        payload=f"osint:{order_id}",
        currency="XTR",
        prices=[LabeledPrice(label="1 OSINT-запрос", amount=PRICE_STARS)],
        provider_token="",
        start_parameter=f"osint_{order_id[:12]}",
    )


async def execute_username(message: Message, username: str, access_label: str) -> bool:
    uid = message.from_user.id
    job = OUT / f"maigret_{uid}_{int(time.time())}"
    job.mkdir(parents=True, exist_ok=True)

    await message.answer(
        f"{access_label} Ищу публичные профили для "
        f"<code>{html.escape(username)}</code>.",
        parse_mode="HTML",
    )

    async with sem:
        code, output = await run_cmd(
            [
                str(ROOT / "runtime" / "maigret" / "bin" / "python"),
                "-m", "maigret", username,
                "--no-progressbar", "--no-color",
                "--folderoutput", str(job), "--html",
            ],
            ROOT,
            uid,
        )

    reports = list(job.glob("*.html"))
    if code == 0 and reports:
        report = max(reports, key=lambda x: x.stat().st_mtime)
        await message.answer_document(
            FSInputFile(report),
            caption=f"Maigret: {username}",
        )
        return True

    await message.answer(f"Maigret не смог завершить запрос, код {code}.")
    await send_output(message, output)
    return False


async def execute_scan(message: Message, target: str, access_label: str) -> bool:
    uid = message.from_user.id

    if not await target_resolves_public(target):
        await message.answer(
            "Цель не разрешается в публичный IP-адрес или указывает на локальную/служебную сеть."
        )
        return False

    job = OUT / f"spiderfoot_{uid}_{int(time.time())}"
    job.mkdir(parents=True, exist_ok=True)

    await message.answer(
        f"{access_label} SpiderFoot запускает сбор открытых данных для "
        f"<code>{html.escape(target)}</code>.\nЭто может занять несколько минут.",
        parse_mode="HTML",
    )

    async with sem:
        code, output = await run_cmd(
            [
                str(ROOT / "runtime" / "spiderfoot" / "bin" / "python"),
                "sf.py",
                "-s", target,
                "-u", "investigate",
                "-o", "json",
                "-q",
            ],
            ROOT / "vendor" / "spiderfoot",
            uid,
        )

    raw_path = job / "result.txt"
    raw_path.write_text(output or "", encoding="utf-8")

    if code != 0:
        await message.answer(f"SpiderFoot завершил работу с кодом {code}.")
        await send_output(message, output)
        return False

    try:
        parsed = json.loads(output or "[]")
    except json.JSONDecodeError:
        await message.answer(
            "SpiderFoot завершился, но вернул некорректный JSON. Отправляю сырой отчёт для диагностики."
        )
        await message.answer_document(FSInputFile(raw_path), caption=f"SpiderFoot raw: {target}")
        return False

    json_path = job / "result.json"
    json_path.write_text(
        json.dumps(parsed, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    await message.answer_document(
        FSInputFile(json_path),
        caption=f"SpiderFoot: {target}",
    )
    return True


async def execute_request(message: Message, command: str, argument: str, access_label: str) -> bool:
    uid = message.from_user.id
    if uid in active_users:
        await message.answer("У тебя уже выполняется запрос. Дождись завершения или используй /cancel.")
        return False

    active_users.add(uid)
    try:
        if command == "username":
            return await execute_username(message, argument, access_label)
        if command == "scan":
            return await execute_scan(message, argument, access_label)
        await message.answer("Неизвестный тип запроса.")
        return False
    finally:
        active_users.discard(uid)


async def handle_request(message: Message, bot: Bot, command: str, argument: str) -> None:
    register_user(message.from_user)
    uid = message.from_user.id

    if uid in active_users:
        await message.answer("У тебя уже выполняется запрос. Дождись завершения или используй /cancel.")
        return

    if command == "username":
        argument = normalize_username(argument)
        if not valid_username(argument):
            await message.answer("Username должен содержать 2–64 символа: буквы, цифры, точку, _ или -.")
            return
    elif command == "scan":
        argument = argument.strip()
        if not valid_target(argument):
            await message.answer("Некорректная цель. Пример: example.com или 8.8.8.8")
            return

    if is_admin(uid):
        await execute_request(message, command, argument, "Администратор: запрос бесплатный.")
        return

    if consume_credit(uid):
        ok = await execute_request(message, command, argument, "Использован бесплатный запрос.")
        if not ok:
            refund_credit(uid)
            await message.answer("Запрос не выполнен, бесплатный запрос возвращён на баланс.")
        return

    await send_payment_invoice(message, bot, command, argument)


async def fulfill_order(message: Message, order) -> bool:
    return await execute_request(
        message,
        order["command"],
        order["argument"],
        "Оплата подтверждена.",
    )


@dp.message(CommandStart())
async def start(message: Message):
    if not allowed(message):
        return
    register_user(message.from_user)
    uid = message.from_user.id
    credits = get_credits(uid)
    admin_line = "\nСтатус: администратор, запросы бесплатны.\n" if is_admin(uid) else ""
    await message.answer(
        "OSINT Bot\n\n"
        f"Стоимость одного платного запроса: {PRICE_STARS} ⭐ Telegram Stars."
        f"{admin_line}\n"
        f"Бесплатных запросов на балансе: {credits}\n\n"
        "/username — поиск публичных профилей по username\n"
        "/scan — сбор открытых данных по домену/IP\n"
        "/balance — баланс бесплатных запросов\n"
        "/retry — повторить оплаченный незавершённый запрос\n"
        "/cancel — остановить текущий запуск\n"
        "/terms — условия оплаты\n"
        "/support — поддержка\n"
        "/help — справка\n\n"
        "Можно писать сразу: /username Rumbo4ka или /scan example.com.\n"
        "Если отправить команду без аргумента, бот попросит данные следующим сообщением.\n\n"
        "Используй только открытые данные и цели, которые тебе разрешено проверять."
    )


@dp.message(Command("help"))
async def help_cmd(message: Message):
    await start(message)


@dp.message(Command("balance"))
async def balance_cmd(message: Message):
    if not allowed(message):
        return
    register_user(message.from_user)
    if is_admin(message.from_user.id):
        await message.answer("Ты администратор. Для тебя запросы бесплатны без ограничений.")
    else:
        await message.answer(
            f"Бесплатных запросов: {get_credits(message.from_user.id)}\n"
            f"После их окончания один запрос стоит {PRICE_STARS} ⭐."
        )


@dp.message(Command("terms"))
async def terms_cmd(message: Message):
    if not allowed(message):
        return
    register_user(message.from_user)
    await message.answer(
        "Условия оплаты\n\n"
        f"• 1 платный запрос стоит {PRICE_STARS} ⭐ Telegram Stars.\n"
        "• Если на балансе есть бесплатные запросы, сначала расходуются они.\n"
        "• Для администраторов запросы бесплатны.\n"
        "• Оплата считается подтверждённой только после successful_payment от Telegram.\n"
        "• Если оплаченный запрос не завершился, /retry запускает его без новой оплаты.\n"
        "• Используйте сервис только для открытых данных и разрешённых целей."
    )


@dp.message(Command("support"))
async def support_cmd(message: Message):
    if not allowed(message):
        return
    register_user(message.from_user)
    await message.answer(SUPPORT_TEXT)


@dp.message(Command("admin"))
async def admin_cmd(message: Message):
    if not allowed(message) or not is_admin(message.from_user.id):
        return
    register_user(message.from_user)
    stats = admin_stats()
    await message.answer(
        "Админ-панель\n\n"
        "/give @username 5 — выдать бесплатные запросы\n"
        "/balance — твой статус\n\n"
        f"Пользователей: {stats['users']}\n"
        f"Оплаченных заказов: {stats['paid']}\n"
        f"Успешно выполненных: {stats['fulfilled']}"
    )


@dp.message(Command("give"))
async def give_cmd(message: Message):
    if not allowed(message) or not is_admin(message.from_user.id):
        return
    register_user(message.from_user)
    parts = (message.text or "").split()
    if len(parts) != 3:
        await message.answer("Формат: /give @username 5")
        return

    username = parts[1].strip()
    try:
        amount = int(parts[2])
    except ValueError:
        await message.answer("Количество запросов должно быть целым числом.")
        return

    if amount < 1 or amount > MAX_GIFT_CREDITS:
        await message.answer(f"Можно выдать от 1 до {MAX_GIFT_CREDITS} запросов за одну команду.")
        return

    result = add_credits_by_username(username, amount)
    if not result:
        await message.answer(
            "Пользователь не найден. Он должен хотя бы один раз открыть бота и отправить /start."
        )
        return

    await message.answer(
        f"Выдано {amount} бесплатных запросов пользователю @{result['username']}.\n"
        f"Теперь на балансе: {result['credits']}."
    )


@dp.message(Command("cancel"))
async def cancel_cmd(message: Message):
    if not allowed(message):
        return
    register_user(message.from_user)
    uid = message.from_user.id
    pending_input.pop(uid, None)
    proc = running.get(uid)
    if not proc:
        if uid in active_users:
            await message.answer("Запрос ожидает запуска. Подожди немного.")
        else:
            await message.answer("У тебя сейчас нет активного запроса.")
        return
    if proc.returncode is None:
        proc.kill()
        await message.answer(
            "Остановил текущий процесс. Оплаченный запрос останется доступен через /retry."
        )
    else:
        await message.answer("Процесс уже завершился.")


@dp.message(Command("username"))
async def username_cmd(message: Message, bot: Bot):
    if not allowed(message):
        return
    register_user(message.from_user)
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) == 1:
        pending_input[message.from_user.id] = "username"
        await message.answer("Отправь username следующим сообщением. Можно с @, например @Rumbo4ka.")
        return
    await handle_request(message, bot, "username", parts[1])


@dp.message(Command("scan"))
async def scan_cmd(message: Message, bot: Bot):
    if not allowed(message):
        return
    register_user(message.from_user)
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) == 1:
        pending_input[message.from_user.id] = "scan"
        await message.answer("Отправь домен или публичный IP следующим сообщением, например example.com.")
        return
    await handle_request(message, bot, "scan", parts[1])


@dp.pre_checkout_query()
async def pre_checkout(query: PreCheckoutQuery):
    payload = query.invoice_payload or ""
    if not payload.startswith("osint:"):
        await query.answer(ok=False, error_message="Неизвестный платёж.")
        return

    order_id = payload.split(":", 1)[1]
    order = get_order(order_id)
    if not order:
        await query.answer(ok=False, error_message="Счёт не найден. Создайте новый запрос.")
        return

    expired = int(time.time()) - order["created_at"] > ORDER_TTL_SECONDS
    valid = (
        order["status"] == "pending"
        and order["user_id"] == query.from_user.id
        and order["amount"] == query.total_amount
        and query.currency == "XTR"
        and not expired
    )
    if not valid:
        await query.answer(ok=False, error_message="Счёт недействителен или уже использован.")
        return

    await query.answer(ok=True)


@dp.message(F.successful_payment)
async def successful_payment(message: Message):
    if not message.from_user or not message.successful_payment:
        return
    register_user(message.from_user)

    payment = message.successful_payment
    payload = payment.invoice_payload or ""
    if not payload.startswith("osint:"):
        return

    order_id = payload.split(":", 1)[1]
    order = get_order(order_id)
    if not order:
        await message.answer("Платёж получен, но заказ не найден. Используйте /support.")
        return

    if (
        order["user_id"] != message.from_user.id
        or payment.currency != "XTR"
        or payment.total_amount != order["amount"]
    ):
        await message.answer("Параметры платежа не совпали с заказом. Используйте /support.")
        return

    if order["status"] == "fulfilled":
        await message.answer("Этот оплаченный запрос уже был выполнен.")
        return

    if order["status"] == "pending":
        if not mark_order_paid(order_id, payment.telegram_payment_charge_id):
            await message.answer("Платёж уже обработан. Используйте /retry при необходимости.")
            return
        order = get_order(order_id)

    if order["status"] != "paid":
        await message.answer("Не удалось подтвердить состояние заказа. Используйте /support.")
        return

    try:
        completed = await fulfill_order(message, order)
    except Exception:
        log.exception("Paid order failed: %s", order_id)
        await message.answer(
            "Оплата сохранена, но запрос не удалось завершить. "
            "Повторно платить не нужно: используйте /retry."
        )
        return

    if completed:
        mark_order_fulfilled(order_id)
    else:
        await message.answer(
            "Оплаченный запрос не завершён. Оплата сохранена, повторите позже через /retry."
        )


@dp.message(Command("retry"))
async def retry_cmd(message: Message):
    if not allowed(message):
        return
    register_user(message.from_user)
    order = latest_paid_order(message.from_user.id)
    if not order:
        await message.answer("Нет оплаченного незавершённого запроса для повтора.")
        return
    if message.from_user.id in active_users:
        await message.answer("Сначала дождись завершения текущего процесса или используй /cancel.")
        return

    try:
        completed = await fulfill_order(message, order)
    except Exception:
        log.exception("Retry failed: %s", order["order_id"])
        await message.answer("Запрос снова не завершился. Оплата сохранена, можно повторить позже.")
        return

    if completed:
        mark_order_fulfilled(order["order_id"])
    else:
        await message.answer("Запрос снова не завершился. Оплата сохранена.")


@dp.message()
async def text_input(message: Message, bot: Bot):
    if not allowed(message) or not message.from_user:
        return
    register_user(message.from_user)
    uid = message.from_user.id
    command = pending_input.pop(uid, None)
    if not command:
        return
    text = (message.text or "").strip()
    if not text:
        await message.answer("Нужен текстовый ввод. Запусти команду ещё раз.")
        return
    await handle_request(message, bot, command, text)


async def main():
    init_db()
    cleanup_reports()
    cleanup_task = asyncio.create_task(cleanup_loop())
    bot = Bot(BOT_TOKEN)
    try:
        await dp.start_polling(bot)
    finally:
        cleanup_task.cancel()
        for proc in list(running.values()):
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
