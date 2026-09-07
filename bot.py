import asyncio
import html
import ipaddress
import os
import re
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
ALLOWED_USER_IDS = {
    int(x.strip()) for x in os.getenv("ALLOWED_USER_IDS", "").split(",")
    if x.strip().isdigit()
}
MAX_CONCURRENT = max(1, int(os.getenv("MAX_CONCURRENT_SCANS", "1")))
TIMEOUT = max(30, int(os.getenv("SCAN_TIMEOUT_SECONDS", "300")))
RATE_LIMIT = max(0, int(os.getenv("RATE_LIMIT_SECONDS", "30")))
REPORT_TTL_HOURS = max(1, int(os.getenv("REPORT_TTL_HOURS", "24")))
PRICE_STARS = max(1, int(os.getenv("PRICE_STARS", "50")))
SUPPORT_TEXT = os.getenv(
    "SUPPORT_TEXT",
    "По вопросам оплаты и работы бота обратитесь к владельцу бота.",
).strip()

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")

dp = Dispatcher()
sem = asyncio.Semaphore(MAX_CONCURRENT)
last_run: dict[int, float] = {}
running: dict[int, asyncio.subprocess.Process] = {}

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{2,64}")
TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,253}")
ORDER_TTL_SECONDS = 24 * 3600


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
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
            "CREATE INDEX IF NOT EXISTS idx_orders_user_status "
            "ON orders(user_id, status, created_at DESC)"
        )


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
            "UPDATE orders SET status = 'fulfilled', fulfilled_at = ? "
            "WHERE order_id = ? AND status = 'paid'",
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


def allowed(message: Message) -> bool:
    return bool(message.from_user) and (
        not ALLOWED_USER_IDS or message.from_user.id in ALLOWED_USER_IDS
    )


def valid_username(value: str) -> bool:
    return bool(USERNAME_RE.fullmatch(value))


def valid_target(value: str) -> bool:
    if not TARGET_RE.fullmatch(value):
        return False

    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host or host == "localhost" or host.endswith(".localhost"):
        return False

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


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
                    import shutil
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
        except OSError:
            pass


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
    payload = f"osint:{order_id}"

    await bot.send_invoice(
        chat_id=message.chat.id,
        title="OSINT-запрос",
        description=f"{label}: {argument}. После оплаты запрос запустится автоматически.",
        payload=payload,
        currency="XTR",
        prices=[LabeledPrice(label="1 OSINT-запрос", amount=PRICE_STARS)],
        provider_token="",
        start_parameter=f"osint_{order_id[:12]}",
    )


async def execute_username(message: Message, username: str) -> None:
    uid = message.from_user.id
    if uid in running:
        await message.answer(
            "У тебя уже идёт другой процесс. Оплаченный запрос сохранён. "
            "После завершения используй /retry."
        )
        raise RuntimeError("user already has a running process")

    job = OUT / f"maigret_{uid}_{int(time.time())}"
    job.mkdir(parents=True, exist_ok=True)
    await message.answer(
        f"Оплата подтверждена. Ищу публичные профили для "
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
    if reports:
        report = max(reports, key=lambda x: x.stat().st_mtime)
        await message.answer_document(
            FSInputFile(report),
            caption=f"Maigret: {username}",
        )
    else:
        await message.answer(f"Maigret завершил работу, код {code}.")
        await send_output(message, output)


async def execute_scan(message: Message, target: str) -> None:
    uid = message.from_user.id
    if uid in running:
        await message.answer(
            "У тебя уже идёт другой процесс. Оплаченный запрос сохранён. "
            "После завершения используй /retry."
        )
        raise RuntimeError("user already has a running process")

    job = OUT / f"spiderfoot_{uid}_{int(time.time())}"
    job.mkdir(parents=True, exist_ok=True)
    await message.answer(
        f"Оплата подтверждена. SpiderFoot запускает сбор открытых данных для "
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

    json_path = job / "result.json"
    json_path.write_text(output or "[]", encoding="utf-8")

    if code == 0 and json_path.stat().st_size > 0:
        await message.answer_document(
            FSInputFile(json_path),
            caption=f"SpiderFoot: {target}",
        )
    else:
        await message.answer(f"SpiderFoot завершил работу с кодом {code}.")
        await send_output(message, output)


async def fulfill_order(message: Message, order) -> bool:
    command = order["command"]
    argument = order["argument"]
    if command == "username":
        await execute_username(message, argument)
    elif command == "scan":
        await execute_scan(message, argument)
    else:
        await message.answer("Неизвестный тип оплаченного запроса. Обратитесь в /support.")
        return False
    return True


@dp.message(CommandStart())
async def start(message: Message):
    if not allowed(message):
        return
    await message.answer(
        "OSINT Bot\n\n"
        f"Стоимость одного запроса: {PRICE_STARS} ⭐ Telegram Stars.\n\n"
        "/username имя — поиск публичных профилей через Maigret\n"
        "/scan example.com — сбор открытых данных через SpiderFoot\n"
        "/retry — повторно запустить уже оплаченный, но не завершённый запрос\n"
        "/cancel — остановить свой текущий запуск\n"
        "/terms — условия оплаты\n"
        "/support — поддержка\n"
        "/help — справка\n\n"
        "Используй только открытые данные и цели, которые тебе разрешено проверять."
    )


@dp.message(Command("help"))
async def help_cmd(message: Message):
    await start(message)


@dp.message(Command("terms"))
async def terms_cmd(message: Message):
    if not allowed(message):
        return
    await message.answer(
        f"Условия оплаты\n\n"
        f"• 1 запрос стоит {PRICE_STARS} ⭐ Telegram Stars.\n"
        "• Оплата списывается только после подтверждения Telegram.\n"
        "• Оплаченный запрос предназначен только для пользователя, создавшего счёт.\n"
        "• Если бот перезапустился после оплаты до завершения запроса, используйте /retry.\n"
        "• Используйте сервис только законно и только для открытых данных или разрешённых целей."
    )


@dp.message(Command("support"))
async def support_cmd(message: Message):
    if not allowed(message):
        return
    await message.answer(SUPPORT_TEXT)


@dp.message(Command("cancel"))
async def cancel_cmd(message: Message):
    if not allowed(message):
        return
    uid = message.from_user.id
    proc = running.get(uid)
    if not proc:
        await message.answer("У тебя сейчас нет активного сканирования.")
        return
    if proc.returncode is None:
        proc.kill()
        await message.answer(
            "Остановил текущий процесс. Если он был оплачен и ещё не отмечен завершённым, "
            "его можно повторить через /retry."
        )
    else:
        await message.answer("Процесс уже завершился.")


@dp.message(Command("username"))
async def username_cmd(message: Message, bot: Bot):
    if not allowed(message):
        return
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) != 2 or not valid_username(parts[1].strip()):
        await message.answer("Формат: /username username")
        return
    if message.from_user.id in running:
        await message.answer("У тебя уже идёт запрос. Сначала дождись завершения или используй /cancel.")
        return
    await send_payment_invoice(message, bot, "username", parts[1].strip())


@dp.message(Command("scan"))
async def scan_cmd(message: Message, bot: Bot):
    if not allowed(message):
        return
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) != 2 or not valid_target(parts[1].strip()):
        await message.answer("Формат: /scan example.com")
        return
    if message.from_user.id in running:
        await message.answer("У тебя уже идёт сканирование. Сначала дождись завершения или используй /cancel.")
        return
    await send_payment_invoice(message, bot, "scan", parts[1].strip())


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
        await message.answer(
            "Оплата сохранена, но запрос не удалось завершить. Ничего повторно оплачивать не нужно: "
            "используйте /retry."
        )
        return

    if completed:
        mark_order_fulfilled(order_id)


@dp.message(Command("retry"))
async def retry_cmd(message: Message):
    if not allowed(message):
        return
    order = latest_paid_order(message.from_user.id)
    if not order:
        await message.answer("Нет оплаченного незавершённого запроса для повтора.")
        return
    if message.from_user.id in running:
        await message.answer("Сначала дождись завершения текущего процесса или используй /cancel.")
        return

    try:
        completed = await fulfill_order(message, order)
    except Exception:
        await message.answer("Запрос снова не завершился. Оплата сохранена, можно повторить позже через /retry.")
        return

    if completed:
        mark_order_fulfilled(order["order_id"])


async def main():
    init_db()
    cleanup_reports()
    bot = Bot(BOT_TOKEN)
    try:
        await dp.start_polling(bot)
    finally:
        for proc in list(running.values()):
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
