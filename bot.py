import asyncio
import html
import ipaddress
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from aiogram import Bot, Dispatcher
from aiogram.filters import Command, CommandStart
from aiogram.types import FSInputFile, Message

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data" / "reports"
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

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")

dp = Dispatcher()
sem = asyncio.Semaphore(MAX_CONCURRENT)
last_run: dict[int, float] = {}
running: dict[int, asyncio.subprocess.Process] = {}

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{2,64}")
TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,253}")


def allowed(message: Message) -> bool:
    return bool(message.from_user) and (
        not ALLOWED_USER_IDS or message.from_user.id in ALLOWED_USER_IDS
    )


def valid_username(value: str) -> bool:
    return bool(USERNAME_RE.fullmatch(value))


def valid_target(value: str) -> bool:
    # SpiderFoot accepts domains, IPs and URLs. Keep input shell-free and
    # reject obvious local/private network targets.
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


@dp.message(CommandStart())
async def start(message: Message):
    if not allowed(message):
        return
    await message.answer(
        "OSINT Bot\n\n"
        "/username имя — поиск публичных профилей через Maigret\n"
        "/scan example.com — сбор открытых данных через SpiderFoot\n"
        "/cancel — остановить свой текущий запуск\n"
        "/help — справка\n\n"
        "Используй только открытые данные и цели, которые тебе разрешено проверять."
    )


@dp.message(Command("help"))
async def help_cmd(message: Message):
    await start(message)


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
        await message.answer("Остановил текущий процесс.")
    else:
        await message.answer("Процесс уже завершился.")


@dp.message(Command("username"))
async def username_cmd(message: Message):
    if not allowed(message):
        return
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) != 2 or not valid_username(parts[1].strip()):
        await message.answer("Формат: /username username")
        return

    uid = message.from_user.id
    if not rate_ok(uid):
        await message.answer("Подожди немного перед следующим запуском.")
        return

    username = parts[1].strip()
    job = OUT / f"maigret_{uid}_{int(time.time())}"
    job.mkdir(parents=True, exist_ok=True)
    await message.answer(
        f"Ищу публичные профили для <code>{html.escape(username)}</code>.",
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


@dp.message(Command("scan"))
async def scan_cmd(message: Message):
    if not allowed(message):
        return
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) != 2 or not valid_target(parts[1].strip()):
        await message.answer("Формат: /scan example.com")
        return

    uid = message.from_user.id
    if uid in running:
        await message.answer("У тебя уже идёт сканирование. Используй /cancel для остановки.")
        return
    if not rate_ok(uid):
        await message.answer("Подожди немного перед следующим запуском.")
        return

    target = parts[1].strip()
    job = OUT / f"spiderfoot_{uid}_{int(time.time())}"
    job.mkdir(parents=True, exist_ok=True)
    await message.answer(
        f"SpiderFoot запускает сбор открытых данных для "
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


async def main():
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
