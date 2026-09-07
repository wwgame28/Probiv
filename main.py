import asyncio
import base64
import csv
import html as html_lib
import ipaddress
import json
import logging
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import bot as core
from aiogram.types import FSInputFile, Message

log = logging.getLogger("osint-bot.enhanced")
IMG_SRC_RE = re.compile(r'(<img\b[^>]*?\bsrc=["\'])(https?://[^"\']+)(["\'])', re.IGNORECASE)
MAX_IMAGE_BYTES = 3 * 1024 * 1024
MAX_IMAGES = 30
MAX_REDIRECTS = 4
DOWNLOAD_TIMEOUT = 10


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _public_http_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if core.is_unsafe_ip(ip):
            return False
    return True


def _fetch_image(url: str) -> tuple[str, bytes] | None:
    opener = urllib.request.build_opener(NoRedirect())
    current = html_lib.unescape(url)
    for _ in range(MAX_REDIRECTS + 1):
        if not _public_http_url(current):
            return None
        req = urllib.request.Request(current, headers={
            "User-Agent": "Mozilla/5.0 (compatible; OSINTBot/1.0)",
            "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        })
        try:
            resp = opener.open(req, timeout=DOWNLOAD_TIMEOUT)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                location = exc.headers.get("Location")
                if not location:
                    return None
                current = urllib.parse.urljoin(current, location)
                continue
            return None
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
        with resp:
            final_url = resp.geturl()
            if not _public_http_url(final_url):
                return None
            content_type = (resp.headers.get_content_type() or "").lower()
            if not content_type.startswith("image/"):
                return None
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > MAX_IMAGE_BYTES:
                return None
            data = resp.read(MAX_IMAGE_BYTES + 1)
            if not data or len(data) > MAX_IMAGE_BYTES:
                return None
            return content_type, data
    return None


def _embed_images_sync(report: Path) -> tuple[Path, int, int]:
    text = report.read_text(encoding="utf-8", errors="replace")
    matches = list(IMG_SRC_RE.finditer(text))
    if not matches:
        return report, 0, 0
    cache: dict[str, str | None] = {}
    attempted = 0
    embedded = 0

    def replace(match: re.Match) -> str:
        nonlocal attempted, embedded
        original_url = match.group(2)
        if original_url in cache:
            data_uri = cache[original_url]
            if data_uri:
                embedded += 1
                return f"{match.group(1)}{data_uri}{match.group(3)}"
            return match.group(0)
        if attempted >= MAX_IMAGES:
            cache[original_url] = None
            return match.group(0)
        attempted += 1
        fetched = _fetch_image(original_url)
        if not fetched:
            cache[original_url] = None
            return match.group(0)
        content_type, data = fetched
        data_uri = f"data:{content_type};base64,{base64.b64encode(data).decode('ascii')}"
        cache[original_url] = data_uri
        embedded += 1
        return f"{match.group(1)}{data_uri}{match.group(3)}"

    updated = IMG_SRC_RE.sub(replace, text)
    if embedded == 0:
        return report, 0, attempted
    output = report.with_name(f"{report.stem}_with_images.html")
    output.write_text(updated, encoding="utf-8")
    return output, embedded, attempted


def _sherlock_rows(csv_path: Path) -> list[dict[str, str]]:
    if not csv_path.exists():
        return []
    rows = []
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            exists = (row.get("exists") or "").upper()
            url = (row.get("url_user") or "").strip()
            if url and "CLAIMED" in exists:
                rows.append({"site": (row.get("name") or "Site").strip(), "url": url})
    return rows


def _build_combined_report(username: str, maigret_report: Path, sherlock_rows: list[dict[str, str]]) -> Path:
    maigret_html = maigret_report.read_text(encoding="utf-8", errors="replace")
    items = "".join(
        f'<li><strong>{html_lib.escape(row["site"])}</strong>: '
        f'<a href="{html_lib.escape(row["url"], quote=True)}">{html_lib.escape(row["url"])}</a></li>'
        for row in sherlock_rows
    ) or "<li>Sherlock не добавил новых подтверждённых профилей.</li>"
    block = (
        '<section style="margin:24px 0;padding:18px;border:1px solid #ddd;border-radius:12px">'
        f'<h2>Sherlock: найдено {len(sherlock_rows)}</h2><ul>{items}</ul></section>'
    )
    marker = re.search(r"<body[^>]*>", maigret_html, re.IGNORECASE)
    if marker:
        pos = marker.end()
        combined = maigret_html[:pos] + block + maigret_html[pos:]
    else:
        combined = f"<html><body><h1>OSINT report for {html_lib.escape(username)}</h1>{block}{maigret_html}</body></html>"
    output = maigret_report.with_name(f"{username}_combined.html")
    output.write_text(combined, encoding="utf-8")
    return output


def _target_host(target: str) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    except ValueError:
        return None
    return (parsed.hostname or "").rstrip(".").lower() or None


def _is_domain(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return "." in host


def _domain_summary_html(target: str, subdomains: list[str], spiderfoot_ok: bool) -> str:
    sub_items = "".join(f"<li>{html_lib.escape(item)}</li>" for item in subdomains[:1000])
    if not sub_items:
        sub_items = "<li>Дополнительные поддомены не найдены.</li>"
    return (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>OSINT domain report</title></head><body style='font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;max-width:900px;margin:30px auto;padding:0 18px'>"
        f"<h1>OSINT отчёт: {html_lib.escape(target)}</h1>"
        f"<p>SpiderFoot: {'готов' if spiderfoot_ok else 'не завершён'}. Subfinder: {len(subdomains)} уникальных поддоменов.</p>"
        "<h2>Публично обнаруженные поддомены</h2><ul>" + sub_items + "</ul>"
        "<p><small>Отчёт предназначен для анализа открытых данных и разрешённых целей.</small></p></body></html>"
    )


async def enhanced_execute_username(message: Message, username: str, access_label: str) -> bool:
    uid = message.from_user.id
    job = core.OUT / f"username_{uid}_{int(core.time.time())}"
    maigret_dir = job / "maigret"
    maigret_dir.mkdir(parents=True, exist_ok=True)
    await message.answer(
        f"{access_label} Запускаю полный поиск <code>{core.html.escape(username)}</code> через Maigret + Sherlock.",
        parse_mode="HTML",
    )

    async with core.sem:
        m_code, m_output = await core.run_cmd([
            str(core.ROOT / "runtime" / "maigret" / "bin" / "python"), "-m", "maigret", username,
            "--no-progressbar", "--no-color", "--folderoutput", str(maigret_dir), "--html",
        ], core.ROOT, uid)

        sherlock_csv = job / "sherlock.csv"
        s_code, s_output = await core.run_cmd([
            str(core.ROOT / "runtime" / "sherlock" / "bin" / "sherlock"), username,
            "--csv", "--output", str(sherlock_csv), "--no-color", "--print-found", "--timeout", "20",
        ], core.ROOT, uid)

    reports = list(maigret_dir.glob("*.html"))
    if m_code != 0 or not reports:
        await message.answer(f"Maigret не завершил поиск, код {m_code}.")
        await core.send_output(message, m_output)
        return False

    report = max(reports, key=lambda x: x.stat().st_mtime)
    rows = _sherlock_rows(sherlock_csv) if s_code == 0 else []
    if s_code != 0:
        log.warning("Sherlock failed for %s: %s", username, s_output[-1000:])

    combined = await asyncio.to_thread(_build_combined_report, username, report, rows)
    try:
        final_report, embedded, _ = await asyncio.to_thread(_embed_images_sync, combined)
    except Exception:
        log.exception("Failed to embed report images")
        final_report, embedded = combined, 0

    caption = f"Полный поиск: {username} • Sherlock: {len(rows)} профилей"
    if embedded:
        caption += f" • фото: {embedded}"
    await message.answer_document(FSInputFile(final_report), caption=caption)
    if s_code != 0:
        await message.answer("Maigret завершён. Sherlock временно не ответил, поэтому отчёт содержит доступные результаты Maigret.")
    return True


async def enhanced_execute_scan(message: Message, target: str, access_label: str) -> bool:
    uid = message.from_user.id
    if not await core.target_resolves_public(target):
        await message.answer("Цель не разрешается в публичный IP-адрес или указывает на локальную/служебную сеть.")
        return False

    job = core.OUT / f"domain_{uid}_{int(core.time.time())}"
    job.mkdir(parents=True, exist_ok=True)
    host = _target_host(target)
    await message.answer(
        f"{access_label} Запускаю расширенный анализ <code>{core.html.escape(target)}</code> через SpiderFoot"
        + (" + Subfinder." if _is_domain(host) else "."),
        parse_mode="HTML",
    )

    async with core.sem:
        sf_code, sf_output = await core.run_cmd([
            str(core.ROOT / "runtime" / "spiderfoot" / "bin" / "python"),
            "sf.py", "-s", target, "-u", "investigate", "-o", "json", "-q",
        ], core.ROOT / "vendor" / "spiderfoot", uid)

        sub_code = 0
        sub_output = ""
        if _is_domain(host):
            sub_code, sub_output = await core.run_cmd([
                str(core.ROOT / "runtime" / "subfinder"), "-d", host, "-silent",
            ], core.ROOT, uid, timeout=min(core.TIMEOUT, 180))

    spiderfoot_path = job / "spiderfoot.json"
    spiderfoot_ok = False
    if sf_code == 0:
        try:
            parsed = json.loads(sf_output or "[]")
            spiderfoot_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
            spiderfoot_ok = True
        except json.JSONDecodeError:
            spiderfoot_path = job / "spiderfoot_raw.txt"
            spiderfoot_path.write_text(sf_output or "", encoding="utf-8")
    else:
        spiderfoot_path = job / "spiderfoot_error.txt"
        spiderfoot_path.write_text(sf_output or f"SpiderFoot exit code: {sf_code}", encoding="utf-8")

    subdomains: list[str] = []
    if _is_domain(host) and sub_code == 0:
        subdomains = sorted({line.strip().lower() for line in sub_output.splitlines() if line.strip()})
    sub_path = job / "subdomains.txt"
    sub_path.write_text("\n".join(subdomains) + ("\n" if subdomains else ""), encoding="utf-8")

    summary_path = job / "summary.html"
    summary_path.write_text(_domain_summary_html(target, subdomains, spiderfoot_ok), encoding="utf-8")
    bundle = job / "osint_bundle.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(summary_path, arcname="summary.html")
        zf.write(spiderfoot_path, arcname=spiderfoot_path.name)
        if _is_domain(host):
            zf.write(sub_path, arcname="subdomains.txt")

    await message.answer_document(
        FSInputFile(bundle),
        caption=f"Расширенный отчёт: {target} • поддоменов: {len(subdomains)}",
    )

    if not spiderfoot_ok and not subdomains:
        await message.answer("Оба источника не дали полноценного результата. Запрос сохранён как диагностический отчёт.")
        return False
    return True


core.execute_username = enhanced_execute_username
core.execute_scan = enhanced_execute_scan

if __name__ == "__main__":
    asyncio.run(core.main())
