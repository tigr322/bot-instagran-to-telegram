import os
import re
import logging
import tempfile
import asyncio
import socket
from urllib.parse import urlsplit, urlunsplit
from contextlib import closing

import requests
from telegram import Update, InputFile
from telegram.constants import ChatAction
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# yt-dlp для Instagram
import yt_dlp

# =====================
# Конфигурация
# =====================
BOT_TOKEN = os.getenv("BOT_TOKEN", "8510855682:AAGGLqqcpJKl4FD9SLU3hNoTNA2Ohc5c6aQ")
REQUEST_TIMEOUT = 25
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
MAX_SIZE_MB = int(os.getenv("MAX_SIZE_MB", "400"))  # ограничение на скачивание
CHUNK_SIZE = 1024 * 256  # 256KB

# Зеркала (оставляем как резерв)
MIRRORS = [
    "https://ddinstagram.com",
    "https://www.ddinstagram.com",
    "https://ddinstagram.org",
    "https://ddinsta.io",
    "https://ddinsta.org",
    "https://ssinstagram.com",  # может быть с кривым SSL
]
INSECURE_SSL_HOSTS = {"ssinstagram.com"}
RESOLVE_TIMEOUT = 2.0
MIRROR_CONNECT_TIMEOUT = 6.0
JINA_PROXY_FMT = "https://r.jina.ai/http://{host}{path_qs}"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ig-bot")

# =====================
# Регэкспы
# =====================
INSTAGRAM_URL_RE = re.compile(r"(https?://(?:www\.)?instagram\.com/[^\s]+)", re.IGNORECASE)
MP4_IN_HTML_RE = re.compile(r'(?:"|\')((?:https?:)?//[^"\']+\.mp4(?:\?[^"\']*)?)(?:"|\')', re.IGNORECASE)
OG_VIDEO_META_RE = re.compile(r'<meta\s+property=["\']og:video["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE)


def _normalize_url(u: str) -> str:
    if u.startswith("//"):
        return "https:" + u
    return u


def _find_mp4_in_html(html: str) -> str | None:
    m = OG_VIDEO_META_RE.search(html)
    if m:
        return _normalize_url(m.group(1))
    m2 = MP4_IN_HTML_RE.search(html)
    if m2:
        return _normalize_url(m2.group(1))
    return None


def _dns_resolves(host: str) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(RESOLVE_TIMEOUT)
            ip = socket.gethostbyname(host)
            s.connect((ip, 443))
            return True
    except Exception:
        return False


def _pick_healthy_mirror() -> str | None:
    for base in MIRRORS:
        try:
            host = urlsplit(base).netloc
            if not _dns_resolves(host):
                log.warning("Mirror DNS/connect failed: %s", host)
                continue

            verify = True
            if any(host.endswith(h) for h in INSECURE_SSL_HOSTS):
                verify = False

            r = requests.get(
                f"{base}/robots.txt",
                timeout=MIRROR_CONNECT_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                verify=verify,
            )
            if r.status_code < 500:
                log.info("Mirror OK: %s (status=%s, verify=%s)", base, r.status_code, verify)
                return base
        except requests.exceptions.SSLError as e:
            log.warning("Mirror SSL error %s: %s", base, e)
        except Exception as e:
            log.warning("Mirror check failed %s: %s", base, e)
    return None


def _fetch_direct_video_from_page(url: str, timeout=REQUEST_TIMEOUT) -> str | None:
    """
    РЕЗЕРВ: пробуем зеркала + прокси, вытаскиваем mp4 из HTML.
    """
    parts = urlsplit(url)
    ig_path_qs = parts.path
    if parts.query:
        ig_path_qs += "?" + parts.query

    mirror_base = _pick_healthy_mirror()
    if mirror_base:
        host = urlsplit(mirror_base).netloc
        mirror_url = urlunsplit((urlsplit(mirror_base).scheme, host, parts.path, parts.query, parts.fragment))

        verify = True
        if any(host.endswith(h) for h in INSECURE_SSL_HOSTS):
            verify = False

        headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
        try:
            r = requests.get(mirror_url, timeout=timeout, headers=headers, verify=verify)
            if r.status_code < 400:
                mp4 = _find_mp4_in_html(r.text)
                if mp4:
                    return _normalize_url(mp4)
            else:
                log.warning("Mirror responded %s for %s", r.status_code, mirror_url)
        except Exception as e:
            log.exception("Mirror fetch failed: %s", e)

    # Фолбэк через Jina proxy
    for host in ("ddinstagram.com", "www.ddinstagram.com"):
        try:
            proxy_url = JINA_PROXY_FMT.format(host=host, path_qs=ig_path_qs)
            r = requests.get(proxy_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if r.status_code < 400:
                mp4 = _find_mp4_in_html(r.text)
                if mp4:
                    return _normalize_url(mp4)
        except Exception as e:
            log.warning("Jina proxy %s failed: %s", host, e)

    return None


def _download_file(url: str, max_size_mb=MAX_SIZE_MB) -> str | None:
    """
    Стримово качает файл в temp и возвращает путь. Ограничивает размер.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Referer": "https://instagram.com/",
    }
    try:
        with requests.get(url, stream=True, timeout=REQUEST_TIMEOUT, headers=headers) as r:
            r.raise_for_status()
            content_length = r.headers.get("Content-Length")
            if content_length:
                size_mb = int(content_length) / (1024 * 1024)
                if size_mb > max_size_mb:
                    log.warning("File too large: %.2f MB > %d MB", size_mb, max_size_mb)
                    return None

            with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as f:
                total = 0
                for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if (total / (1024 * 1024)) > max_size_mb:
                        log.warning("File grew too large while downloading (> %d MB)", max_size_mb)
                        path = f.name
                        f.close()
                        try:
                            os.unlink(path)
                        except Exception:
                            pass
                        return None
                    f.write(chunk)
                return f.name
    except Exception as e:
        log.exception("Download failed: %s", e)
        return None


def _ytdlp_download(insta_url: str) -> str | None:
    """
    Пытаемся без ffmpeg:
    1) скачать готовый прогрессивный MP4 (single file);
    2) если не получилось — достаём прямой URL формата и качаем нашим стримером.
    """
    out_dir = tempfile.mkdtemp(prefix="igdl_")
    out_tpl = os.path.join(out_dir, "%(id)s.%(ext)s")

    # формат: просим сразу "цельный" mp4 (без merge)
    ydl_opts = {
        "quiet": True,
        "noprogress": True,
        "outtmpl": out_tpl,
        "format": (
            # прогрессивные варианты, где есть и видео, и звук, предпочтительно mp4
            "best[ext=mp4][acodec!=none][vcodec!=none]/"
            "best[protocol^=http][acodec!=none][vcodec!=none]/"
            "best"
        ),
        # Не просим merge (чтобы не требовался ffmpeg)
        "merge_output_format": None,
        "postprocessors": [],    # без постпроцессинга
        "retries": 3,
        "socket_timeout": REQUEST_TIMEOUT,
        "http_headers": {"User-Agent": USER_AGENT},
    }

    try:
        # 1) Пробуем сразу скачать цельный файл
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(insta_url, download=True)
            # попытка найти итоговый файл
            if "_filename" in info and os.path.exists(info["_filename"]):
                return info["_filename"]
            fname = ydl.prepare_filename(info)
            if fname and os.path.exists(fname):
                return fname
    except Exception as e:
        log.warning("yt-dlp direct download failed: %s", e)

    # 2) Если не вышло — достаём форматы и качаем лучший прогрессивный URL сами
    try:
        with yt_dlp.YoutubeDL({"quiet": True, "noprogress": True, "http_headers": {"User-Agent": USER_AGENT}}) as ydl:
            info = ydl.extract_info(insta_url, download=False)
            fmts = info.get("formats") or []
            # выбираем формат, где есть и видео, и звук, протокол http(s), расширение mp4
            candidates = [
                f for f in fmts
                if f.get("url")
                and (f.get("acodec") not in (None, "none"))
                and (f.get("vcodec") not in (None, "none"))
                and (f.get("protocol") or "").startswith("http")
                and f.get("ext") == "mp4"
            ]
            # сортнём по высоте/битрейту
            def key(f):
                return (f.get("height") or 0, f.get("tbr") or 0)
            candidates.sort(key=key, reverse=True)

            if candidates:
                direct_url = candidates[0]["url"]
                path = _download_file(direct_url, MAX_SIZE_MB)
                if path:
                    return path
    except Exception as e:
        log.warning("yt-dlp info/fallback failed: %s", e)

    return None


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Пришлите ссылку на Instagram Reels/видео. Я попробую скачать и отправить файл."
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    m = INSTAGRAM_URL_RE.search(text)
    if not m:
        await update.message.reply_text("Не нашёл ссылку на instagram.com в сообщении.")
        return

    insta_url = m.group(1).split("?")[0].rstrip("/") + "/"
    log.info("Got IG URL: %s", insta_url)

    try:
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.UPLOAD_VIDEO)
    except Exception:
        pass

    # 1) Основной путь — yt-dlp
    video_path = await asyncio.to_thread(_ytdlp_download, insta_url)

    # 2) Если yt-dlp не справился — пробуем зеркала/прокси → прямая mp4 → скачать
    if not video_path:
        direct_url = await asyncio.to_thread(_fetch_direct_video_from_page, insta_url)
        if direct_url:
            video_path = await asyncio.to_thread(_download_file, direct_url, MAX_SIZE_MB)

    if not video_path:
        await update.message.reply_text("Не удалось извлечь видео. Попробуйте другую ссылку на Reels.")
        return

    try:
        with open(video_path, "rb") as f:
            await update.message.reply_video(
                video=InputFile(f, filename=os.path.basename(video_path)),
                caption="",
                supports_streaming=True,
            )
    except Exception as e:
        log.exception("send_video(file) failed: %s", e)
        await update.message.reply_text("Видео скачано, но отправка не удалась 😕")
    finally:
        # Чистим временный файл/папку
        try:
            os.unlink(video_path)
        except Exception:
            pass
        try:
            # удалить пустую директорию, если осталось
            base_dir = os.path.dirname(video_path)
            if base_dir.startswith(tempfile.gettempdir()):
                os.rmdir(base_dir)
        except Exception:
            pass


# ============== Одноэкземплярный запуск (фикс 409) ==============
LOCK_FD = None
LOCK_PATH = None

def _acquire_single_instance_lock() -> None:
    """
    Создаём lock-файл уникальный для токена. Второй запуск — с Exit.
    """
    global LOCK_FD, LOCK_PATH
    import hashlib
    h = hashlib.sha1((BOT_TOKEN or "no_token").encode()).hexdigest()[:10]
    LOCK_PATH = os.path.join(tempfile.gettempdir(), f"igbot_{h}.lock")

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        LOCK_FD = os.open(LOCK_PATH, flags)
        os.write(LOCK_FD, str(os.getpid()).encode())
        os.fsync(LOCK_FD)
        log.info("Instance lock acquired: %s", LOCK_PATH)
    except FileExistsError:
        raise SystemExit("Другой экземпляр бота уже запущен (lock file существует).")


def _release_single_instance_lock() -> None:
    global LOCK_FD, LOCK_PATH
    try:
        if LOCK_FD is not None:
            os.close(LOCK_FD)
        if LOCK_PATH and os.path.exists(LOCK_PATH):
            os.unlink(LOCK_PATH)
            log.info("Instance lock released.")
    except Exception:
        pass


def main():
    if not BOT_TOKEN:
        raise SystemExit("Установите переменную окружения BOT_TOKEN с токеном бота.")

    _acquire_single_instance_lock()
    try:
        app = Application.builder().token(BOT_TOKEN).build()
        app.add_handler(CommandHandler("start", start_cmd))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

        log.info("Bot started.")
        # Важно: удаляем хвост апдейтов и явно вырубаем вебхук
        app.bot.delete_webhook(drop_pending_updates=True)
        app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)
    finally:
        _release_single_instance_lock()


if __name__ == "__main__":
    main()
