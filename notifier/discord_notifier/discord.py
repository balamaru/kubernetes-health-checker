# Format laporan menjadi pesan Discord (embed) dan kirim via Discord webhook.
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Batas Discord: 10 embed/pesan, total 6000 karakter/pesan, title 256,
# description 4096, field name 256, field value 1024, 25 field/embed, content 2000.
MAX_EMBEDS = 10
MAX_TOTAL = 5800  # sisakan margin
COLORS = {"critical": 0xE03E3E, "warning": 0xF2A33A, "info": 0x3B82F6, "resolved": 0x2EA043}
SEV_LABEL = {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO"}
SEV_ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵"}
STATUS_LABEL = {"firing": "BARU", "reminder": "MASIH TERJADI", "resolved": "RESOLVED"}
CATEGORY_LABEL = {
    "cluster": "Cluster / Control plane", "node": "Node", "pod": "Pod", "workload": "Workload",
    "network": "Jaringan in-cluster", "storage": "Storage", "event": "Event",
}


def _cut(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _embed_size(e: dict) -> int:
    n = len(e.get("title", "")) + len(e.get("description", ""))
    n += len((e.get("footer") or {}).get("text", ""))
    for f in e.get("fields", []):
        n += len(f["name"]) + len(f["value"])
    return n


def _duration(first_seen: str | None) -> str:
    if not first_seen:
        return ""
    try:
        dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    except ValueError:
        return ""
    mins = int((datetime.now(timezone.utc) - dt).total_seconds() // 60)
    if mins < 1:
        return "baru saja"
    if mins < 60:
        return f"{mins} menit"
    h, m = divmod(mins, 60)
    return f"{h} jam {m} menit" if h < 24 else f"{h // 24} hari {h % 24} jam"


def _code(lines: list[str], limit: int = 1024) -> str:
    body = "\n".join(str(x).replace("```", "ʼʼʼ") for x in lines)
    return "```\n" + _cut(body, limit - 8) + "\n```"


def _numbered_fields(name: str, items: list[str], max_fields: int = 3) -> list[dict]:
    """Daftar bernomor dipecah ke beberapa field (batas 1024 karakter per field)."""
    fields, cur = [], ""
    for i, item in enumerate(items, 1):
        line = _cut(f"{i}. {item}", 1000) + "\n"
        if len(cur) + len(line) > 1024:
            fields.append(cur)
            cur = ""
        cur += line
    if cur:
        fields.append(cur)
    out = []
    for i, val in enumerate(fields[:max_fields]):
        out.append({"name": name if i == 0 else f"{name} (lanjutan)", "value": val.strip(), "inline": False})
    return out


def finding_embed(f: dict, remediation_enabled: bool, llm_status: str = "") -> dict:
    status = f.get("status", "firing")
    sev = f.get("severity", "warning")
    resolved = status == "resolved"
    icon = "✅" if resolved else SEV_ICON.get(sev, "⚪")
    title = f"{icon} [{STATUS_LABEL.get(status, status.upper())}] {f.get('title', '')}"
    analysis = f.get("analysis") or {}
    extra = f.get("extra") or {}
    llm_ok = analysis.get("source") == "llm"

    # Judul embed = "ada masalah apa"; deskripsi = "kenapa errornya"
    if resolved:
        desc = f"**Masalah sudah tidak terdeteksi lagi.**\nDurasi gangguan: {_duration(f.get('first_seen')) or '-'}"
    elif llm_ok:
        desc = f"**Akar masalah:** {analysis.get('root_cause', '-')}"
        if analysis.get("impact"):
            desc += f"\n\n**Dampak:** {analysis['impact']}"
        ev = analysis.get("evidence") or []
        if ev:
            desc += "\n\n**Bukti dari cluster:**\n" + "\n".join(f"• {_cut(x, 300)}" for x in ev[:6])
    else:
        desc = f"**Penjelasan:** {f.get('explanation') or '-'}"
        ins = extra.get("insights") or []
        if ins:
            desc += "\n\n**Temuan dari data cluster:**\n" + "\n".join(f"• {_cut(x, 350)}" for x in ins[:6])

    res = f.get("resource") or {}
    fields = [
        {"name": "Severity", "value": SEV_LABEL.get(sev, sev), "inline": True},
        {"name": "Kategori", "value": CATEGORY_LABEL.get(f.get("category"), f.get("category", "-")), "inline": True},
        {"name": "Resource", "value": _cut(f"`{res.get('ref') or res.get('name', '-')}`", 1024), "inline": False},
    ]
    if status == "reminder":
        fields.insert(2, {"name": "Berlangsung", "value": _duration(f.get("first_seen")) or "-", "inline": True})
    if not resolved:
        evidence = [_cut(e, 300) for e in f.get("evidence") or [] if e]
        if evidence:
            fields.append({"name": "Detail deteksi", "value": _code(evidence[:6]), "inline": False})
        logs = extra.get("log_excerpt") or []
        if logs:
            label = _cut(extra.get("log_label") or "Log terakhir", 256)
            fields.append({"name": label, "value": _code([_cut(x, 200) for x in logs]), "inline": False})
        if llm_ok:
            fields += _numbered_fields("Rekomendasi remediasi", analysis.get("remediation") or [])
            cmds = analysis.get("commands") or []
            if cmds:
                fields.append({"name": "Perintah", "value": _code(cmds[:8]), "inline": False})
            if analysis.get("needs_more_info"):
                fields.append({"name": "Perlu dicek lebih lanjut", "value": _cut(analysis["needs_more_info"], 1024), "inline": False})
        elif f.get("remediation"):
            fields.append({"name": "Remediasi", "value": _cut(f["remediation"], 1024), "inline": False})

    footer = f"id {f.get('id', '-')}"
    if not resolved:
        if llm_ok:
            footer += f" • Analisis AI: {analysis.get('provider')}/{analysis.get('model')} (confidence {analysis.get('confidence', '-')}) — verifikasi sebelum eksekusi"
        elif extra.get("llm_error"):
            footer += f" • Analisis LLM gagal: {_cut(extra['llm_error'], 120)}"
        elif extra.get("llm_skipped"):
            footer += f" • Analisis LLM dilewati: {extra['llm_skipped']}"
        elif not remediation_enabled:
            footer += f" • Analisis LLM {llm_status}" if llm_status else " • Remediasi otomatis nonaktif (LLM belum dikonfigurasi)"
    embed = {
        "title": _cut(title, 256),
        "description": _cut(desc, 4096),
        "color": COLORS["resolved"] if resolved else COLORS.get(sev, 0x808080),
        "fields": fields[:25],
        "footer": {"text": _cut(footer, 2048)},
        "timestamp": f.get("first_seen") if not resolved else None,
    }
    return _shrink(embed)


def _shrink(e: dict, limit: int = MAX_TOTAL) -> dict:
    """Pastikan satu embed muat di batas 6000 karakter Discord."""
    log_fields = [x["name"] for x in e["fields"] if x["name"].startswith(("Log terakhir", "Baris error di log"))]
    drop_order = log_fields + ["Perintah", "Detail deteksi", "Perlu dicek lebih lanjut", "Rekomendasi remediasi (lanjutan)"]
    for name in drop_order:
        if _embed_size(e) <= limit:
            break
        e["fields"] = [x for x in e["fields"] if x["name"] != name]
    if _embed_size(e) > limit:
        over = _embed_size(e) - limit
        e["description"] = _cut(e["description"], max(200, len(e["description"]) - over - 10))
    return e


def build_messages(report: dict, username: str = "", avatar_url: str = "",
                   mention_critical: str = "", max_messages: int = 5) -> list[dict]:
    cluster = report.get("cluster", "kubernetes")
    s = report.get("summary") or {}
    findings = report.get("findings") or []
    has_new_critical = any(f.get("status") == "firing" and f.get("severity") == "critical" for f in findings)

    header = (
        f"**Laporan Health Check — cluster `{cluster}`**\n"
        f"Aktif: 🔴 {s.get('active_critical', 0)} critical · 🟠 {s.get('active_warning', 0)} warning"
        f" | Baru: {s.get('new', 0)} · Pengingat: {s.get('reminder', 0)} · Resolved: {s.get('resolved', 0)}"
    )
    if s.get("truncated"):
        header += f"\n_({s['truncated']} temuan lain tidak ditampilkan — lihat endpoint /status checker)_"
    errs = report.get("check_errors") or []
    if errs:
        header += "\n⚠️ Sebagian pemeriksaan gagal: " + "; ".join(_cut(e, 150) for e in errs[:3])
    if has_new_critical and mention_critical:
        header = f"{mention_critical} " + header

    embeds = [finding_embed(f, report.get("remediation_enabled", False), report.get("llm_status", ""))
              for f in findings]
    for e in embeds:
        if e.get("timestamp") is None:
            e.pop("timestamp", None)

    # Bagi embed ke beberapa pesan sesuai batas Discord
    chunks: list[list[dict]] = []
    cur: list[dict] = []
    cur_size = 0
    for e in embeds:
        size = _embed_size(e)
        if cur and (len(cur) >= MAX_EMBEDS or cur_size + size > MAX_TOTAL):
            chunks.append(cur)
            cur, cur_size = [], 0
        cur.append(e)
        cur_size += size
    if cur:
        chunks.append(cur)
    if not chunks:
        chunks = [[]]

    dropped = 0
    if len(chunks) > max_messages:
        dropped = sum(len(c) for c in chunks[max_messages:])
        chunks = chunks[:max_messages]

    messages = []
    for i, chunk in enumerate(chunks):
        msg: dict = {"embeds": chunk, "allowed_mentions": {"parse": ["roles", "everyone", "users"]}}
        if i == 0:
            content = header
            if dropped:
                content += f"\n_({dropped} temuan tambahan dipotong karena batas jumlah pesan)_"
            msg["content"] = _cut(content, 2000)
        elif len(chunks) > 1:
            msg["content"] = f"_(lanjutan {i + 1}/{len(chunks)})_"
        if username:
            msg["username"] = username
        if avatar_url:
            msg["avatar_url"] = avatar_url
        messages.append(msg)
    return messages


class DiscordError(Exception):
    pass


def post(webhook_url: str, message: dict, timeout: int = 15, max_retries: int = 5) -> None:
    """Kirim satu pesan ke Discord webhook, menangani rate limit (HTTP 429)."""
    url = webhook_url + ("&" if "?" in webhook_url else "?") + "wait=true"
    body = json.dumps(message, ensure_ascii=False).encode("utf-8")
    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "k8s-health-notifier/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                remaining = resp.headers.get("X-RateLimit-Remaining")
                reset_after = resp.headers.get("X-RateLimit-Reset-After")
                if remaining == "0" and reset_after:
                    time.sleep(min(float(reset_after), 10))
                return
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")[:500]
            if exc.code == 429:
                try:
                    wait = float(json.loads(text).get("retry_after", 1))
                except (ValueError, AttributeError):
                    wait = float(exc.headers.get("Retry-After", 1) or 1)
                log.warning("Discord rate limit, menunggu %.2fs (percobaan %d)", wait, attempt)
                time.sleep(min(wait, 30))
                continue
            if 500 <= exc.code < 600:
                log.warning("Discord HTTP %s, retry (percobaan %d)", exc.code, attempt)
                time.sleep(min(2 ** attempt, 10))
                continue
            raise DiscordError(f"Discord menolak pesan (HTTP {exc.code}): {text}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("Gagal terhubung ke Discord: %s (percobaan %d)", exc, attempt)
            time.sleep(min(2 ** attempt, 10))
    raise DiscordError(f"Gagal mengirim ke Discord setelah {max_retries} percobaan")
