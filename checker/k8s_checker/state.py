# Deduplikasi notifikasi: hanya kirim temuan baru, pengingat berkala, dan resolved.
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import Finding, iso, parse_time, utcnow

log = logging.getLogger(__name__)


@dataclass
class Tracked:
    finding: Finding
    first_seen: datetime
    last_seen: datetime
    last_notified: datetime | None


@dataclass
class Delta:
    firing: list[tuple[Finding, datetime]]
    reminders: list[tuple[Finding, datetime]]
    resolved: list[tuple[Finding, datetime]]
    expired: list[str]  # id yang dihapus diam-diam

    def is_empty(self) -> bool:
        return not (self.firing or self.reminders or self.resolved)


class StateStore:
    def __init__(self, path: str = "", reminder_minutes: int = 60, notify_resolved: bool = True):
        self.path = path
        self.reminder = timedelta(minutes=reminder_minutes) if reminder_minutes > 0 else None
        self.notify_resolved = notify_resolved
        self.active: dict[str, Tracked] = {}
        self._load()

    # Menghitung perubahan tanpa mengubah state; state baru diterapkan via commit()
    def diff(self, current: list[Finding]) -> Delta:
        now = utcnow()
        cur = {f.id: f for f in current}
        firing, reminders, resolved, expired = [], [], [], []
        for fid, f in cur.items():
            t = self.active.get(fid)
            if t is None or t.last_notified is None:
                firing.append((f, t.first_seen if t else now))
            elif self.reminder and now - t.last_notified >= self.reminder:
                reminders.append((f, t.first_seen))
        for fid, t in self.active.items():
            if fid in cur:
                continue
            if t.finding.auto_expire or not self.notify_resolved or t.last_notified is None:
                expired.append(fid)
            else:
                resolved.append((t.finding, t.first_seen))
        return Delta(firing, reminders, resolved, expired)

    def commit(self, current: list[Finding], delta: Delta, delivered: bool) -> None:
        now = utcnow()
        notified_ids = {f.id for f, _ in delta.firing + delta.reminders} if delivered else set()
        new_active: dict[str, Tracked] = {}
        for f in current:
            old = self.active.get(f.id)
            new_active[f.id] = Tracked(
                finding=f,
                first_seen=old.first_seen if old else now,
                last_seen=now,
                last_notified=now if f.id in notified_ids else (old.last_notified if old else None),
            )
        if not delivered:
            # Pertahankan temuan resolved agar dikirim ulang di siklus berikutnya
            for f, _ in delta.resolved:
                if f.id not in new_active and f.id in self.active:
                    new_active[f.id] = self.active[f.id]
        self.active = new_active
        self._save()

    # persistence
    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                raw = json.load(fh)
            for fid, item in raw.get("active", {}).items():
                self.active[fid] = Tracked(
                    finding=Finding.from_dict(item["finding"]),
                    first_seen=parse_time(item["first_seen"]) or utcnow(),
                    last_seen=parse_time(item["last_seen"]) or utcnow(),
                    last_notified=parse_time(item.get("last_notified")),
                )
            log.info("State dimuat dari %s (%d temuan aktif)", self.path, len(self.active))
        except Exception as exc:  # noqa: BLE001
            log.warning("Gagal memuat state %s: %s — mulai dari kosong", self.path, exc)

    def _save(self) -> None:
        if not self.path:
            return
        data = {"active": {
            fid: {
                "finding": t.finding.to_dict(),
                "first_seen": iso(t.first_seen),
                "last_seen": iso(t.last_seen),
                "last_notified": iso(t.last_notified),
            } for fid, t in self.active.items()
        }}
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("Gagal menyimpan state ke %s: %s", self.path, exc)
