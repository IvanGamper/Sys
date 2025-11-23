# Fitness Galerie-App (auf Basis deines Ticket-Systems)
# - TinyDB für Metadaten (data/exercises.json)
# - Medien: data/media/ (lokale Uploads) oder externe URLs
# - Keine Authentifizierung (kein Login)
# - Seiten: Galerie (Dashboard), Verwaltung (Upload / Bearbeiten / Löschen)
#
# Hinweis: Lege requirements.txt im Repo-Root mit mindestens:
# streamlit==1.39.0
# tinydb==4.8.2
# pandas==2.2.3
# python-dotenv==1.0.1

import os
import uuid
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
from tinydb import TinyDB, Query

# --------------------
# Konfiguration
# --------------------
DB_JSON_PATH = os.getenv("EX_DB_PATH", "data/exercises.json")
MEDIA_DIR = os.getenv("EX_MEDIA_DIR", "data/media")

CATEGORIES = ["Ganzkörper", "Brust", "Rücken", "Beine", "Arme", "Kern", "Mobilität", "Cardio", "Sonstiges"]

# unterstützte Upload-Erweiterungen
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
VIDEO_EXT = {".mp4", ".webm", ".ogg"}

# --------------------
# Hilfsfunktionen
# --------------------

def ensure_dirs():
    os.makedirs(os.path.dirname(DB_JSON_PATH) or '.', exist_ok=True)
    os.makedirs(MEDIA_DIR, exist_ok=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def sanitize_filename(name: str) -> str:
    # sehr einfache Sanitizer: uuid + original extension
    name = name.replace(' ', '_')
    return name


def save_upload(uploaded_file) -> str:
    """Speichert ein hochgeladenes File in MEDIA_DIR und gibt relativen Pfad zurück."""
    if uploaded_file is None:
        return ""
    filename = uploaded_file.name
    base, ext = os.path.splitext(filename)
    uid = uuid.uuid4().hex
    safe_name = f"{uid}{ext}"
    dest_path = os.path.join(MEDIA_DIR, safe_name)
    # write bytes
    with open(dest_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return dest_path


def is_youtube_url(url: str) -> bool:
    return any(host in url for host in ("youtube.com", "youtu.be"))


def media_is_image(path_or_url: str) -> bool:
    if not path_or_url:
        return False
    p = path_or_url.split('?')[0]
    _, ext = os.path.splitext(p)
    return ext.lower() in IMAGE_EXT


def media_is_video(path_or_url: str) -> bool:
    if not path_or_url:
        return False
    p = path_or_url.split('?')[0]
    _, ext = os.path.splitext(p)
    return ext.lower() in VIDEO_EXT or is_youtube_url(path_or_url)

# --------------------
# DB Wrapper (TinyDB)
# --------------------
class GalleryDB:
    def __init__(self, path: str = DB_JSON_PATH):
        ensure_dirs()
        self.path = path
        self.db = TinyDB(self.path)
        self.table = self.db.table("exercises")

    def create_exercise(self, title: str, description: str, category: str, media_url: str, media_type: str) -> int:
        now = now_iso()
        doc = {
            "title": title,
            "description": description,
            "category": category,
            "media_url": media_url,
            "media_type": media_type,  # 'image' or 'video'
            "created_at": now,
            "updated_at": now,
            "archived": 0
        }
        return self.table.insert(doc)

    def list_exercises(self, archived: bool = False) -> List[Dict[str, Any]]:
        res: List[Dict[str, Any]] = []
        for item in self.table:
            # item ist ein TinyDB Document mit .doc_id
            doc = dict(item)
            # doc_id anhängen für einfache Handhabung in UI
            doc["id"] = item.doc_id
            if archived and doc.get("archived", 0) == 1:
                res.append(doc)
            elif not archived and doc.get("archived", 0) == 0:
                res.append(doc)
        # sort newest first (fallback bei fehlendem updated_at)
        res.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return res

    def get(self, doc_id: int) -> Optional[Dict[str, Any]]:
        for item in self.table:
            if item.doc_id == doc_id:
                d = dict(item)
                d["id"] = item.doc_id
                return d
        return None

    def update(self, doc_id: int, fields: Dict[str, Any]):
        fields["updated_at"] = now_iso()
        self.table.update(fields, doc_ids=[doc_id])

    def delete(self, doc_id: int):
        # delete metadata and remove local media file if it is stored locally
        item = self.get(doc_id)
        if not item:
            return
        media = item.get("media_url", "") or ""
        # Nur lokale Dateien löschen (URLs überspringen)
        try:
            if media and not media.lower().startswith("http"):
                abs_media = os.path.abspath(media)
                abs_media_dir = os.path.abspath(MEDIA_DIR)
                if abs_media.startswith(abs_media_dir) and os.path.exists(abs_media):
                    os.remove(abs_media)
        except Exception:
            # Fehler beim Löschen ignorieren (optional: logging)
            pass
        self.table.remove(doc_ids=[doc_id])

    def toggle_archive(self, doc_id: int):
        item = self.get(doc_id)
        if not item:
            return
        new = 0 if item.get("archived", 0) == 1 else 1
        self.update(doc_id, {"archived": new})

# global DB instance
DB = GalleryDB()

# --------------------
# UI Components
# --------------------

def show_gallery(search: str = "", category: Optional[str] = None, show_archived: bool = False):
    st.header("📋 Galerie")
    exercises = DB.list_exercises(archived=show_archived)

    if search:
        s = search.lower()
        exercises = [e for e in exercises if s in (e.get("title", "") + " " + e.get("description", "")).lower()]
    if category and category != "Alle":
        exercises = [e for e in exercises if e.get("category") == category]

    if not exercises:
        st.info("Keine Übungen gefunden.")
        return

    # grid: 3 Spalten
    cols = st.columns(3)
    for idx, ex in enumerate(exercises):
        col = cols[idx % 3]
        with col:
            st.markdown(f"### {ex.get('title','-')}\n**{ex.get('category','-')}**")

            if ex.get("media_type") == "image":
                try:
                    st.image(ex.get("media_url"), use_column_width=True)
                except Exception:
                    st.caption("Bild konnte nicht geladen werden.")
            elif ex.get("media_type") == "video":
                try:
                    st.video(ex.get("media_url"))
                except Exception:
                    # fallback: show Link
                    st.write(ex.get("media_url"))

            st.write(ex.get("description", ""))
            st.caption(f"Erstellt: {ex.get('created_at','-')}")


def page_management():
    st.header("🛠️ Verwaltung — Galerie")

    tab_add, tab_list = st.tabs(["➕ Neue Übung", "🗂️ Vorhandene Übungen"])

    with tab_add:
        st.subheader("Neue Übung hinzufügen")
        with st.form("add_exercise"):
            title = st.text_input("Titel")
            description = st.text_area("Beschreibung")
            category = st.selectbox("Kategorie", ["Alle"] + CATEGORIES, index=1)

            media_choice = st.radio("Medienquelle", ["Hochladen", "URL"], horizontal=True)
            media_path = ""
            media_type = "image"

            if media_choice == "Hochladen":
                up = st.file_uploader("Bild oder Video auswählen (Bilder: png/jpg, Videos: mp4)", accept_multiple_files=False)
                if up is not None:
                    # speichern
                    media_path = save_upload(up)
                    # try to infer type
                    if media_is_video(media_path):
                        media_type = "video"
                    else:
                        media_type = "image"
                    st.success(f"Datei hochgeladen: {os.path.basename(media_path)}")
            else:
                url = st.text_input("Media-URL (YouTube, MP4, Bild-URL)")
                if url:
                    media_path = url.strip()
                    media_type = "video" if media_is_video(media_path) else "image"

            submitted = st.form_submit_button("✅ Hinzufügen")
            if submitted:
                if not title or not media_path:
                    st.error("Titel und Medium sind erforderlich.")
                else:
                    DB.create_exercise(title.strip(), description.strip(), category if category != "Alle" else "Sonstiges", media_path, media_type)
                    st.success("✅ Übung hinzugefügt")
                    st.experimental_rerun()

    with tab_list:
        st.subheader("Bestehende Übungen")
        exercises = DB.list_exercises(archived=False)
        if not exercises:
            st.info("Keine Übungen vorhanden.")
        for ex in exercises:
            with st.expander(f"{ex.get('title')} — {ex.get('category')}"):
                st.write(ex.get('description', ''))
                if ex.get('media_type') == 'image':
                    try:
                        st.image(ex.get('media_url'))
                    except Exception:
                        st.caption("Bild konnte nicht geladen werden.")
                else:
                    try:
                        st.video(ex.get('media_url'))
                    except Exception:
                        st.write(ex.get('media_url'))

                c1, c2, c3 = st.columns([1, 1, 1])
                ex_id = ex.get('id')
                if c1.button("✏️ Bearbeiten", key=f"edit_{ex_id}"):
                    st.session_state['edit_id'] = ex_id
                    st.experimental_rerun()
                if c2.button("🗑️ Löschen", key=f"del_{ex_id}"):
                    DB.delete(ex_id)
                    st.success("✅ Gelöscht")
                    st.experimental_rerun()
                if c3.button("📦 Archivieren", key=f"arch_{ex_id}"):
                    DB.toggle_archive(ex_id)
                    st.experimental_rerun()

    # Bearbeiten (wenn in session)
    if 'edit_id' in st.session_state:
        edit_id = st.session_state['edit_id']
        item = DB.get(edit_id)
        if not item:
            st.error("Eintrag nicht gefunden.")
            st.session_state.pop('edit_id', None)
        else:
            st.subheader(f"Bearbeite: {item.get('title')}")
            with st.form("edit_form"):
                categories_list = ["Alle"] + CATEGORIES
                default_cat = item.get('category', 'Sonstiges')
                default_index = categories_list.index(default_cat) if default_cat in categories_list else 0

                new_title = st.text_input("Titel", value=item.get('title', ''))
                new_desc = st.text_area("Beschreibung", value=item.get('description', ''))
                new_cat = st.selectbox("Kategorie", categories_list, index=default_index)

                media_choice = st.radio("Medienquelle", ["Beibehalten", "Neue Datei hochladen", "Neue URL"], horizontal=True)
                new_media = item.get('media_url')
                new_media_type = item.get('media_type')

                if media_choice == "Neue Datei hochladen":
                    up = st.file_uploader("Bild oder Video auswählen (überschreibt)", accept_multiple_files=False, key='edit_up')
                    if up:
                        p = save_upload(up)
                        new_media = p
                        new_media_type = "video" if media_is_video(p) else "image"
                        st.success("Neue Datei gespeichert.")
                elif media_choice == "Neue URL":
                    url = st.text_input("Neue Media-URL", value=item.get('media_url', ''))
                    if url:
                        new_media = url.strip()
                        new_media_type = "video" if media_is_video(new_media) else "image"

                if st.form_submit_button("💾 Speichern"):
                    DB.update(edit_id, {"title": new_title, "description": new_desc, "category": (new_cat if new_cat != 'Alle' else 'Sonstiges'), "media_url": new_media, "media_type": new_media_type})
                    st.success("✅ Aktualisiert")
                    st.session_state.pop('edit_id', None)
                    st.experimental_rerun()

# --------------------
# Main
# --------------------

def main():
    st.set_page_config(page_title="Fitness Galerie", layout="wide", page_icon="🏋️")

    st.sidebar.title("🏋️ Fitness Galerie")
    nav = st.sidebar.radio("Navigation", ["📋 Galerie", "🛠️ Verwaltung"], index=0)

    # Filters in sidebar for gallery
    if nav == "📋 Galerie":
        search = st.sidebar.text_input("🔍 Suche")
        cat = st.sidebar.selectbox("Kategorie", ["Alle"] + CATEGORIES)
        show_arch = st.sidebar.checkbox("Archivierte anzeigen")

        show_gallery(search=search, category=cat, show_archived=show_arch)

    elif nav == "🛠️ Verwaltung":
        page_management()


if __name__ == "__main__":
    main()
