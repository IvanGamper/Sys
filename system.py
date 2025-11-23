# app_nosql_fixed.py
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


import pandas as pd
import streamlit as st

from werkzeug.security import generate_password_hash, check_password_hash


# TinyDB für lokale NoSQL-Variante
try:
    from tinydb import TinyDB, Query
    from tinydb.operations import delete
except Exception as e:
    raise RuntimeError("Bitte installiere tinydb: pip install tinydb") from e

# --------------------
# Konfiguration
# --------------------
DB_JSON_PATH = os.getenv("TINYDB_PATH", "tickets_nosql.json")

STATI = ["Neu", "In Bearbeitung", "Warten auf Benutzer", "Gelöst", "Geschlossen"]
PRIO = ["Niedrig", "Normal", "Hoch", "Kritisch"]
CATS = ["Hardware", "Software", "Netzwerk", "Sonstiges"]

STATUS_COLORS = {
    "Neu": "🔵",
    "In Bearbeitung": "🟡",
    "Warten auf Benutzer": "🟠",
    "Gelöst": "🟢",
    "Geschlossen": "⚫"
}

PRIO_COLORS = {
    "Niedrig": "🟢",
    "Normal": "🟡",
    "Hoch": "🟠",
    "Kritisch": "🔴"
}

# --------------------
# TinyDB Wrapper
# --------------------
class NoSqlDB:
    """Einfacher TinyDB-Wrapper mit Tables: users, tickets"""
    def __init__(self, path: str = DB_JSON_PATH):
        self.path = path
        self.db = TinyDB(self.path)
        # Tabellen
        self.users = self.db.table("users")
        self.tickets = self.db.table("tickets")

    # Hilfs: konvertiere TinyDB doc (mit doc_id) in dict mit "id"
    @staticmethod
    def _doc_to_row(doc: dict, doc_id: int) -> dict:
        row = dict(doc)
        row["id"] = doc_id
        return row

    # users
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        q = Query()
        rows = self.users.search(q.username == username.strip())
        if not rows:
            return None
        # Active prüfen (wenn Feld fehlt => aktiv)
        doc = rows[0]
        doc_id = self._find_doc_id(self.users, doc)
        if doc.get("active", 1) != 1:
            return None
        return self._doc_to_row(doc, doc_id)

    def create_user(self, username: str, password_hash: str, role: str = "user") -> int:
        now = datetime.now(timezone.utc).isoformat()
        doc = {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "active": 1,
            "created_at": now,
            "deleted_at": None
        }
        doc_id = self.users.insert(doc)
        return doc_id

    def list_active_users(self) -> List[Dict[str, Any]]:
        q = Query()
        rows = self.users.search(q.active == 1)
        # convert to include id
        result = []
        for r in rows:
            doc_id = self._find_doc_id(self.users, r)
            result.append(self._doc_to_row(r, doc_id))
        # sort by username
        result.sort(key=lambda x: x.get("username",""))
        return result

    def deactivate_user(self, user_id: int):
        # TinyDB document IDs are integers (doc_id)
        self.users.update({"active": 0, "deleted_at": datetime.now(timezone.utc).isoformat()}, doc_ids=[user_id])

    # tickets
    def create_ticket(self, title: str, description: str, category: str, priority: str, creator_id: int) -> int:
        now = datetime.now(timezone.utc).isoformat()
        doc = {
            "title": title,
            "description": description,
            "category": category,
            "status": "Neu",
            "priority": priority,
            "creator_id": creator_id,
            "assignee_id": None,
            "created_at": now,
            "updated_at": now,
            "archived": 0
        }
        return self.tickets.insert(doc)

    def fetch_tickets(self,
                      creator_id: Optional[int] = None,
                      archived: bool = False,
                      search_term: Optional[str] = None,
                      category: Optional[str] = None,
                      priority: Optional[str] = None) -> List[Dict[str, Any]]:
        all_rows = self.tickets.all()
        results = []
        for r in all_rows:
            # apply archived filter
            if archived:
                ok_arch = bool(r.get("archived", 0))
            else:
                ok_arch = (r.get("archived", 0) == 0)
            if not ok_arch:
                continue
            if creator_id is not None and r.get("creator_id") != creator_id:
                continue
            if search_term:
                s = search_term.lower()
                if s not in (r.get("title","").lower() + " " + r.get("description","").lower()):
                    continue
            if category and category != "Alle" and r.get("category") != category:
                continue
            if priority and priority != "Alle" and r.get("priority") != priority:
                continue
            doc_id = self._find_doc_id(self.tickets, r)
            results.append(self._doc_to_row(r, doc_id))
        # order by updated_at desc (ISO timestamps sort lexicographically)
        results.sort(key=lambda x: x.get("updated_at",""), reverse=True)
        return results

    def update_ticket(self, ticket_id: int, fields: Dict[str, Any]):
        if not fields:
            return
        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.tickets.update(fields, doc_ids=[ticket_id])

    def fetch_all_tickets_raw(self, archived: bool = False) -> List[Dict[str, Any]]:
        rows = self.fetch_tickets(archived=archived)
        return rows

    def stats(self) -> Dict[str, int]:
        rows = self.fetch_tickets(archived=True) + self.fetch_tickets(archived=False)
        total = len(rows)
        neue = len([r for r in rows if r.get("status") == "Neu"])
        in_bear = len([r for r in rows if r.get("status") == "In Bearbeitung"])
        geloest = len([r for r in rows if r.get("status") == "Gelöst"])
        archiviert = len([r for r in rows if r.get("archived",0) == 1])
        return {"total": total, "neue": neue, "in_bearbeitung": in_bear, "geloest": geloest, "archiviert": archiviert}

    from tinydb import Query

    from tinydb import Query

    def _find_doc_id(self, table, doc):
        """
        Versucht robust die TinyDB doc_id zu finden.
        - Prüft zuerst nach old_id (falls importiert)
        - Dann nach eindeutigen Feldern (username für users, title+created_at für tickets)
        - Dann Full-/Subset-Match als Fallback
        Liefert doc_id (int) oder None.
        """
        q = Query()

        # 1) old_id (am stabilsten bei Migration)
        if doc.get("old_id") is not None:
            res = table.search(q.old_id == doc["old_id"])
            if res:
                # Iteriere table (Document-Objekte) um doc_id zu bekommen
                for item in table:
                    if item.get("old_id") == doc["old_id"]:
                        return item.doc_id

        # 2) username (User-lookup)
        if "username" in doc:
            res = table.search(q.username == doc["username"])
            if res:
                for item in table:
                    if item.get("username") == doc["username"]:
                        return item.doc_id

        # 3) title + created_at (Ticket-lookup)
        if "title" in doc and "created_at" in doc:
            res = table.search((q.title == doc["title"]) & (q.created_at == doc["created_at"]))
            if res:
                for item in table:
                    if item.get("title") == doc["title"] and item.get("created_at") == doc["created_at"]:
                        return item.doc_id

        # 4) Fallback: try subset equality (best-effort)
        for item in table:
            # only compare keys that exist in both
            common_keys = [k for k in doc.keys() if k in item]
            if common_keys and all(item.get(k) == doc.get(k) for k in common_keys):
                return item.doc_id

        return None



# global DB instance
NOSQL = NoSqlDB()

# --------------------
# Utility-Functions (gleich wie vorher)
# --------------------
# Passwort verschlüsseln (werkzeug)
def hash_pw(password: str) -> str:
    return generate_password_hash(password)

# Passwort prüfen (werkzeug)
def verify_pw(password: str, stored_hash: str) -> bool:
    return check_password_hash(stored_hash, password)


def safe_index(options, value, default=0):
    try:
        return options.index(value)
    except Exception:
        return default

def next_status(s: str) -> str:
    try:
        i = STATI.index(s)
        return STATI[min(i + 1, len(STATI) - 1)]
    except ValueError:
        return s

def prev_status(s: str) -> str:
    try:
        i = STATI.index(s)
        return STATI[max(i - 1, 0)]
    except ValueError:
        return s

def format_datetime(dt_str):
    if not dt_str:
        return "—"
    try:
        dt = datetime.fromisoformat(str(dt_str).replace('Z', '+00:00'))
        return dt.strftime("%d.%m.%Y %H:%M")
    except:
        return str(dt_str)

# --------------------
# Repositories (NoSQL-Variante)
# --------------------
class UserRepository:
    """NoSQL-Repos über TinyDB"""
    @staticmethod
    def get_by_username(username: str) -> Optional[Dict[str, Any]]:
        return NOSQL.get_user_by_username(username)

    @staticmethod
    def create(username: str, password_hash: str, role: str = "user") -> int:
        return NOSQL.create_user(username, password_hash, role)

    @staticmethod
    def list_active() -> List[Dict[str, Any]]:
        return NOSQL.list_active_users()

    @staticmethod
    def deactivate(user_id: int):
        NOSQL.deactivate_user(user_id)

class TicketRepository:
    """NoSQL-Repos über TinyDB"""
    @staticmethod
    def create(title: str, description: str, category: str, priority: str, creator_id: int) -> int:
        return NOSQL.create_ticket(title, description, category, priority, creator_id)

    @staticmethod
    def fetch(creator_id: Optional[int] = None, archived: bool = False,
              search_term: Optional[str] = None, category: Optional[str] = None,
              priority: Optional[str] = None) -> List[Dict[str, Any]]:
        return NOSQL.fetch_tickets(creator_id, archived, search_term, category, priority)

    @staticmethod
    def update(ticket_id: int, fields: Dict[str, Any]):
        return NOSQL.update_ticket(ticket_id, fields)

    @staticmethod
    def fetch_all_raw(archived: bool = False) -> List[Dict[str, Any]]:
        return NOSQL.fetch_all_tickets_raw(archived)

    @staticmethod
    def stats() -> Dict[str, int]:
        return NOSQL.stats()

# --------------------
# Services (wie vorher)
# --------------------
class AuthService:
    @staticmethod
    def login(username: str, password: str) -> Optional[Dict[str, Any]]:
        u = UserRepository.get_by_username(username.strip())
        if not u:
            return None
        if verify_pw(password, u.get("password_hash", "")):
            return {"id": u["id"], "username": u["username"], "role": u["role"]}
        return None

    @staticmethod
    def create_user(username: str, password: str, role: str = "user") -> int:
        pw_hash = hash_pw(password)
        return UserRepository.create(username, pw_hash, role)

class TicketService:
    @staticmethod
    def create_ticket(title: str, description: str, category: str, priority: str, creator_id: int) -> int:
        return TicketRepository.create(title, description, category, priority, creator_id)

    @staticmethod
    def list_tickets(creator_id: Optional[int] = None, archived: bool = False,
                     search_term: Optional[str] = None, category: Optional[str] = None,
                     priority: Optional[str] = None) -> List[Dict[str, Any]]:
        return TicketRepository.fetch(creator_id, archived, search_term, category, priority)

    @staticmethod
    def update_ticket(ticket_id: int, **fields):
        TicketRepository.update(ticket_id, fields)

    @staticmethod
    def stats() -> Dict[str, int]:
        return TicketRepository.stats()

# --------------------
# UI (Streamlit) - nahezu unverändert
# --------------------
class AppUI:
    def __init__(self):
        st.set_page_config(page_title="Ticketsystem (NoSQL)", layout="wide", page_icon="🎫", initial_sidebar_state="expanded")
        st.markdown("""
            <style>
            .stButton button { border-radius: 5px; }
            div[data-testid="stExpander"] { border: 1px solid #ddd; border-radius: 5px; }
            </style>
        """, unsafe_allow_html=True)

    def show_stats(self):
        stats = TicketService.stats()
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Gesamt", stats.get('total', 0))
        col2.metric("🔵 Neu", stats.get('neue', 0))
        col3.metric("🟡 In Bearbeitung", stats.get('in_bearbeitung', 0))
        col4.metric("🟢 Gelöst", stats.get('geloest', 0))
        col5.metric("📦 Archiviert", stats.get('archiviert', 0))
        st.divider()

    def kanban_card(self, t: Dict[str, Any]):
        status_icon = STATUS_COLORS.get(t.get('status', ''), '⚪')
        prio_icon = PRIO_COLORS.get(t.get('priority', ''), '⚪')
        st.markdown(f"{status_icon} {prio_icon} **#{t['id']} — {t['title']}**")
        st.caption(f"📁 {t.get('category','-')} • ⏰ {format_datetime(t.get('updated_at'))}")
        desc = t.get('description') or ''
        st.write(desc[:150] + ("…" if len(desc) > 150 else ""))
        st.caption(f"👤 {t.get('creator_id','?')} → 👨‍💼 {t.get('assignee_id','—') or 'Nicht zugewiesen'}")

    def page_login(self):
        st.title("🎫 Ticketsystem Login (NoSQL)")
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.form("login_form"):
                st.subheader("Anmelden")
                u = st.text_input("Benutzername")
                p = st.text_input("Passwort", type="password")
                if st.form_submit_button("🔐 Anmelden", use_container_width=True):
                    user = AuthService.login(u, p)
                    if user:
                        st.session_state.update({
                            "user_id": user["id"],
                            "role": user["role"],
                            "username": user["username"]
                        })
                        st.success("✅ Erfolgreich angemeldet!")
                        st.rerun()
                    else:
                        st.error("❌ Ungültige Zugangsdaten")

    def page_create_ticket(self):
        st.header("➕ Neues Ticket erstellen")
        with st.form("create_ticket_form"):
            title = st.text_input("📝 Titel")
            desc = st.text_area("📄 Beschreibung", height=200)
            col1, col2 = st.columns(2)
            cat = col1.selectbox("📁 Kategorie", CATS)
            prio = col2.selectbox("⚠️ Priorität", PRIO, index=1)

            if st.form_submit_button("✅ Ticket anlegen", use_container_width=True):
                if not title or not desc:
                    st.error("❌ Titel und Beschreibung dürfen nicht leer sein.")
                else:
                    TicketService.create_ticket(title.strip(), desc.strip(), cat, prio, st.session_state.user_id)
                    st.success("✅ Ticket angelegt!")
                    st.balloons()
                    st.rerun()

    def page_kanban(self):
        st.header("🎫 Ticket Kanban-Board")
        self.show_stats()

        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        search = col1.text_input("🔍 Suche", placeholder="Ticket durchsuchen...")
        filter_cat = col2.selectbox("📁 Kategorie", ["Alle"] + CATS)
        filter_prio = col3.selectbox("⚠️ Priorität", ["Alle"] + PRIO)
        show_arch = col4.checkbox("📦 Archiv")

        is_admin = (st.session_state.get("role") == "admin")
        tickets = TicketService.list_tickets(
            archived=show_arch,
            search_term=search or None,
            category=(None if filter_cat == "Alle" else filter_cat),
            priority=(None if filter_prio == "Alle" else filter_prio),
        )
        if not tickets:
            st.info("ℹ️ Keine Tickets gefunden.")
            return

        users = UserRepository.list_active()
        user_map = {u["id"]: u["username"] for u in users}
        user_ids = [None] + [u["id"] for u in users]

        cols = st.columns(len(STATI))
        for idx, status_name in enumerate(STATI):
            with cols[idx]:
                status_icon = STATUS_COLORS.get(status_name, '⚪')
                col_tickets = [t for t in tickets if t.get("status") == status_name]
                st.subheader(f"{status_icon} {status_name} ({len(col_tickets)})")

                if not col_tickets:
                    st.caption("—")

                for t in col_tickets:
                    with st.container():
                        self.kanban_card(t)
                        c1, c2, c3 = st.columns([1, 1, 2])

                        with c1:
                            if st.button("⬅️", key=f"left_{t['id']}", help="Vorheriger Status"):
                                TicketService.update_ticket(t["id"], {"status": prev_status(t["status"])})
                                st.rerun()
                        with c2:
                            if st.button("➡️", key=f"right_{t['id']}", help="Nächster Status"):
                                TicketService.update_ticket(t["id"], {"status": next_status(t["status"])})
                                st.rerun()

                        cur = t.get("assignee_id")
                        a_index = 0 if cur in (None, 0) else (user_ids.index(cur) if cur in user_ids else 0)
                        assignee = c3.selectbox(
                            "Bearbeiter",
                            user_ids, index=a_index,
                            format_func=lambda v: "—" if v is None else user_map.get(v, "?"),
                            key=f"as_{t['id']}",
                            label_visibility="collapsed"
                        )

                        if is_admin:
                            arch = st.checkbox("📦 Archivieren", value=bool(t.get("archived", 0)), key=f"arch_{t['id']}")
                        else:
                            arch = bool(t.get("archived", 0))

                        if st.button("💾 Speichern", key=f"save_{t['id']}", use_container_width=True):
                            fields = {"assignee_id": assignee}
                            if is_admin:
                                fields["archived"] = int(arch)
                            TicketService.update_ticket(t["id"], **fields)
                            st.success("✅ Gespeichert")
                            st.rerun()

    def page_admin(self):
        st.header("🔧 Admin: Tickets verwalten")

        show_arch = st.checkbox("📦 Archivierte anzeigen")
        tickets = TicketService.list_tickets(archived=show_arch)

        if not tickets:
            st.info("ℹ️ Keine Tickets vorhanden")
            return

        users = UserRepository.list_active()
        user_map = {u["id"]: u["username"] for u in users}
        user_ids = [None] + [u["id"] for u in users]

        for t in tickets:
            with st.expander(f"#{t['id']} — {t['title']}", expanded=False):
                status_icon = STATUS_COLORS.get(t.get('status', ''), '⚪')
                prio_icon = PRIO_COLORS.get(t.get('priority', ''), '⚪')

                st.markdown(f"{status_icon} {prio_icon} **Ticket #{t['id']}**")
                st.caption(f"Erstellt: {format_datetime(t.get('created_at'))} | "
                           f"Aktualisiert: {format_datetime(t.get('updated_at'))}")
                st.write(t.get("description", ""))
                st.caption(f"Von: {t.get('creator_id','?')} → Bearbeiter: {t.get('assignee_id','-') or '-'}")

                st.divider()

                c1, c2, c3, c4 = st.columns(4)
                status = c1.selectbox("Status", STATI, index=safe_index(STATI, t.get("status")), key=f"st_{t['id']}")
                prio = c2.selectbox("Priorität", PRIO, index=safe_index(PRIO, t.get("priority"), 1), key=f"pr_{t['id']}")
                cat = c3.selectbox("Kategorie", CATS, index=safe_index(CATS, t.get("category")), key=f"ct_{t['id']}")

                current_assignee = t.get("assignee_id")
                assignee_index = 0 if current_assignee in (None, 0) else (user_ids.index(current_assignee) if current_assignee in user_ids else 0)
                assignee = c4.selectbox("Bearbeiter", user_ids, index=assignee_index,
                                        format_func=lambda v: "—" if v is None else user_map.get(v, "?"),
                                        key=f"as_adm_{t['id']}")

                arch = st.checkbox(f"📦 Archivieren", value=bool(t.get("archived", 0)), key=f"arch_adm_{t['id']}")

                if st.button(f"💾 Speichern", key=f"save_adm_{t['id']}", use_container_width=True):
                    TicketService.update_ticket(t["id"], status=status, priority=prio, category=cat,
                                                assignee_id=assignee, archived=int(arch))
                    st.success("✅ Gespeichert")
                    st.rerun()

    def page_database(self):
        st.header("🗄️ Datenbank (NoSQL)")
        tab1, tab2 = st.tabs(["👥 Benutzer", "🎫 Tickets"])

        with tab1:
            st.subheader("Aktive Benutzer")
            users = UserRepository.list_active()
            if users:
                df = pd.DataFrame(users)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("Keine Benutzer vorhanden")

            st.divider()

            with st.form("new_user"):
                st.subheader("➕ Neuen Benutzer anlegen")
                col1, col2, col3 = st.columns(3)
                u = col1.text_input("Username")
                p = col2.text_input("Passwort", type="password")
                r = col3.selectbox("Rolle", ["user", "admin"])

                if st.form_submit_button("✅ Anlegen", use_container_width=True):
                    if u and p:
                        AuthService.create_user(u, p, r)
                        st.success("✅ Benutzer angelegt.")
                        st.rerun()
                    else:
                        st.error("❌ Username und Passwort erforderlich.")

            st.divider()

            st.subheader("🗑️ Benutzer deaktivieren")
            if not users:
                st.info("Keine aktiven Benutzer vorhanden.")
            else:
                victim = st.selectbox("Benutzer auswählen", users, format_func=lambda x: x["username"])
                confirm = st.text_input("Zur Bestätigung Benutzernamen erneut eingeben")
                sure = st.checkbox("Ich bin sicher")
                is_self = ("user_id" in st.session_state) and (victim["id"] == st.session_state["user_id"])
                if is_self:
                    st.warning("⚠️ Du kannst dich nicht selbst deaktivieren.")
                if st.button("🗑️ Benutzer deaktivieren",
                             disabled=is_self or not sure or confirm != victim["username"],
                             type="primary"):
                    UserRepository.deactivate(victim["id"])
                    st.success(f"✅ Benutzer '{victim["username"]}' wurde deaktiviert.")
                    st.rerun()

    def page_profile(self):
        st.header("👤 Profil")
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown(f"""
            ### Angemeldet als

            **Benutzername:** {st.session_state.username}  
            **Rolle:** {st.session_state.role}
            """)
            if st.button("🚪 Logout", use_container_width=True, type="primary"):
                for k in ["user_id", "role", "username"]:
                    st.session_state.pop(k, None)
                st.success("✅ Erfolgreich abgemeldet!")
                st.rerun()

# --------------------
# Main
# --------------------
def main():
    ui = AppUI()

    # === LOGIN TEMPORÄR DEAKTIVIERT ===
    # Für temporäre Tests setzen wir automatisch eine Session (Gast/Admin).
    # Entfernen oder ändern, wenn Login wieder aktiv sein soll.
    if "user_id" not in st.session_state:
        st.session_state["user_id"] = 0
        st.session_state["username"] = "guest"
        st.session_state["role"] = "admin"  # setze zu 'user' falls du keine Admin-Rechte willst

    st.sidebar.title("🎫 Ticketsystem (NoSQL) — Testmodus: Login deaktiviert")
    st.sidebar.markdown(f"**👤 Benutzer:**  {st.session_state.get('username','-')}")
    st.sidebar.markdown(f"**🛡️ Rolle:**  {st.session_state.get('role','-')}")
    st.sidebar.divider()

    menu = ["📋 Kanban-Board", "➕ Ticket erstellen"]
    if st.session_state.get("role") == "admin":
        menu.append("🛠️ Verwaltung")

    choice = st.sidebar.radio("Navigation", menu, label_visibility="collapsed")
    st.sidebar.divider()
    if st.sidebar.button("🚪 Logout"):
        for k in ["user_id", "role", "username"]:
            st.session_state.pop(k, None)
        st.rerun()

    if choice == "📋 Kanban-Board":
        ui.page_kanban()
    elif choice == "➕ Ticket erstellen":
        ui.page_create_ticket()
    elif choice == "🛠️ Verwaltung":
        sub = st.radio("Verwaltungsbereich", ["🎫 Tickets", "👥 Benutzer"], horizontal=True)
        if sub == "🎫 Tickets":
            ui.page_admin()
        else:
            ui.page_database()

if __name__ == "__main__":
    main()
