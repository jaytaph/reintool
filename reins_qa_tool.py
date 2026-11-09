#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["textual>=1.0", "httpx>=0.27"]
# ///
"""
Rein's QA Tool — a terminal UI for poking at the PRS Beheer API.

Usage:
    uv run reins_qa_tool.py                                    # local, http://localhost:8512
    uv run reins_qa_tool.py --env test --cert me.crt --key me.key
    uv run reins_qa_tool.py --env test --cert me.crt --key me.key --check   # connection test only

The test environment sits behind Traefik mTLS (client cert signed by the dev mTLS CA) plus an
IP allowlist. Optionally a bearer token can be sent (--token, or fetched with --oauth-url).

Every flag has a BEHEER_* environment variable, see --help.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import random
import ssl
import string
import time
from typing import Any

import httpx
from rich.syntax import Syntax
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    SelectionList,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

ENVIRONMENTS = {
    "local": "http://localhost:8512",
    "test": "https://pseudoniemendienst.beheer.test.gf.irealisatie.nl",
}

SCOPES = ["prs:administration", "prs:pseudonym", "prs:oprf-pseudonym", "prs:saml-pseudonym"]
PERSONAL_ID_TYPES = ["oprf", "reversible_pseudonym", "irreversible_pseudonym", "personal_id"]


# --------------------------------------------------------------------------- API


class ApiError(Exception):
    def __init__(self, status: int | None, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.status or 'ERR'}: {self.detail}"


def format_detail(body: Any) -> str:
    if isinstance(body, dict) and "detail" in body:
        detail = body["detail"]
        if isinstance(detail, list):  # FastAPI validation errors
            parts = []
            for d in detail:
                loc = ".".join(str(p) for p in d.get("loc", []) if p != "body")
                parts.append(f"{loc}: {d.get('msg')}" if loc else str(d.get("msg")))
            return "; ".join(parts)
        return str(detail)
    return json.dumps(body) if not isinstance(body, str) else body


def explain_transport_error(e: Exception) -> str:
    msg = f"{type(e).__name__}: {e}"
    text = str(e).lower()
    if "certificate_required" in text or "certificate required" in text:
        return msg + " — server requires a client certificate: pass --cert/--key (signed by the dev mTLS CA)"
    if "unknown ca" in text or "bad certificate" in text or "certificate_unknown" in text:
        return msg + " — server rejected your client certificate (not signed by the expected CA?)"
    if "certificate verify failed" in text:
        return msg + " — server certificate not trusted (try --cacert)"
    if isinstance(e, httpx.ConnectTimeout):
        return msg + " — host not reachable (VPN? IP allowlist?)"
    if isinstance(e, (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError)):
        return msg + " — connection refused/reset: missing/untrusted client cert, or IP not allowlisted"
    return msg


# Some TLS alerts (e.g. TLS 1.3 "certificate required") surface as raw ssl.SSLError, not httpx errors.
TRANSPORT_ERRORS = (httpx.HTTPError, ssl.SSLError, OSError)


class OAuthConfig:
    def __init__(self, url: str, audience: str | None, scope: str | None, organization_id: str | None) -> None:
        self.url, self.audience, self.scope, self.organization_id = url, audience, scope, organization_id


class Api:
    def __init__(
        self,
        base_url: str,
        verify: ssl.SSLContext | bool,
        log: Any,
        token: str | None = None,
        oauth: OAuthConfig | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.http = httpx.AsyncClient(base_url=self.base_url, verify=verify, timeout=15.0)
        self.log = log
        self.token = token
        self.oauth = oauth

    async def fetch_token(self) -> None:
        """client_credentials grant over mTLS, same shape as get_token_prs.sh."""
        assert self.oauth is not None
        form = {"grant_type": "client_credentials"}
        if self.oauth.audience:
            form["target_audience"] = self.oauth.audience
        if self.oauth.scope:
            form["scope"] = self.oauth.scope
        if self.oauth.organization_id:
            form["organization_id"] = self.oauth.organization_id
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=15.0) as c:
                resp = await c.post(self.oauth.url, data=form)
        except TRANSPORT_ERRORS as e:
            self.log("POST", self.oauth.url, None, (time.perf_counter() - start) * 1000, None, str(e))
            raise ApiError(None, "token: " + explain_transport_error(e)) from e
        self.log("POST", self.oauth.url, resp.status_code, (time.perf_counter() - start) * 1000, None,
                 resp.text if resp.status_code >= 400 else "")
        if resp.status_code >= 400:
            raise ApiError(resp.status_code, f"token request failed: {resp.text[:300]}")
        self.token = resp.json()["access_token"]

    async def request(self, method: str, path: str, _retry: bool = True, **kwargs: Any) -> Any:
        if self.oauth and not self.token:
            await self.fetch_token()
        if self.token:
            kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.token}"
        start = time.perf_counter()
        try:
            resp = await self.http.request(method, path, **kwargs)
        except TRANSPORT_ERRORS as e:
            self.log(method, path, None, (time.perf_counter() - start) * 1000, kwargs.get("json"), str(e))
            raise ApiError(None, explain_transport_error(e)) from e
        if resp.status_code == 401 and self.oauth and _retry:
            self.token = None  # expired? fetch a fresh one and try once more
            return await self.request(method, path, _retry=False, **kwargs)

        elapsed = (time.perf_counter() - start) * 1000
        try:
            body: Any = resp.json()
        except ValueError:
            body = resp.text
        self.log(method, path, resp.status_code, elapsed, kwargs.get("json"), body)
        if resp.status_code >= 400:
            detail = format_detail(body)
            if resp.status_code == 403 and isinstance(body, str) and body.strip() == "Forbidden":
                # Plain-text 403 comes from Traefik, not the API (which answers JSON).
                detail += " — blocked by the gateway IP allowlist; connect via VPN or use kubectl port-forward"
            raise ApiError(resp.status_code, detail)
        return body

    # Organizations
    async def list_orgs(self, include_deleted: bool) -> list[dict[str, Any]]:
        return await self.request("GET", "/organizations", params={"include_deleted": include_deleted})

    async def create_org(self, data: dict[str, Any]) -> dict[str, Any]:
        return await self.request("POST", "/organizations", json=data)

    async def update_org(self, org_id: str, data: dict[str, Any]) -> dict[str, Any]:
        return await self.request("PUT", f"/organizations/{org_id}", json=data)

    async def delete_org(self, org_id: str) -> dict[str, Any]:
        return await self.request("DELETE", f"/organizations/{org_id}")

    # Clients
    async def list_clients(self, org_id: str, include_deleted: bool) -> list[dict[str, Any]]:
        return await self.request(
            "GET", f"/organizations/{org_id}/clients", params={"include_deleted": include_deleted}
        )

    async def create_client(self, org_id: str, data: dict[str, Any]) -> dict[str, Any]:
        return await self.request("POST", f"/organizations/{org_id}/clients", json=data)

    async def update_client(self, org_id: str, client_id: str, data: dict[str, Any]) -> dict[str, Any]:
        return await self.request("PUT", f"/organizations/{org_id}/clients/{client_id}", json=data)

    async def delete_client(self, org_id: str, client_id: str) -> dict[str, Any]:
        return await self.request("DELETE", f"/organizations/{org_id}/clients/{client_id}")

    # Certificates
    async def list_certs(self, org_id: str, include_deleted: bool) -> list[dict[str, Any]]:
        return await self.request(
            "GET", f"/organizations/{org_id}/certificates", params={"include_deleted": include_deleted}
        )

    async def create_cert(self, org_id: str, data: dict[str, Any]) -> dict[str, Any]:
        return await self.request("POST", f"/organizations/{org_id}/certificates", json=data)

    async def update_cert(self, org_id: str, cert_id: str, data: dict[str, Any]) -> dict[str, Any]:
        return await self.request("PUT", f"/organizations/{org_id}/certificates/{cert_id}", json=data)

    async def delete_cert(self, org_id: str, cert_id: str) -> dict[str, Any]:
        return await self.request("DELETE", f"/organizations/{org_id}/certificates/{cert_id}")

    # Misc
    async def resolve(self, data: dict[str, Any]) -> dict[str, Any]:
        return await self.request("POST", "/clients/resolve", json=data)

    async def health(self) -> Any:
        try:
            return await self.request("GET", "/health")
        except ApiError as e:
            if e.status == 503:
                return {"status": "error", "detail": e.detail}
            raise

    async def version(self) -> Any:
        return await self.request("GET", "/version.json")


# ------------------------------------------------------------------------ helpers


def random_oin() -> str:
    return "00000099" + "".join(random.choices(string.digits, k=8)) + "0000"


def short(uuid: str) -> str:
    return uuid.split("-")[0]


def status_text(obj: dict[str, Any]) -> Text:
    if obj.get("deleted_at"):
        return Text("deleted", style="bold red")
    return Text("active", style="green")


def name_text(obj: dict[str, Any], key: str = "name") -> Text:
    style = "dim strike" if obj.get("deleted_at") else ""
    return Text(str(obj.get(key, "")), style=style)


def split_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


# ------------------------------------------------------------------------ modals


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel"), Binding("y", "dismiss(True)", "Yes")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog confirm"):
            yield Label(self.question, classes="question")
            with Horizontal(classes="buttons"):
                yield Button("Yes (y)", variant="error", id="yes")
                yield Button("No (esc)", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class FormScreen(ModalScreen[dict[str, Any] | None]):
    """Base form: subclasses implement compose_fields() and collect()."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel"), Binding("ctrl+s", "save", "Save")]
    TITLE_TEXT = "Form"
    SUPPORTS_DELETED = True

    def __init__(self, values: dict[str, Any] | None = None, editing: bool = False, error: str = "") -> None:
        super().__init__()
        self.values = values or {}
        self.editing = editing
        self.error = error

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.title_text(), classes="title")
            with VerticalScroll(classes="fields"):
                yield from self.compose_fields()
                if self.editing and self.SUPPORTS_DELETED:
                    yield Label("Deleted")
                    yield Switch(value=self._initial_deleted(), id="deleted")
            yield Static(self.error, classes="error", id="error")
            with Horizontal(classes="buttons"):
                yield Button("Save (ctrl+s)", variant="primary", id="save")
                yield Button("Cancel (esc)", id="cancel")

    def title_text(self) -> str:
        return ("Edit " if self.editing else "New ") + self.TITLE_TEXT

    def on_mount(self) -> None:
        # Start typing straight away in the first field.
        inputs = self.query(Input)
        if inputs:
            inputs.first().focus()

    def _initial_deleted(self) -> bool:
        if "deleted" in self.values:
            return bool(self.values["deleted"])
        return self.values.get("deleted_at") is not None

    def compose_fields(self) -> ComposeResult:
        raise NotImplementedError

    def collect(self) -> dict[str, Any]:
        raise NotImplementedError

    def selection(self, id_: str, options: list[str], selected: list[str]) -> SelectionList[str]:
        return SelectionList[str](*[(o, o, o in selected) for o in options], id=id_)

    def val(self, id_: str) -> str:
        return self.query_one(f"#{id_}", Input).value.strip()

    def sel(self, id_: str) -> list[str]:
        return list(self.query_one(f"#{id_}", SelectionList).selected)

    def action_save(self) -> None:
        data = self.collect()
        if self.editing and self.SUPPORTS_DELETED:
            data["deleted"] = self.query_one("#deleted", Switch).value
        self.dismiss(data)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        else:
            self.dismiss(None)


class OrganizationForm(FormScreen):
    TITLE_TEXT = "Organization"

    def compose_fields(self) -> ComposeResult:
        v = self.values
        yield Label("External ID (OIN, 20 chars)")
        yield Input(value=v.get("external_id", random_oin()), id="external_id")
        yield Label("Name")
        yield Input(value=v.get("name", ""), placeholder="Org name", id="name")
        yield Label("Scopes")
        yield self.selection("scopes", SCOPES, v.get("scopes", SCOPES))
        yield Label("Receive personal ID types")
        yield self.selection("receive", PERSONAL_ID_TYPES, v.get("receive_personal_id_types", PERSONAL_ID_TYPES))
        yield Label("Request personal ID types")
        yield self.selection("request", PERSONAL_ID_TYPES, v.get("request_personal_id_types", PERSONAL_ID_TYPES))

    def collect(self) -> dict[str, Any]:
        return {
            "external_id": self.val("external_id"),
            "name": self.val("name"),
            "scopes": self.sel("scopes"),
            "receive_personal_id_types": self.sel("receive"),
            "request_personal_id_types": self.sel("request"),
        }


class CertificateForm(FormScreen):
    TITLE_TEXT = "Certificate"
    SUPPORTS_DELETED = False  # certificates are removed with DELETE, PUT has no deleted flag

    def compose_fields(self) -> ComposeResult:
        v = self.values
        yield Label("Organization identifier (from the certificate)")
        yield Input(value=v.get("organization_identifier", ""), id="organization_identifier")
        yield Label("Domain (certificate CN or SAN)")
        yield Input(value=v.get("domain", ""), placeholder="client.example.com", id="domain")

    def collect(self) -> dict[str, Any]:
        return {"organization_identifier": self.val("organization_identifier"), "domain": self.val("domain")}


class ClientForm(FormScreen):
    TITLE_TEXT = "Client"

    def __init__(self, certs: list[dict[str, Any]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.certs = certs

    def compose_fields(self) -> ComposeResult:
        v = self.values
        yield Label("Name")
        yield Input(value=v.get("name", ""), placeholder="My Client", id="name")
        yield Label("Scopes")
        yield self.selection("scopes", SCOPES, v.get("scopes", []))
        yield Label("Request personal ID types")
        yield self.selection("request", PERSONAL_ID_TYPES, v.get("request_personal_id_types", []))
        yield Label("Certificates")
        selected = v.get("certificates", [])
        if self.certs:
            yield SelectionList[str](
                *[
                    (f"{c['domain']}  [{short(c['id'])}]" + ("  (deleted)" if c.get("deleted_at") else ""),
                     c["id"], c["id"] in selected)
                    for c in self.certs
                ],
                id="certificates",
            )
        else:
            yield Static("No certificates registered for this organization.", classes="hint")

    def collect(self) -> dict[str, Any]:
        certs = self.sel("certificates") if self.certs else []
        return {
            "name": self.val("name"),
            "scopes": self.sel("scopes"),
            "request_personal_id_types": self.sel("request"),
            "certificates": certs,
        }


class ResolveForm(FormScreen):
    SUPPORTS_DELETED = False

    def title_text(self) -> str:
        return "Resolve client  (POST /clients/resolve)"

    def compose_fields(self) -> ComposeResult:
        v = self.values
        yield Label("Client ID")
        yield Input(value=v.get("client_id", ""), id="client_id")
        yield Label("Organization external ID (OIN)")
        yield Input(value=v.get("organization_external_id", ""), id="organization_external_id")
        yield Label("Certificate domains (comma separated)")
        yield Input(value=", ".join(v.get("certificate_domains", [])), id="certificate_domains")
        yield Label("Certificate organization identifier")
        yield Input(
            value=v.get("certificate_organization_identifier", ""), id="certificate_organization_identifier"
        )

    def collect(self) -> dict[str, Any]:
        return {
            "client_id": self.val("client_id"),
            "organization_external_id": self.val("organization_external_id"),
            "certificate_domains": split_csv(self.val("certificate_domains")),
            "certificate_organization_identifier": self.val("certificate_organization_identifier"),
        }


# --------------------------------------------------------------------------- app


class ReinsQATool(App[None]):
    TITLE = "Rein's QA Tool"

    CSS = """
    #main { height: 1fr; }
    #left { width: 45%; border: round $primary; }
    #right { width: 1fr; }
    #tabs { height: 1fr; border: round $secondary; }
    #details-box { height: 1fr; border: round $accent; }
    #log { height: 10; border: round $panel; }
    #log.hidden { display: none; }
    .pane-title { padding: 0 1; text-style: bold; color: $text-muted; }
    DataTable { height: 1fr; }

    ModalScreen { align: center middle; background: $background 60%; }
    .dialog {
        width: 80; max-width: 95%; height: auto; max-height: 90%;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    .dialog.confirm { width: 60; }
    .dialog .title { text-style: bold; color: $accent; margin-bottom: 1; }
    .dialog .question { margin-bottom: 1; }
    .dialog .fields { height: auto; max-height: 30; }
    .dialog Label { margin-top: 1; }
    .dialog SelectionList { height: auto; max-height: 8; }
    .dialog .error { color: $error; height: auto; margin-top: 1; }
    .dialog .hint { color: $text-muted; }
    .buttons { height: auto; margin-top: 1; align-horizontal: right; }
    .buttons Button { margin-left: 1; }
    """

    BINDINGS = [
        Binding("n", "new", "New"),
        Binding("e", "edit", "Edit"),
        Binding("d", "delete", "Delete"),
        Binding("r", "refresh", "Refresh"),
        Binding("x", "toggle_deleted", "Show deleted"),
        Binding("v", "resolve", "Resolve"),
        Binding("g", "generate", "Demo data"),
        Binding("h", "health", "Health"),
        Binding("c", "copy_id", "Copy ID"),
        Binding("l", "toggle_log", "Log"),
        Binding("1", "focus_table('orgs')", "Orgs", show=False),
        Binding("2", "focus_table('clients')", "Clients", show=False),
        Binding("3", "focus_table('certs')", "Certs", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, api: Api) -> None:
        super().__init__()
        self.api = api
        self.api.log = self.log_request
        self.include_deleted = False
        self.orgs: dict[str, dict[str, Any]] = {}
        self.clients: dict[str, dict[str, Any]] = {}
        self.certs: dict[str, dict[str, Any]] = {}
        self.current_org_id: str | None = None
        self.last_table = "orgs"

    # ------------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Label("Organizations  [1]", classes="pane-title")
                yield DataTable(id="orgs", cursor_type="row", zebra_stripes=True)
            with Vertical(id="right"):
                with TabbedContent(id="tabs"):
                    with TabPane("Clients [2]", id="tab-clients"):
                        yield DataTable(id="clients", cursor_type="row", zebra_stripes=True)
                    with TabPane("Certificates [3]", id="tab-certs"):
                        yield DataTable(id="certs", cursor_type="row", zebra_stripes=True)
                with VerticalScroll(id="details-box"):
                    yield Static("Select something…", id="details")
        yield RichLog(id="log", markup=True, wrap=False, highlight=False)
        yield Footer()

    async def on_mount(self) -> None:
        self.sub_title = self.api.base_url
        self.query_one("#orgs", DataTable).add_columns("Name", "External ID", "Scopes", "Status")
        self.query_one("#clients", DataTable).add_columns("Name", "Scopes", "ID types", "Certs", "Status", "ID")
        self.query_one("#certs", DataTable).add_columns("Domain", "Org identifier", "Status", "ID")
        self.query_one("#log", RichLog).border_title = "HTTP log"
        self.query_one("#details-box").border_title = "Details"
        self.query_one("#orgs").focus()
        self.check_server()
        self.load_orgs()

    # Our own main-screen shortcuts; built-in app actions (focus_next for tab, etc.) must stay enabled.
    MAIN_SCREEN_ACTIONS = frozenset(
        {"new", "edit", "delete", "refresh", "toggle_deleted", "resolve", "generate", "health", "copy_id",
         "toggle_log", "focus_table"}
    )

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # Don't let main-screen shortcuts fire while a dialog is open.
        if action in self.MAIN_SCREEN_ACTIONS and isinstance(self.screen, ModalScreen):
            return False
        return True

    # ------------------------------------------------------------------ logging

    def log_request(
        self, method: str, path: str, status: int | None, ms: float, payload: Any, body: Any
    ) -> None:
        log = self.query_one("#log", RichLog)
        if status is None:
            colour = "red"
        elif status >= 500:
            colour = "red"
        elif status >= 400:
            colour = "yellow"
        else:
            colour = "green"
        ts = time.strftime("%H:%M:%S")
        log.write(
            Text.from_markup(
                f"[dim]{ts}[/] [bold]{method:6}[/] {path}  [{colour}]{status or 'ERR'}[/]  [dim]{ms:.0f}ms[/]"
            )
        )
        if status is None or status >= 400:
            log.write(Text(f"         {format_detail(body)}", style=colour))

    def report(self, err: ApiError, action: str) -> None:
        self.notify(str(err.detail), title=f"{action} failed ({err.status or 'no response'})", severity="error",
                    timeout=8)

    # ------------------------------------------------------------------ details

    def show_details(self, obj: Any, title: str = "Details") -> None:
        self.query_one("#details-box").border_title = title
        self.query_one("#details", Static).update(
            Syntax(json.dumps(obj, indent=2, default=str), "json", theme="monokai", word_wrap=True)
        )

    # ------------------------------------------------------------------ table helpers

    @staticmethod
    def selected_key(table: DataTable) -> str | None:
        if table.row_count == 0:
            return None
        try:
            return str(table.coordinate_to_cell_key(Coordinate(table.cursor_row, 0)).row_key.value)
        except Exception:
            return None

    @staticmethod
    def select_key(table: DataTable, key: str | None) -> None:
        if key is None:
            return
        try:
            table.move_cursor(row=table.get_row_index(key))
        except Exception:
            pass

    def active_entity(self) -> str:
        focused = self.focused
        if isinstance(focused, DataTable) and focused.id in ("orgs", "clients", "certs"):
            return focused.id
        return self.last_table

    def on_descendant_focus(self, event: Any) -> None:
        widget = event.widget if hasattr(event, "widget") else None
        if isinstance(widget, DataTable) and widget.id:
            self.last_table = widget.id

    def action_focus_table(self, table_id: str) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        if table_id == "clients":
            tabs.active = "tab-clients"
        elif table_id == "certs":
            tabs.active = "tab-certs"
        self.query_one(f"#{table_id}", DataTable).focus()

    # ------------------------------------------------------------------ loading

    @work(exclusive=True, group="server")
    async def check_server(self) -> None:
        parts = [self.api.base_url]
        try:
            ver = await self.api.version()
            if isinstance(ver, dict):
                parts.append(f"v{ver.get('version', '?')} ({str(ver.get('git_ref', ''))[:8]})")
        except ApiError:
            pass
        try:
            health = await self.api.health()
            parts.append(f"health: {health.get('status', '?')}")
        except ApiError as e:
            parts.append("unreachable")
            self.report(e, "Connect")
        self.sub_title = "  ·  ".join(parts)

    @work(exclusive=True, group="orgs")
    async def load_orgs(self, select_id: str | None = None) -> None:
        table = self.query_one("#orgs", DataTable)
        keep = select_id or self.selected_key(table)
        try:
            orgs = await self.api.list_orgs(self.include_deleted)
        except ApiError as e:
            self.report(e, "Loading organizations")
            return
        self.orgs = {o["id"]: o for o in orgs}
        table.clear()
        for o in sorted(orgs, key=lambda o: o.get("name", "").lower()):
            table.add_row(name_text(o), o.get("external_id", ""), str(len(o.get("scopes", []))), status_text(o),
                          key=o["id"])
        self.select_key(table, keep)
        if not orgs:
            self.current_org_id = None
            self.query_one("#clients", DataTable).clear()
            self.query_one("#certs", DataTable).clear()
            self.query_one("#details", Static).update("No organizations yet — press [b]n[/b] to create one, "
                                                      "or [b]g[/b] to generate demo data.")

    @work(exclusive=True, group="children")
    async def load_children(self, select_client: str | None = None, select_cert: str | None = None) -> None:
        org_id = self.current_org_id
        clients_t = self.query_one("#clients", DataTable)
        certs_t = self.query_one("#certs", DataTable)
        keep_client = select_client or self.selected_key(clients_t)
        keep_cert = select_cert or self.selected_key(certs_t)
        if org_id is None:
            clients_t.clear()
            certs_t.clear()
            return
        try:
            certs = await self.api.list_certs(org_id, self.include_deleted)
            clients = await self.api.list_clients(org_id, self.include_deleted)
        except ApiError as e:
            self.report(e, "Loading clients/certificates")
            return
        if org_id != self.current_org_id:
            return  # user moved on in the meantime

        self.certs = {c["id"]: c for c in certs}
        certs_t.clear()
        for c in certs:
            certs_t.add_row(name_text(c, "domain"), c.get("organization_identifier", ""), status_text(c),
                            short(c["id"]), key=c["id"])
        self.select_key(certs_t, keep_cert)

        self.clients = {c["id"]: c for c in clients}
        clients_t.clear()
        for c in clients:
            cert_domains = [self.certs.get(cid, {}).get("domain", short(cid)) for cid in c.get("certificates", [])]
            clients_t.add_row(
                name_text(c),
                ", ".join(s.removeprefix("prs:") for s in c.get("scopes", [])),
                ", ".join(c.get("request_personal_id_types", [])),
                ", ".join(cert_domains) or "-",
                status_text(c),
                short(c["id"]),
                key=c["id"],
            )
        self.select_key(clients_t, keep_client)

        tabs = self.query_one("#tabs", TabbedContent)
        tabs.get_tab("tab-clients").label = f"Clients ({len(clients)}) [2]"
        tabs.get_tab("tab-certs").label = f"Certificates ({len(certs)}) [3]"

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        key = str(event.row_key.value) if event.row_key is not None else None
        if key is None:
            return
        table_id = event.data_table.id
        if table_id == "orgs" and key in self.orgs:
            self.show_details(self.orgs[key], f"Organization · {self.orgs[key].get('name')}")
            if key != self.current_org_id:
                self.current_org_id = key
                self.load_children()
        elif table_id == "clients" and key in self.clients:
            self.show_details(self.clients[key], f"Client · {self.clients[key].get('name')}")
        elif table_id == "certs" and key in self.certs:
            self.show_details(self.certs[key], f"Certificate · {self.certs[key].get('domain')}")

    # ------------------------------------------------------------------ actions

    def action_refresh(self) -> None:
        self.check_server()
        self.load_orgs()
        self.load_children()
        self.notify("Refreshed", timeout=1.5)

    def action_toggle_deleted(self) -> None:
        self.include_deleted = not self.include_deleted
        self.notify(f"Including deleted: {'yes' if self.include_deleted else 'no'}", timeout=2)
        self.load_orgs()
        self.load_children()

    def action_toggle_log(self) -> None:
        self.query_one("#log").toggle_class("hidden")

    def action_copy_id(self) -> None:
        entity = self.active_entity()
        key = self.selected_key(self.query_one(f"#{entity}", DataTable))
        if key:
            self.copy_to_clipboard(key)
            self.notify(f"Copied {key}", timeout=2)

    def require_org(self) -> str | None:
        if self.current_org_id is None:
            self.notify("Select an organization first", severity="warning")
        return self.current_org_id

    @work(exclusive=True, group="dialog")
    async def action_new(self) -> None:
        entity = self.active_entity()
        values: dict[str, Any] = {}
        error = ""
        while True:
            if entity == "orgs":
                data = await self.push_screen_wait(OrganizationForm(values=values, error=error))
                if data is None:
                    return
                try:
                    org = await self.api.create_org(data)
                except ApiError as e:
                    values, error = data, str(e)
                    continue
                self.notify(f"Organization '{org['name']}' created")
                self.load_orgs(select_id=org["id"])
                return

            org_id = self.require_org()
            if org_id is None:
                return
            if entity == "certs":
                if not values:
                    values = {"organization_identifier": self.orgs[org_id].get("external_id", "")}
                data = await self.push_screen_wait(CertificateForm(values=values, error=error))
                if data is None:
                    return
                try:
                    cert = await self.api.create_cert(org_id, data)
                except ApiError as e:
                    values, error = data, str(e)
                    continue
                self.notify(f"Certificate '{cert['domain']}' created")
                self.load_children(select_cert=cert["id"])
                return

            # clients
            if not values:
                org = self.orgs[org_id]
                values = {
                    "scopes": org.get("scopes", []),
                    "request_personal_id_types": org.get("request_personal_id_types", []),
                }
            certs = [c for c in self.certs.values() if not c.get("deleted_at")]
            data = await self.push_screen_wait(ClientForm(certs, values=values, error=error))
            if data is None:
                return
            try:
                client = await self.api.create_client(org_id, data)
            except ApiError as e:
                values, error = data, str(e)
                continue
            self.notify(f"Client '{client['name']}' created")
            self.load_children(select_client=client["id"])
            return

    @work(exclusive=True, group="dialog")
    async def action_edit(self) -> None:
        entity = self.active_entity()
        table = self.query_one(f"#{entity}", DataTable)
        key = self.selected_key(table)
        if key is None:
            self.notify("Nothing selected", severity="warning")
            return
        error = ""

        if entity == "orgs":
            values: dict[str, Any] = dict(self.orgs[key])
            while True:
                data = await self.push_screen_wait(OrganizationForm(values=values, editing=True, error=error))
                if data is None:
                    return
                try:
                    await self.api.update_org(key, data)
                except ApiError as e:
                    values, error = data, str(e)
                    continue
                self.notify("Organization updated")
                self.load_orgs(select_id=key)
                self.show_details(data)
                return

        org_id = self.require_org()
        if org_id is None:
            return
        if entity == "certs":
            values = dict(self.certs[key])
            while True:
                data = await self.push_screen_wait(CertificateForm(values=values, editing=True, error=error))
                if data is None:
                    return
                try:
                    await self.api.update_cert(org_id, key, data)
                except ApiError as e:
                    values, error = data, str(e)
                    continue
                self.notify("Certificate updated")
                self.load_children(select_cert=key)
                return

        values = dict(self.clients[key])
        while True:
            data = await self.push_screen_wait(
                ClientForm(list(self.certs.values()), values=values, editing=True, error=error)
            )
            if data is None:
                return
            try:
                await self.api.update_client(org_id, key, data)
            except ApiError as e:
                values, error = data, str(e)
                continue
            self.notify("Client updated")
            self.load_children(select_client=key)
            return

    @work(exclusive=True, group="dialog")
    async def action_delete(self) -> None:
        entity = self.active_entity()
        key = self.selected_key(self.query_one(f"#{entity}", DataTable))
        if key is None:
            self.notify("Nothing selected", severity="warning")
            return
        label = {
            "orgs": lambda: f"organization '{self.orgs[key]['name']}'",
            "clients": lambda: f"client '{self.clients[key]['name']}'",
            "certs": lambda: f"certificate '{self.certs[key]['domain']}'",
        }[entity]()
        if not await self.push_screen_wait(ConfirmScreen(f"Delete {label}?")):
            return
        try:
            if entity == "orgs":
                await self.api.delete_org(key)
                self.load_orgs()
            elif entity == "clients" and self.current_org_id:
                await self.api.delete_client(self.current_org_id, key)
                self.load_children()
            elif entity == "certs" and self.current_org_id:
                await self.api.delete_cert(self.current_org_id, key)
                self.load_children()
        except ApiError as e:
            self.report(e, "Delete")
            return
        self.notify(f"Deleted {label}")

    @work(exclusive=True, group="dialog")
    async def action_resolve(self) -> None:
        values: dict[str, Any] = {}
        org = self.orgs.get(self.current_org_id or "")
        if org:
            values["organization_external_id"] = org.get("external_id", "")
        client_key = self.selected_key(self.query_one("#clients", DataTable))
        client = self.clients.get(client_key or "")
        if client:
            values["client_id"] = client["id"]
            first_cert = next((self.certs[c] for c in client.get("certificates", []) if c in self.certs), None)
            if first_cert:
                values["certificate_domains"] = [first_cert["domain"]]
                values["certificate_organization_identifier"] = first_cert["organization_identifier"]
        error = ""
        while True:
            data = await self.push_screen_wait(ResolveForm(values=values, error=error))
            if data is None:
                return
            try:
                result = await self.api.resolve(data)
            except ApiError as e:
                values, error = data, str(e)
                continue
            self.show_details({"request": data, "response": result}, "Resolve result ✔")
            self.notify(f"Resolved: matched {result.get('matched_domain')}", title="Resolve OK")
            return

    @work(exclusive=True, group="dialog")
    async def action_health(self) -> None:
        try:
            health = await self.api.health()
            version = await self.api.version()
        except ApiError as e:
            self.report(e, "Health")
            return
        self.show_details({"health": health, "version": version}, "Server")
        sev = "information" if health.get("status") == "ok" else "error"
        self.notify(f"Health: {health.get('status')}", severity=sev)

    @work(exclusive=True, group="dialog")
    async def action_generate(self) -> None:
        if not await self.push_screen_wait(
            ConfirmScreen("Generate a demo organization with a certificate and a client?")
        ):
            return
        tag = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
        try:
            org = await self.api.create_org({
                "external_id": random_oin(),
                "name": f"QA Org {tag}",
                "scopes": SCOPES,
                "receive_personal_id_types": PERSONAL_ID_TYPES,
                "request_personal_id_types": PERSONAL_ID_TYPES,
            })
            cert = await self.api.create_cert(org["id"], {
                "organization_identifier": org["external_id"],
                "domain": f"qa-{tag}.example.com",
            })
            await self.api.create_client(org["id"], {
                "name": f"QA Client {tag}",
                "scopes": SCOPES,
                "request_personal_id_types": PERSONAL_ID_TYPES,
                "certificates": [cert["id"]],
            })
        except ApiError as e:
            self.report(e, "Generate")
            self.load_orgs()
            return
        self.notify(f"Created QA Org {tag}", title="Demo data")
        self.load_orgs(select_id=org["id"])

    async def on_unmount(self) -> None:
        await self.api.http.aclose()


# --------------------------------------------------------------------------- main


def build_ssl(
    cert: str | None, key: str | None, key_password: str | None, cacert: str | None, insecure: bool
) -> ssl.SSLContext | bool:
    if not (cert or cacert or insecure):
        return True
    ctx = ssl.create_default_context(cafile=cacert)
    if cert:
        # Only prompts when the key is actually encrypted.
        password = key_password or (lambda: getpass.getpass(f"Passphrase for {key or cert}: "))
        ctx.load_cert_chain(cert, key, password=password)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def check_connection(api: Api) -> int:
    def log(method: str, path: str, status: int | None, ms: float, _payload: Any, body: Any) -> None:
        print(f"{method:6} {path}  {status or 'ERR'}  {ms:.0f}ms")
        if status is None or status >= 400:
            print(f"       {format_detail(body)}")

    api.log = log
    print(f"Checking {api.base_url} …")
    ok = True
    for name, call in (("version", api.version), ("health", api.health),
                       ("organizations", lambda: api.list_orgs(False))):
        try:
            result = await call()
            summary = f"{len(result)} found" if isinstance(result, list) else json.dumps(result)[:200]
            print(f"  ✔ {name}: {summary}")
        except ApiError as e:
            ok = False
            print(f"  ✘ {name}: {e}")
    await api.http.aclose()
    return 0 if ok else 1


def main() -> None:
    env = os.environ.get
    parser = argparse.ArgumentParser(
        description="Rein's QA Tool — TUI for the PRS Beheer API",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    conn = parser.add_argument_group("connection")
    conn.add_argument("--env", choices=sorted(ENVIRONMENTS), default=env("BEHEER_ENV"),
                      help="preset base URL [BEHEER_ENV]")
    conn.add_argument("--url", default=env("BEHEER_URL"), help="base URL, overrides --env [BEHEER_URL]")
    conn.add_argument("--check", action="store_true", help="test the connection and exit, no TUI")

    tls = parser.add_argument_group("mTLS")
    tls.add_argument("--cert", default=env("BEHEER_CERT"), help="client certificate PEM [BEHEER_CERT]")
    tls.add_argument("--key", default=env("BEHEER_KEY"), help="client key PEM [BEHEER_KEY]")
    tls.add_argument("--key-password", default=env("BEHEER_KEY_PASSWORD"),
                     help="key passphrase, prompted if needed [BEHEER_KEY_PASSWORD]")
    tls.add_argument("--cacert", default=env("BEHEER_CACERT"), help="CA bundle to verify the server [BEHEER_CACERT]")
    tls.add_argument("--insecure", action="store_true", help="skip server TLS verification")

    auth = parser.add_argument_group("bearer token (optional)")
    auth.add_argument("--token", default=env("BEHEER_TOKEN"), help="static bearer token [BEHEER_TOKEN]")
    auth.add_argument("--oauth-url", default=env("BEHEER_OAUTH_URL"),
                      help="fetch a token via client_credentials (mTLS) from this URL [BEHEER_OAUTH_URL]")
    auth.add_argument("--oauth-audience", default=env("BEHEER_OAUTH_AUDIENCE"),
                      help="target_audience [BEHEER_OAUTH_AUDIENCE]")
    auth.add_argument("--oauth-scope", default=env("BEHEER_OAUTH_SCOPE", "prs:administration"),
                      help="scope [BEHEER_OAUTH_SCOPE]")
    auth.add_argument("--oauth-org", default=env("BEHEER_OAUTH_ORG"),
                      help="organization_id (OIN) [BEHEER_OAUTH_ORG]")
    args = parser.parse_args()

    url = args.url or ENVIRONMENTS[args.env or "local"]
    if url.startswith("https://") and not args.cert:
        print("warning: no --cert/--key given; remote beheer environments require mTLS.")
    oauth = OAuthConfig(args.oauth_url, args.oauth_audience, args.oauth_scope, args.oauth_org) \
        if args.oauth_url else None
    try:
        verify = build_ssl(args.cert, args.key, args.key_password, args.cacert, args.insecure)
    except (OSError, ssl.SSLError) as e:
        raise SystemExit(f"Could not load client certificate/key: {e}")
    api = Api(url, verify, log=lambda *a: None, token=args.token, oauth=oauth)

    if args.check:
        import asyncio
        raise SystemExit(asyncio.run(check_connection(api)))
    ReinsQATool(api).run()


if __name__ == "__main__":
    main()
