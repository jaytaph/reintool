# /// script
# requires-python = ">=3.11"
# dependencies = ["textual>=1.0", "httpx>=0.27"]
# ///
import asyncio, json, sys, uuid, re
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
import httpx
import reins_qa_tool as t

DB = {"orgs": {}, "certs": {}, "clients": {}}
def now(): return "2026-11-09T12:00:00"
def handler(req: httpx.Request):
    p, m = req.url.path, req.method
    body = json.loads(req.content) if req.content else None
    if p == "/health": return httpx.Response(200, json={"status": "ok", "components": {"database": "ok"}})
    if p == "/version.json": return httpx.Response(200, json={"version": "1.2.3", "git_ref": "abcdef123456"})
    if p == "/clients/resolve": return httpx.Response(200, json={"scopes": "prs:pseudonym", "matched_domain": body["certificate_domains"][0]})
    if p == "/organizations":
        if m == "GET": return httpx.Response(200, json=list(DB["orgs"].values()))
        if len(body["external_id"]) != 20: return httpx.Response(422, json={"detail": [{"loc": ["body","external_id"], "msg": "Invalid OIN"}]})
        o = {**body, "id": str(uuid.uuid4()), "created_at": now(), "updated_at": now()}; DB["orgs"][o["id"]] = o
        return httpx.Response(201, json=o)
    mm = re.match(r"/organizations/([^/]+)/(clients|certificates)(?:/([^/]+))?$", p)
    if mm:
        oid, kind, iid = mm.groups(); store = DB["clients" if kind == "clients" else "certs"]
        if m == "GET": return httpx.Response(200, json=[x for x in store.values() if x["organization_id"] == oid])
        if m == "POST":
            x = {**body, "id": str(uuid.uuid4()), "organization_id": oid, "created_at": now(), "updated_at": now()}; store[x["id"]] = x
            return httpx.Response(201, json=x)
        if m == "DELETE": return httpx.Response(200, json=store.pop(iid))
        if m == "PUT": store[iid].update(body); return httpx.Response(200, json=store[iid])
    mm = re.match(r"/organizations/([^/]+)$", p)
    if mm:
        oid = mm.group(1)
        if m == "DELETE":
            if any(c["organization_id"] == oid for c in DB["clients"].values()):
                return httpx.Response(403, json={"detail": "Organization has active clients"})
            return httpx.Response(200, json=DB["orgs"].pop(oid))
        if m == "PUT": DB["orgs"][oid].update(body); return httpx.Response(200, json=DB["orgs"][oid])
    return httpx.Response(404, json={"detail": "nope"})

async def main():
    api = t.Api("http://fake", True, log=None)
    api.http = httpx.AsyncClient(base_url="http://fake", transport=httpx.MockTransport(handler))
    app = t.ReinsQATool(api)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause(0.3)
        print("subtitle:", app.sub_title)
        # generate demo data
        await pilot.press("g"); await pilot.pause(0.2); await pilot.press("y"); await pilot.pause(0.5)
        print("orgs:", len(DB["orgs"]), "certs:", len(DB["certs"]), "clients:", len(DB["clients"]))
        print("client rows:", app.query_one("#clients").row_count, "cert rows:", app.query_one("#certs").row_count)
        # new org with invalid OIN -> error then form reopens
        await pilot.press("1"); await pilot.press("n"); await pilot.pause(0.2)
        inp = app.screen.query_one("#external_id"); inp.value = "123"
        app.screen.query_one("#name").value = "Bad Org"
        await pilot.press("ctrl+s"); await pilot.pause(0.3)
        print("reopened with error:", type(app.screen).__name__, str(app.screen.query_one("#error").render()))
        app.screen.query_one("#external_id").value = t.random_oin()
        await pilot.press("ctrl+s"); await pilot.pause(0.4)
        print("orgs after create:", len(DB["orgs"]), "screen:", type(app.screen).__name__)
        # delete org with clients -> 403
        await pilot.press("1"); await pilot.pause(0.1)
        app.select_key(app.query_one("#orgs"), next(k for k,o in DB["orgs"].items() if o["name"].startswith("QA")))
        await pilot.pause(0.3)
        await pilot.press("d"); await pilot.pause(0.2); await pilot.press("y"); await pilot.pause(0.3)
        print("notifications:", [n.message for n in app._notifications][-2:])
        # edit client
        await pilot.press("2"); await pilot.pause(0.1); await pilot.press("e"); await pilot.pause(0.2)
        print("edit screen:", type(app.screen).__name__, "has deleted switch:", bool(app.screen.query("#deleted")))
        app.screen.query_one("#name").value = "Renamed"
        await pilot.press("ctrl+s"); await pilot.pause(0.3)
        print("client names:", [c["name"] for c in DB["clients"].values()], "deleted flag:", [c.get("deleted") for c in DB["clients"].values()])
        # cert edit has no deleted switch
        await pilot.press("3"); await pilot.pause(0.1); await pilot.press("e"); await pilot.pause(0.2)
        print("cert edit:", type(app.screen).__name__, "deleted switch:", bool(app.screen.query("#deleted")), app.screen.query_one(".title").render())
        await pilot.press("escape"); await pilot.pause(0.1)
        # resolve prefilled
        await pilot.press("2"); await pilot.press("v"); await pilot.pause(0.2)
        print("resolve prefill:", app.screen.collect())
        await pilot.press("ctrl+s"); await pilot.pause(0.3)
        print("details title:", app.query_one("#details-box").border_title)
        app.save_screenshot("shot.svg", path=str(__import__("pathlib").Path(__file__).resolve().parent))

async def oauth_test():
    seen = {"tokens": 0, "auth": []}
    def h(req):
        if req.url.path == "/token":
            seen["tokens"] += 1
            return httpx.Response(200, json={"access_token": f"tok{seen['tokens']}"})
        seen["auth"].append(req.headers.get("authorization"))
        if req.headers.get("authorization") == "Bearer tok1":
            return httpx.Response(401, json={"detail": "expired"})
        return httpx.Response(200, json=[])
    api = t.Api("http://fake", True, log=lambda *a: None, oauth=t.OAuthConfig("http://fake/token", "aud", "prs:administration", "x"))
    tr = httpx.MockTransport(h)
    api.http = httpx.AsyncClient(base_url="http://fake", transport=tr)
    orig = httpx.AsyncClient
    t.httpx.AsyncClient = lambda **kw: orig(transport=tr, **{k:v for k,v in kw.items() if k!="verify"})
    print("oauth result:", await api.list_orgs(False), seen)
    t.httpx.AsyncClient = orig

if __name__ == "__main__": asyncio.run(main())
if __name__ == "__main__": asyncio.run(oauth_test())
