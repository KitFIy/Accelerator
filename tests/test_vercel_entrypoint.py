"""Проверки ASGI-точки входа main.py и поведения в режиме Vercel."""

import asyncio

import httpx


def test_vercel_entrypoint_health_and_a04(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("AXISEC_STREAM_MAX_SECONDS", "0.05")
    from axisec.gateway.app import create_app

    app = create_app()

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://vercel") as c:
            h = await c.get("/api/health")
            idx = await c.get("/")
            a04_off = await c.post("/api/demo/run", json={"id": "A04", "protected": False})
            a04_on = await c.post("/api/demo/run", json={"id": "A04", "protected": True})
            sse = await c.get("/api/stream")
        await app.state.http.aclose()
        return h, idx, a04_off, a04_on, sse

    h, idx, a04_off, a04_on, sse = asyncio.run(go())
    assert h.status_code == 200 and h.json()["status"] == "ok"
    assert idx.status_code == 200 and b"AXI<span>SEC</span>" in idx.content
    assert a04_off.json()["harms"]
    assert a04_on.json()["harms"] == []
    assert sse.status_code == 200 and ": connected" in sse.text


def test_main_module_exports_fastapi_app():
    import main

    assert hasattr(main, "app")
    assert any(getattr(r, "path", None) == "/api/health" for r in main.app.routes)
