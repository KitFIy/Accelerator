"""Точка входа для платформ, которым нужен готовый объект ASGI-приложения (Vercel и подобные).

Локальный запуск остаётся прежним: python -m axisec
Через uvicorn напрямую:           uvicorn main:app
"""

from axisec.gateway.app import create_app

app = create_app()
