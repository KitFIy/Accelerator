"""Запуск: python -m axisec [--host 0.0.0.0] [--port 8080]"""

import argparse

import uvicorn

from .gateway.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="axisec", description="Шлюз контроля действий ИИ-агентов")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--policy", default=None, help="путь к YAML-файлу политики")
    args = parser.parse_args()
    uvicorn.run(create_app(args.policy), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
