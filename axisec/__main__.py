"""Запуск: python -m axisec [--host 0.0.0.0] [--port 8080] [--workers 1] [--mode enforce|observe]"""

import argparse
import os

import uvicorn

from .env import load_dotenv
from .gateway.app import create_app


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="axisec", description="Шлюз контроля действий ИИ-агентов")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--policy", default=None, help="путь к YAML-файлу политики")
    parser.add_argument("--mode", choices=["enforce", "observe"], default=None, help="режим работы политики")
    parser.add_argument("--workers", type=int, default=1, help="число воркеров Uvicorn")
    args = parser.parse_args()
    if args.workers > 1:
        if args.policy:
            os.environ["AXISEC_POLICY"] = args.policy
        if args.mode:
            os.environ["AXISEC_MODE"] = args.mode
        uvicorn.run("axisec.gateway.app:create_app", factory=True, host=args.host, port=args.port,
                    workers=args.workers, log_level="warning")
    else:
        uvicorn.run(create_app(args.policy, mode_override=args.mode), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
