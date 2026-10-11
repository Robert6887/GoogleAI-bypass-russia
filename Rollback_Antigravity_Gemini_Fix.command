#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "======================================================================"
echo "  СБРОС СЕТЕВЫХ НАСТРОЕК ANTIGRAVITY + GEMINI (ROLLBACK)"
echo "  Сейчас macOS попросит ввести пароль администратора (sudo)"
echo "======================================================================"
sudo /usr/bin/python3 "$DIR/macos-instant-fix.py" --rollback
echo ""
read -n 1 -s -r -p "Нажмите любую клавишу, чтобы закрыть окно..."
echo ""
