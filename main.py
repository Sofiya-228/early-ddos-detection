"""Команды запуска экспериментов на пакетном трафике CIC-IDS2017."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PCAP = ROOT / 'data' / 'raw' / 'Friday-WorkingHours.pcap'
FEATURES = ROOT / 'data' / 'processed' / 'friday_2s.csv'
SCRIPTS = {
	'run': 'stage2.py',
	'research': 'pcap_research_next.py',
	'onset': 'pcap_check_onset.py',
}


def run_command(args: list[str]) -> None:
	result = subprocess.run(args, cwd=ROOT, check=False)
	if result.returncode:
		raise SystemExit(result.returncode)


def main() -> None:
	parser = argparse.ArgumentParser(description='Раннее обнаружение DDoS по PCAP')
	parser.add_argument(
		'command',
		choices=['check', 'prepare', 'test', 'run', 'research', 'onset'],
		help='Операция с проектом',
	)
	args = parser.parse_args()

	if args.command == 'check':
		print(f'Исходный PCAP: {"найден" if PCAP.is_file() else "отсутствует"}')
		print(f'Временные признаки: {"найдены" if FEATURES.is_file() else "отсутствуют"}')
		print(f'Python: {sys.executable}')
	elif args.command == 'prepare':
		if not PCAP.is_file():
			raise SystemExit(f'Не найден исходный PCAP: {PCAP}')
		run_command([
			'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
			'-File', str(ROOT / 'stage1.ps1'), '-PythonExe', sys.executable,
		])
	elif args.command == 'test':
		run_command([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'])
	else:
		if not FEATURES.is_file():
			raise SystemExit(f'Не найдены временные признаки: {FEATURES}. Выполни prepare.')
		run_command([sys.executable, str(ROOT / SCRIPTS[args.command])])


if __name__ == '__main__':
	main()
