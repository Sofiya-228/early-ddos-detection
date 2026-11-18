"""Проверка гипотезы об атаке на основании реальных адресов из официального CIC-IDS2017.
Не доказывает класс автоматически: NAT и маршрут в захвате могут менять адреса.
"""
from collections import Counter
from datetime import datetime
from pathlib import Path
import csv, json, shutil, subprocess, tempfile
ROOT = Path(__file__).resolve().parent
CFG = json.loads((ROOT / 'config.json').read_text(encoding='utf-8'))
START = int(datetime.fromisoformat(CFG['candidate_attack_start']).timestamp())
END = int(datetime.fromisoformat(CFG['candidate_attack_end']).timestamp())
ATTACKERS = {'205.174.165.69', '205.174.165.70', '205.174.165.71'}
VICTIMS = {'205.174.165.68', '192.168.10.50', '172.16.0.1'}
PCAP = ROOT / 'data/processed/friday_excerpt.pcap'
if not PCAP.exists():
	raise SystemExit('Сначала выполните stage1.ps1')
tshark = shutil.which('tshark') or 'C:\\Program Files\\Wireshark\\tshark.exe'
args = [tshark, '-n', '-r', str(PCAP), '-Y', 'ip', '-T', 'fields', '-E', 'occurrence=f', '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst']
counts = {s: {'n': 0, 'known_attacker': 0, 'known_victim': 0, 'top_src': Counter(), 'top_dst': Counter()} for s in ['pre', 'attack', 'post']}
with tempfile.TemporaryFile(mode='w+t', encoding='utf-8') as err:
	proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err, text=True, encoding='utf-8', errors='replace')
	for row in csv.reader(proc.stdout, delimiter='\t'):
		if len(row) < 3:
			continue
		try:
			t = float(row[0])
		except ValueError:
			continue
		k = 'pre' if t < START else 'attack' if t < END else 'post'
		c = counts[k]
		src = row[1].strip()
		dst = row[2].strip()
		c['n'] += 1
		c['known_attacker'] += int(src in ATTACKERS or dst in ATTACKERS)
		c['known_victim'] += int(src in VICTIMS or dst in VICTIMS)
		if src:
			c['top_src'][src] += 1
		if dst:
			c['top_dst'][dst] += 1
	proc.stdout.close()
	if proc.wait() != 0:
		err.seek(0)
		raise SystemExit('Ошибка TShark: ' + err.read()[-1000:])
for k, c in counts.items():
	print('\n', k.upper(), 'пакетов', c['n'])
	print('С известным IP атакующих:', c['known_attacker'], '; с IP цели/NAT:', c['known_victim'])
	print('Топ-8 источников:', c['top_src'].most_common(8))
	print('Топ-8 получателей:', c['top_dst'].most_common(8))
print('\nОфициальное расписание CIC-IDS2017: DDoS LOIT 15:56–16:16 (время стенда); предполагаемый локальный интервал здесь 22:56–23:16 (+0400).')
print('Нужны проверка соответствия IP и характерных изменений трафика; высокое число пакетов само по себе не является разметкой.')
