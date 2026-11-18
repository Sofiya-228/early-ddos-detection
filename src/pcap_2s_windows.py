"""Extract causal packet-window features from an existing PCAP using TShark.

No attack labels are read or generated. A 2 s window ending at T includes only
packets captured before T. The script does NOT capture live network traffic.

Example on Windows:
 python pcap_2s_windows.py --pcap data/raw/friday_ddos_excerpt.pcap     --output results/packets_2s.csv --window 2 --step 1
"""
from __future__ import annotations
import argparse
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from pathlib import Path
import shutil
import subprocess
import tempfile

@dataclass
class SecondBucket:
	packets: int = 0
	bytes: int = 0
	tcp: int = 0
	syn: int = 0
	src: set[str] = field(default_factory=set)
	dst: set[str] = field(default_factory=set)

def parse_packet_fields(row: list[str]) -> tuple[int, int, str, str, bool, bool] | None:
	"""Extract epoch second, frame bytes, source, destination, TCP, initial SYN."""
	if len(row) < 6 or not row[0] or (not row[1]):
		return None
	try:
		second = math.floor(float(row[0]))
		size = int(row[1])
	except ValueError:
		return None
	is_tcp = bool(row[4].strip())
	syn = row[4].strip().lower() in {'1', 'true', 'set'}
	ack = row[5].strip().lower() in {'1', 'true', 'set'}
	return (second, size, row[2].strip(), row[3].strip(), is_tcp, syn and (not ack))

def update_buckets(buckets: dict[int, SecondBucket], fields: tuple[int, int, str, str, bool, bool]) -> None:
	second, size, src, dst, is_tcp, syn = fields
	bucket = buckets.setdefault(second, SecondBucket())
	bucket.packets += 1
	bucket.bytes += size
	bucket.tcp += int(is_tcp)
	bucket.syn += int(syn)
	if src:
		bucket.src.add(src)
	if dst:
		bucket.dst.add(dst)

def iso(epoch_second: int) -> str:
	return datetime.fromtimestamp(epoch_second, timezone.utc).isoformat().replace('+00:00', 'Z')

def aggregate(buckets: dict[int, SecondBucket], window: int=2, step: int=1):
	"""Slide a window using exclusively already observed packet timestamps."""
	if not buckets:
		return
	start = min(buckets)
	stop = max(buckets) + 1
	for win_start in range(start, stop - window + 1, step):
		interval = [buckets.get(sec) for sec in range(win_start, win_start + window)]
		observed = [b for b in interval if b is not None]
		packets = sum((b.packets for b in observed))
		bytes_ = sum((b.bytes for b in observed))
		tcp = sum((b.tcp for b in observed))
		syn = sum((b.syn for b in observed))
		src = set().union(*(b.src for b in observed))
		dst = set().union(*(b.dst for b in observed))
		yield {
			'window_start_utc': iso(win_start),
			'window_end_utc': iso(win_start + window),
			'window_end_epoch': win_start + window,
			'packets_per_sec': round(packets / window, 4),
			'bytes_per_sec': round(bytes_ / window, 4),
			'syn_per_sec': round(syn / window, 4),
			'syn_ratio_tcp': round(syn / tcp, 6) if tcp else 0,
			'unique_src_ips': len(src),
			'unique_dst_ips': len(dst),
			'packets_in_window': packets,
			'tcp_packets_in_window': tcp,
			'syn_packets_in_window': syn,
		}

def tshark_path(explicit: str | None) -> str:
	if explicit:
		return explicit
	which = shutil.which('tshark')
	if which:
		return which
	default = Path('C:\\Program Files\\Wireshark\\tshark.exe')
	if default.exists():
		return str(default)
	raise FileNotFoundError('TShark не найден. Установи Wireshark с компонентом TShark или укажи --tshark.')

def run(pcap: Path, output: Path, window: int, step: int, tshark: str) -> None:
	if not pcap.is_file():
		raise FileNotFoundError(f'Не найден PCAP: {pcap}')
	output.parent.mkdir(parents=True, exist_ok=True)
	args = [
		tshark,
		'-n',
		'-r',
		str(pcap),
		'-Y',
		'ip',
		'-T',
		'fields',
		'-E',
		'occurrence=f',
		'-e',
		'frame.time_epoch',
		'-e',
		'frame.len',
		'-e',
		'ip.src',
		'-e',
		'ip.dst',
		'-e',
		'tcp.flags.syn',
		'-e',
		'tcp.flags.ack',
	]
	buckets: dict[int, SecondBucket] = {}
	count = 0
	with tempfile.TemporaryFile(mode='w+t', encoding='utf-8') as err:
		proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err, text=True, encoding='utf-8', errors='replace')
		assert proc.stdout is not None
		for row in csv.reader(proc.stdout, delimiter='\t'):
			fields = parse_packet_fields(row)
			if fields is None:
				continue
			update_buckets(buckets, fields)
			count += 1
		proc.stdout.close()
		code = proc.wait()
		if code != 0:
			err.seek(0)
			raise RuntimeError(f'TShark завершился с кодом {code}: {err.read()[-3000:]}')
	if not buckets:
		raise ValueError('В файле не найдено IPv4-пакетов; проверь PCAP и фильтр.')
	headers = [
		'window_start_utc',
		'window_end_utc',
		'window_end_epoch',
		'packets_per_sec',
		'bytes_per_sec',
		'syn_per_sec',
		'syn_ratio_tcp',
		'unique_src_ips',
		'unique_dst_ips',
		'packets_in_window',
		'tcp_packets_in_window',
		'syn_packets_in_window',
	]
	n = 0
	with output.open('w', newline='', encoding='utf-8') as handle:
		writer = csv.DictWriter(handle, fieldnames=headers)
		writer.writeheader()
		for item in aggregate(buckets, window, step):
			writer.writerow(item)
			n += 1
	print('IPv4 пакетов прочитано:', count)
	print('Первый пакет, начало секунды (UTC):', iso(min(buckets)))
	print('Последний пакет, начало секунды (UTC):', iso(max(buckets)))
	print('Число окон:', n)
	print('Окно:', window, 'секунд; шаг:', step, 'секунд')
	print('Результат:', output)
	print('ВАЖНО: CSV не содержит меток атак. Сверь часовой пояс PCAP с расписанием CIC-IDS2017 до оценки задержки.')

def main():
	p = argparse.ArgumentParser(description='Агрегация пакетов PCAP в скользящие окна')
	p.add_argument('--pcap', required=True, type=Path)
	p.add_argument('--output', default=Path('results/pcap_2s_windows.csv'), type=Path)
	p.add_argument('--window', default=2, type=int)
	p.add_argument('--step', default=1, type=int)
	p.add_argument('--tshark', default=None)
	args = p.parse_args()
	if args.window < 1 or args.step < 1:
		p.error('Окно и шаг должны быть положительными целыми числами')
	run(args.pcap, args.output, args.window, args.step, tshark_path(args.tshark))
if __name__ == '__main__':
	main()
