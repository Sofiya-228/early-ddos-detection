"""Контроль временной шкалы и распределений пакетных признаков."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data' / 'processed' / 'friday_2s.csv'
PERIODS = [
	('Обучающий участок', 'train_start', 'train_end'),
	('Калибровка', 'calibration_start', 'calibration_end'),
	('Период атаки по расписанию', 'candidate_attack_start', 'candidate_attack_end'),
	('После атаки', 'candidate_attack_end', 'test_end'),
]


def to_epoch(value: str) -> int:
	return int(datetime.fromisoformat(value).timestamp())


def main() -> None:
	if not DATA.is_file():
		raise SystemExit(f'Не найдены признаки: {DATA}')

	config = json.loads((ROOT / 'config.json').read_text(encoding='utf-8'))
	frame = pd.read_csv(DATA)
	if frame.empty or not frame.window_end_epoch.is_monotonic_increasing:
		raise SystemExit('Временные окна отсутствуют или не упорядочены.')

	start = to_epoch(config['train_start'])
	end = to_epoch(config['test_end'])
	if frame.window_end_epoch.min() > start + 4 or frame.window_end_epoch.max() < end - 4:
		raise SystemExit('Диапазон данных не покрывает обучение и тест.')

	print(f'Секундных окон: {len(frame)}')
	print(f'Первое окно (UTC): {frame.window_start_utc.iloc[0]}')
	print(f'Последнее окно (UTC): {frame.window_end_utc.iloc[-1]}')

	for title, begin_key, end_key in PERIODS:
		begin = to_epoch(config[begin_key])
		finish = to_epoch(config[end_key])
		part = frame.loc[(frame.window_end_epoch > begin + 1) & (frame.window_end_epoch <= finish)]
		if part.empty:
			continue
		print(
			f'{title}: {len(part)} окон; '
			f'пакеты/с (медиана)={part.packets_per_sec.median():.1f}; '
			f'пакеты/с (среднее)={part.packets_per_sec.mean():.1f}; '
			f'SYN/с={part.syn_per_sec.mean():.1f}; '
			f'уникальные источники={part.unique_src_ips.mean():.1f}'
		)


if __name__ == '__main__':
	main()
