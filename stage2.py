"""Единый эксперимент: 5 методов, temporal split, метрики и графики."""
from __future__ import annotations
import argparse
from datetime import datetime
import json
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.metrics import precision_score, recall_score, f1_score, average_precision_score, roc_auc_score
from src.detectors import score_methods, INPUTS
ROOT = Path(__file__).resolve().parent

def ts(s):
	return int(datetime.fromisoformat(s).timestamp())

def use_window(df, start, end):
	return df[(df.window_end_epoch > ts(start)) & (df.window_end_epoch <= ts(end))].copy().reset_index(drop=True)

def false_alarm_episodes(flags, y):
	episodes = 0
	in_run = False
	for f, t in zip(flags, y):
		if t == 1:
			in_run = False
			continue
		if f and (not in_run):
			episodes += 1
		in_run = bool(f)
	return episodes

def analyze(cfg_path, confirmed=False):
	cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
	csvpath = ROOT / 'data/processed/friday_2s.csv'
	if not csvpath.is_file():
		raise FileNotFoundError(f'Не найден {csvpath}; сначала выполни этап 1')
	df = pd.read_csv(csvpath).sort_values('window_end_epoch').reset_index(drop=True)
	if not df.window_end_epoch.is_unique:
		raise ValueError('Повторяющиеся времена окончания окон: нужен шаг 1 сек и окно 2 сек')
	tr = use_window(df, cfg['train_start'], cfg['train_end'])
	ca = use_window(df, cfg['calibration_start'], cfg['calibration_end'])
	te = use_window(df, cfg['test_start'], cfg['test_end'])
	if min(len(tr), len(ca), len(te)) < 100:
		raise ValueError(f'Недостаточно секундных окон: train={len(tr)} calibration={len(ca)} test={len(te)}. Проверь часовой пояс.')
	assert tr.window_end_epoch.max() <= ca.window_end_epoch.min()
	assert ca.window_end_epoch.max() <= te.window_end_epoch.min()
	attack_start = ts(cfg['candidate_attack_start'])
	attack_end = ts(cfg['candidate_attack_end'])
	if not ts(cfg['test_start']) < attack_start < attack_end < ts(cfg['test_end']):
		raise ValueError('Границы атаки должны быть внутри теста')
	t = te.window_end_epoch.to_numpy(dtype=float)
	y = ((t > attack_start) & (t - 2 < attack_end)).astype(int)
	cal_scores, test_scores = score_methods(tr, ca, te, cfg)
	out = ROOT / 'results'
	out.mkdir(parents=True, exist_ok=True)
	(out / 'plots').mkdir(exist_ok=True)
	results = []
	full_preds = pd.DataFrame({
		'window_end_epoch': te.window_end_epoch,
		'window_end_utc': te.window_end_utc,
		'label_candidate': y,
	})
	for name, cs in cal_scores.items():
		scores = test_scores[name]
		threshold = float(np.quantile(cs, float(cfg['threshold_quantile'])))
		prediction = (scores > threshold).astype(int)
		alarms = t[(prediction == 1) & (y == 1)]
		delay = float(alarms[0] - attack_start) if len(alarms) else None
		fph = (y == 0).sum() / 3600.0
		alarm_runs = false_alarm_episodes(prediction, y)
		result = {
			'method': name,
			'precision': float(precision_score(y, prediction, zero_division=0)),
			'recall': float(recall_score(y, prediction, zero_division=0)),
			'f1': float(f1_score(y, prediction, zero_division=0)),
			'pr_auc_AP': float(average_precision_score(y, scores)),
			'roc_auc': float(roc_auc_score(y, scores)),
			'FP_windows': int(((prediction == 1) & (y == 0)).sum()),
			'FN_windows': int(((prediction == 0) & (y == 1)).sum()),
			'false_alarm_episodes': alarm_runs,
			'false_alarms_per_benign_hour': round(alarm_runs / fph, 3) if fph > 0 else None,
			'first_detection_delay_s': delay,
			'threshold': threshold,
		}
		results.append(result)
		key = name.lower().replace(' ', '_').replace('-', '_')
		full_preds[key + '_score'] = scores
		full_preds[key + '_alarm'] = prediction
		fig, ax = plt.subplots(figsize=(11, 3.5))
		dt = pd.to_datetime(te.window_end_epoch, unit='s', utc=True).dt.tz_convert(cfg['timezone'])
		ax.plot(dt, scores, label='Оценка аномальности', linewidth=0.9)
		ax.axhline(threshold, color='black', linestyle='--', label='Порог (нормальная калибровка)')
		ax.axvspan(pd.Timestamp(cfg['candidate_attack_start']), pd.Timestamp(cfg['candidate_attack_end']), alpha=0.15, label='Период атаки (предварительно)')
		ax.set(title=name, xlabel='Время, +04:00', ylabel='Оценка')
		ax.legend(fontsize=8)
		fig.autofmt_xdate()
		fig.tight_layout()
		fig.savefig(out / 'plots' / f'{key}.png', dpi=130)
		plt.close(fig)
	pd.DataFrame(results).to_csv(out / 'comparison_PROVISIONAL.csv', index=False)
	full_preds.to_csv(out / 'predictions_PROVISIONAL.csv', index=False)
	fig, ax = plt.subplots(figsize=(11, 3.5))
	dt = pd.to_datetime(te.window_end_epoch, unit='s', utc=True).dt.tz_convert(cfg['timezone'])
	ax.plot(dt, te.packets_per_sec, label='Пакеты/с', linewidth=1)
	ax.axvspan(pd.Timestamp(cfg['candidate_attack_start']), pd.Timestamp(cfg['candidate_attack_end']), alpha=0.15, label='Период атаки (предварительно)')
	ax.legend()
	ax.set(xlabel='Время +04:00', ylabel='Пакеты/с', title='Пакетная активность (2-сек. окна, шаг 1 сек.)')
	fig.autofmt_xdate()
	fig.tight_layout()
	fig.savefig(out / 'plots' / 'traffic.png', dpi=130)
	plt.close(fig)
	meta = {
		'train_windows': len(tr),
		'calibration_windows': len(ca),
		'test_windows': len(te),
		'train_period': [cfg['train_start'], cfg['train_end']],
		'calibration_period': [cfg['calibration_start'], cfg['calibration_end']],
		'test_period': [cfg['test_start'], cfg['test_end']],
		'candidate_attack_period': [cfg['candidate_attack_start'], cfg['candidate_attack_end']],
		'labels_confirmed': bool(confirmed),
		'WARNING': 'ГРАНИЦЫ ПОДТВЕРЖДЕНЫ ПОЛЬЗОВАТЕЛЕМ; подтвердить внешними данными' if confirmed else cfg['label_status'],
		'train_features': INPUTS,
		'no_label_used_for_training_or_threshold': True,
		'interval_note': 'Перекрывающиеся 2-сек. окна зависимы; одна непрерывная атака; время - до конца первого тревожного окна; не online IDS.',
	}
	(out / 'experiment_info.json').write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding='utf-8')
	print('\nРезультат:', out / 'comparison_PROVISIONAL.csv')
	print('Обучение / калибровка / тест:', len(tr), len(ca), len(te))
	print(pd.DataFrame(results)[['method', 'precision', 'recall', 'f1', 'pr_auc_AP', 'FP_windows', 'false_alarm_episodes', 'first_detection_delay_s']].to_string(index=False))
	print('\nВНИМАНИЕ: цифры предварительные до независимого подтверждения периода атаки!')
if __name__ == '__main__':
	p = argparse.ArgumentParser(description='Офлайн-эксперимент раннего обнаружения по PCAP')
	p.add_argument('--config', default='config.json')
	p.add_argument('--confirmed', action='store_true', help='Только после проверки периода атаки; не делает метки точнее')
	args = p.parse_args()
	analyze(ROOT / args.config, confirmed=args.confirmed)
