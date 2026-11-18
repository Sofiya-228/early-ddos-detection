"""Небольшая серия ВОСПРОИЗВОДИМЫХ, но ИССЛЕДОВАТЕЛЬСКИХ PCAP-экспериментов.

Скопируйте этот файл в корень NIR_DDoS_Project и запустите:
	python pcap_research_next.py

Читает только готовые 2-секундные признаки; исходный PCAP повторно не обрабатывает.

Метки DDoS в этом скрипте основаны на ВРЕМЕНИ сценария, поэтому результаты
экспериментальные, НЕ независимая оценка качества новой атаки. В частности,
выбирать лучший набор параметров по F1 здесь нельзя и затем утверждать,
что получена независимая тестовая метрика на той же атаке.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
ROOT = Path(__file__).resolve().parent
WINDOW_SECONDS = 2
STEP_SECONDS = 1
REFERENCE_FIRST_ATTACK_PACKET_UTC = '2017-07-07T18:56:31.796937+00:00'
SETS = {
	'all_6': ['packets_per_sec', 'bytes_per_sec', 'syn_per_sec', 'syn_ratio_tcp', 'unique_src_ips', 'unique_dst_ips'],
	'volume_2': ['packets_per_sec', 'bytes_per_sec'],
	'volume_syn_3': ['packets_per_sec', 'bytes_per_sec', 'syn_per_sec'],
	'structure_3': ['syn_ratio_tcp', 'unique_src_ips', 'unique_dst_ips'],
}

def epoch(s):
	return datetime.fromisoformat(s).timestamp()

def slice_by_end(df, start, end):
	return df.loc[(df.window_end_epoch > epoch(start)) & (df.window_end_epoch <= epoch(end))].copy().reset_index(drop=True)

def do_ewma(x, alpha, state=0.0):
	out = np.zeros(len(x), dtype=float)
	for i, v in enumerate(x):
		state = alpha * float(v) + (1 - alpha) * state
		out[i] = max(0.0, state)
	return (out, state)

def do_cusum(x, k, state=0.0):
	out = np.zeros(len(x), dtype=float)
	for i, v in enumerate(x):
		state = max(0.0, state + float(v) - k)
		out[i] = state
	return (out, state)

def alarm_episodes(flags, labels):
	count = 0
	active = False
	for flag, label in zip(flags, labels):
		if label:
			active = False
			continue
		if flag and (not active):
			count += 1
		active = bool(flag)
	return count

def add_metrics(records, name, family, features, param, q, cal_score, test_score, y, times, sched_start, precise_start, report_group):
	limit = float(np.quantile(cal_score, q))
	pred = np.asarray(test_score > limit, dtype=bool)
	hits = times[pred & (y == 1)]
	first = float(hits[0]) if len(hits) else np.nan
	benign_seconds = int((y == 0).sum()) * STEP_SECONDS
	alarms = alarm_episodes(pred, y)
	ispost = times >= epoch('2017-07-07T23:17:00+04:00') + WINDOW_SECONDS
	attack_values = test_score[y == 1]
	records.append(dict(
		variant=name,
		family=family,
		feature_set=features,
		params=param,
		report_group=report_group,
		calibration_quantile=q,
		threshold=limit,
		precision=precision_score(y, pred, zero_division=0),
		recall=recall_score(y, pred, zero_division=0),
		f1=f1_score(y, pred, zero_division=0),
		average_precision=average_precision_score(y, test_score),
		roc_auc=roc_auc_score(y, test_score),
		FP_windows=int((pred & (y == 0)).sum()),
		FN_windows=int((~pred & (y == 1)).sum()),
		false_alarm_episodes=alarms,
		false_alarm_episodes_per_benign_hour=alarms * 3600 / benign_seconds if benign_seconds else np.nan,
		post_attack_alarm_windows=int((pred & ispost & (y == 0)).sum()),
		first_alarm_local=datetime.fromtimestamp(first, timezone.utc).astimezone(datetime.fromisoformat('2017-07-07T22:56:00+04:00').tzinfo).isoformat() if np.isfinite(first) else '',
		delay_schedule_s=first - sched_start if np.isfinite(first) else np.nan,
		delay_first_packet_reference_s=first - precise_start if np.isfinite(first) else np.nan,
		cal_score_p99=float(np.quantile(cal_score, 0.99)),
		attack_score_p99=float(np.quantile(attack_values, 0.99)),
		cal_score_max=float(np.max(cal_score)),
		attack_score_max=float(np.max(attack_values)),
	))

def summarize_features(df, tr, ca, te, y, dst):
	parts = {'train': tr, 'calibration': ca, 'test_attack_candidate': te.loc[y == 1], 'test_benign_candidate': te.loc[y == 0]}
	rows = []
	for name, part in parts.items():
		for feat in SETS['all_6']:
			v = part[feat].astype(float)
			rows.append({'segment': name, 'feature': feat, 'n_windows': len(v), 'mean': v.mean(), 'median': v.median(), 'p90': v.quantile(0.9), 'p99': v.quantile(0.99)})
	pd.DataFrame(rows).to_csv(dst, index=False, encoding='utf-8-sig')

def main():
	cfg = json.loads((ROOT / 'config.json').read_text(encoding='utf-8'))
	path = ROOT / 'data/processed/friday_2s.csv'
	if not path.is_file():
		raise SystemExit(f'Не найден {path}. Сначала: python main.py prepare')
	df = pd.read_csv(path).sort_values('window_end_epoch').reset_index(drop=True)
	need = set(SETS['all_6']) | {'window_end_epoch'}
	missing = need - set(df.columns)
	if missing:
		raise SystemExit(f'Нет необходимых колонок: {sorted(missing)}')
	if not np.isfinite(df[list(need)].to_numpy(dtype=float)).all():
		raise SystemExit('Обнаружены NaN/inf в агрегатах')
	tr = slice_by_end(df, cfg['train_start'], cfg['train_end'])
	ca = slice_by_end(df, cfg['calibration_start'], cfg['calibration_end'])
	te = slice_by_end(df, cfg['test_start'], cfg['test_end'])
	ca = ca.iloc[WINDOW_SECONDS - STEP_SECONDS:].reset_index(drop=True)
	te = te.iloc[WINDOW_SECONDS - STEP_SECONDS:].reset_index(drop=True)
	if min(len(tr), len(ca), len(te)) < 100:
		raise SystemExit('Мало окон после разделения; проверь config.json')
	times = te.window_end_epoch.to_numpy(float)
	sched_start = epoch(cfg['candidate_attack_start'])
	sched_end = epoch(cfg['candidate_attack_end'])
	y = ((times > sched_start) & (times - WINDOW_SECONDS < sched_end)).astype(int)
	precise_start = epoch(REFERENCE_FIRST_ATTACK_PACKET_UTC)
	out = ROOT / 'results' / 'research_next'
	out.mkdir(parents=True, exist_ok=True)
	summarize_features(df, tr, ca, te, y, out / 'feature_summary.csv')
	print(f'Train={len(tr)}, calibration={len(ca)}, test={len(te)}; атака (предварительно)={sum(y)}')
	print('Все пороги получают ТОЛЬКО из калибровочной нормальной последовательности.')
	print('ВНИМАНИЕ: таблица — исследование чувствительности, а не независимая оценка после подбора параметров.')
	records = []
	qlevels = (0.95, 0.99, 0.995)
	xtr = tr.packets_per_sec.to_numpy(float)
	mu, sigma = (xtr.mean(), max(xtr.std(), 1e-06))
	zca = (ca.packets_per_sec.to_numpy(float) - mu) / sigma
	zte = (te.packets_per_sec.to_numpy(float) - mu) / sigma

	def append(name, family, features, param, sc, st, group):
		sc, st = (np.asarray(sc, float), np.asarray(st, float))
		for q in qlevels:
			add_metrics(records, name, family, features, param, q, sc, st, y, times, sched_start, precise_start, group)
	append('Threshold / packets', 'threshold', 'packets_per_sec', 'standard-z', zca, zte, 'primary')
	for alpha in (0.15, 0.3, 0.5):
		sc, state = do_ewma(zca, alpha)
		st, _ = do_ewma(zte, alpha, state)
		append(f'EWMA alpha={alpha:g}', 'ewma', 'packets_per_sec', f'alpha={alpha:g}', sc, st, 'primary' if alpha == 0.3 else 'sensitivity')
	for k in (0.5, 1.0, 2.0):
		sc, state = do_cusum(zca, k)
		st, _ = do_cusum(zte, k, state)
		append(f'CUSUM k={k:g}', 'cusum', 'packets_per_sec', f'k={k:g}', sc, st, 'primary' if k == 0.5 else 'sensitivity')
	for feature_set in ('all_6', 'volume_2', 'volume_syn_3', 'structure_3'):
		cols = SETS[feature_set]
		rawtr = tr[cols].to_numpy(float)
		rawca = ca[cols].to_numpy(float)
		rawte = te[cols].to_numpy(float)
		for tform in ('raw', 'log1p'):
			train, cal, test = (rawtr, rawca, rawte) if tform == 'raw' else (np.log1p(np.maximum(0, rawtr)), np.log1p(np.maximum(0, rawca)), np.log1p(np.maximum(0, rawte)))
			forest = IsolationForest(n_estimators=150, max_samples='auto', random_state=42, n_jobs=-1)
			forest.fit(train)
			sc = -forest.score_samples(cal)
			st = -forest.score_samples(test)
			append(f'IF {feature_set} {tform}', 'isolation_forest', feature_set, tform, sc, st, 'primary' if feature_set == 'all_6' and tform == 'raw' else 'ablation')
	for feature_set in ('all_6', 'volume_syn_3'):
		cols = SETS[feature_set]
		rawtr = tr[cols].to_numpy(float)
		rawca = ca[cols].to_numpy(float)
		rawte = te[cols].to_numpy(float)
		for tform in ('raw', 'log1p'):
			train, cal, test = (rawtr, rawca, rawte) if tform == 'raw' else (np.log1p(np.maximum(0, rawtr)), np.log1p(np.maximum(0, rawca)), np.log1p(np.maximum(0, rawte)))
			for nu in (0.03, 0.1):
				svm = make_pipeline(StandardScaler(), OneClassSVM(kernel='rbf', nu=nu, gamma='scale'))
				svm.fit(train)
				sc = -svm.decision_function(cal).reshape(-1)
				st = -svm.decision_function(test).reshape(-1)
				append(f'OCSVM {feature_set} {tform} nu={nu:g}', 'one_class_svm', feature_set, f'{tform};nu={nu:g};gamma=scale', sc, st, 'primary' if feature_set == 'all_6' and tform == 'raw' and (nu == 0.03) else 'ablation')
	tab = pd.DataFrame(records)
	tab.to_csv(out / 'all_variants_EXPLORATORY.csv', index=False, encoding='utf-8-sig')
	at99 = tab[(tab.calibration_quantile == 0.99) & (tab.report_group == 'primary')]
	at99.to_csv(out / 'main_comparison_q99_EXPLORATORY.csv', index=False, encoding='utf-8-sig')
	print('\nОСНОВНЫЕ МЕТОДЫ, калибровочный порог = 99-й процентиль')
	cols = ['variant', 'precision', 'recall', 'f1', 'FP_windows', 'post_attack_alarm_windows', 'delay_schedule_s', 'delay_first_packet_reference_s']
	print(at99[cols].round(3).to_string(index=False))
	print('\nДиагностика OCSVM:')
	print(tab[(tab.family == 'one_class_svm') & (tab.calibration_quantile == 0.99)][['variant', 'f1', 'recall', 'threshold', 'cal_score_max', 'attack_score_max']].round(4).to_string(index=False))
	fig, ax = plt.subplots(figsize=(12, 4))
	localtimes = pd.to_datetime(te.window_end_epoch, unit='s', utc=True).dt.tz_convert(cfg['timezone'])
	ax.plot(localtimes, te.packets_per_sec, linewidth=0.85, label='Пакеты в секунду')
	ax.axvspan(pd.Timestamp(cfg['candidate_attack_start']), pd.Timestamp(cfg['candidate_attack_end']), alpha=0.12, color='orange', label='Атака: по расписанию')
	ax.axvline(pd.Timestamp(REFERENCE_FIRST_ATTACK_PACKET_UTC).tz_convert(cfg['timezone']), color='red', linestyle='--', label='Первый атакующий пакет (внешняя разметка)')
	ax.set(xlabel='Время (+04:00)', ylabel='Пакеты/с', title='Пакетный трафик и внешний ориентир начала DDoS')
	ax.legend(fontsize=8)
	fig.autofmt_xdate()
	fig.tight_layout()
	fig.savefig(out / 'traffic_attack_reference.png', dpi=140)
	plt.close(fig)
	report = {
		'dataset': 'Исходный Friday-WorkingHours.pcap, обработан ранее TShark',
		'window_seconds': WINDOW_SECONDS,
		'step_seconds': STEP_SECONDS,
		'n_train': len(tr),
		'n_calibration': len(ca),
		'n_test': len(te),
		'overlap_purge': 'Удалено по одному пограничному окну в начале calibration и test, чтобы избежать общих секунд с предыдущим сегментом.',
		'model_selection_note': 'Все варианты ПРЕДВАРИТЕЛЬНО заданы, на данных тестовой атаки НЕ выбирать лучший для итоговой независимой оценки.',
		'ground_truth_note': 'Интервал атаки основан на расписании и внешнем уточнении; не является полной пакетной разметкой.',
		'time_note': 'Delay = время КОНЦА 2-секундного окна - момент начала; время вычисления/обработки не добавлено.',
		'first_attack_reference_utc': REFERENCE_FIRST_ATTACK_PACKET_UTC,
		'train_windows_overlap': 'Соседние окна перекрываются на 1 секунду; не считать окна независимыми атаками.',
	}
	(out / 'methodology.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
	print('\nФайлы в:', out)
	print('  main_comparison_q99_EXPLORATORY.csv — основные 5 методов')
	print('  all_variants_EXPLORATORY.csv — варианты параметров и признаков')
	print('  feature_summary.csv — отличие обучающего, калибровочного и тестового трафика')
	print('  traffic_attack_reference.png — график с уточнённым временем начала')
	print('  methodology.json — ограничения и методика')
if __name__ == '__main__':
	main()
