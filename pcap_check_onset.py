"""Уточнение временной разметки раннего DDoS-обнаружения на уже созданных 2-с окнах.

Разместите рядом с main.py и выполните: python pcap_check_onset.py
PCAP не перечитывается. Ни метки, ни начало атаки не участвуют в fit() или
подборе порогов. Результаты остаются исследовательскими (один эпизод атаки).
"""
from pathlib import Path
from datetime import datetime, timezone, timedelta
import csv
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, average_precision_score, roc_auc_score
ROOT = Path(__file__).resolve().parent
CSV = ROOT / 'data' / 'processed' / 'friday_2s.csv'
OUT = ROOT / 'results' / 'onset_check'
OUT.mkdir(parents=True, exist_ok=True)
WIDTH = 2.0
LOCAL_TZ = timezone(timedelta(hours=4))
FIRST_ATTACK = datetime.fromisoformat('2017-07-07T18:56:31.796937+00:00').timestamp()
LAST_ATTACK = datetime.fromisoformat('2017-07-07T19:16:12.216560+00:00').timestamp()
SOURCE = 'https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html'
FEATURES = ['packets_per_sec', 'bytes_per_sec', 'syn_per_sec', 'syn_ratio_tcp', 'unique_src_ips', 'unique_dst_ips']
PLOT_METHODS = [
	('Threshold, q=0.99', 'Пороговый', '#7C3AED'),
	('EWMA alpha=0.15, q=0.99', 'EWMA, α=0,15', '#D97706'),
	('CUSUM k=0.5, q=0.99', 'CUSUM, k=0,5', '#64748B'),
	('IF 3 features, q=0.95', 'Isolation Forest', '#16A34A'),
	('OCSVM 3 features, q=0.995', 'One-Class SVM', '#2563EB'),
]

def plot_onset_with_alarms(zoom, cfg, rows, feature, ylabel, output):
	"""Сигнал вверху, раздельная временная лента первых тревог внизу.

	Все точки берутся из результатов нового расчёта модели (rows),
	а не проставляются вручную по прежней таблице.
	"""
	import matplotlib.patheffects as pe
	fig, (ax, lane) = plt.subplots(2, 1, figsize=(12.5, 6.3), sharex=True, gridspec_kw={'height_ratios': [3.6, 1.7]}, layout='constrained')
	schedule = datetime.fromisoformat(cfg['candidate_attack_start'])
	onset = datetime.fromtimestamp(FIRST_ATTACK, LOCAL_TZ)
	left = datetime.fromtimestamp(FIRST_ATTACK - 45, LOCAL_TZ)
	right = datetime.fromtimestamp(FIRST_ATTACK + 90, LOCAL_TZ)
	ax.plot(zoom.local_time, zoom[feature], color='#2563EB', linewidth=1.65, label=feature, zorder=3)
	ax.axvline(schedule, color='#858585', linewidth=1.3, linestyle=':', label='Начало по расписанию', zorder=1)
	ax.axvline(onset, color='#E11D48', linewidth=1.75, linestyle='--', label='Первый атакующий пакет', zorder=2)
	ax.set_ylabel(ylabel)
	ax.set_title('Начало DDoS: нагрузка и первые тревоги детекторов', fontsize=13)
	ax.grid(axis='y', alpha=0.18)
	ax.legend(loc='upper left', fontsize=8, framealpha=0.95)
	by_name = {r['method']: r for r in rows}
	marker_rows = []
	for idx, (full_name, short, color) in enumerate(PLOT_METHODS):
		if full_name not in by_name:
			raise ValueError('Отсутствует результат метода для графика: ' + full_name)
		r = by_name[full_name]
		first = r['first_new_alarm_local']
		local_dt = datetime.fromisoformat(first) if first else None
		y = len(PLOT_METHODS) - idx
		if local_dt and left <= local_dt <= right:
			ax.axvline(local_dt, linestyle=':', linewidth=1.1, color=color, alpha=0.45, zorder=1)
			lane.scatter([local_dt], [y], color=color, s=78, zorder=4, edgecolors='white', linewidths=0.8)
			delay = r['detection_delay_from_first_packet_s']
			stamp = local_dt.strftime('%H:%M:%S')
			shown = f'{stamp}   (+{float(delay):.1f} с)' if delay != '' else stamp
			lane.annotate(shown, (local_dt, y), xytext=(6, 5), textcoords='offset points', fontsize=8, color=color, path_effects=[pe.withStroke(linewidth=3, foreground='white')])
		else:
			shown = 'Тревога не обнаружена' if not local_dt else 'Вне показанного диапазона'
			lane.text(left, y + 0.1, shown, fontsize=8, color=color)
		marker_rows.append({
			'method': full_name,
			'label': short,
			'first_new_alarm_local': first,
			'delay_from_first_attack_packet_s': r['detection_delay_from_first_packet_s'],
			'F1_on_one_episode_EXPLORATORY': r['F1'],
			'FP_windows': r['FP_windows'],
		})
	lane.axvline(schedule, color='#858585', linewidth=1.15, linestyle=':')
	lane.axvline(onset, color='#E11D48', linewidth=1.5, linestyle='--')
	lane.set_yticks(range(1, len(PLOT_METHODS) + 1), [a[1] for a in reversed(PLOT_METHODS)])
	lane.set_ylim(0.45, len(PLOT_METHODS) + 0.9)
	lane.set_xlim(left, right)
	lane.grid(axis='x', alpha=0.2)
	lane.set_xlabel('Время (+04:00), время окончания окна')
	lane.set_title('Момент первой новой тревоги каждого метода', fontsize=9, loc='left')
	lane.xaxis.set_major_locator(mdates.SecondLocator(interval=15, tz=LOCAL_TZ))
	lane.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S', tz=LOCAL_TZ))
	for tick in lane.get_xticklabels():
		tick.set_rotation(25)
		tick.set_ha('right')
	fig.savefig(output, dpi=175)
	plt.close(fig)
	return marker_rows

def seconds(iso):
	return datetime.fromisoformat(iso).timestamp()

def split(df, a, b):
	return df[(df.window_end_epoch > seconds(a)) & (df.window_end_epoch <= seconds(b))].copy().reset_index(drop=True)

def zvalue(series, mean, std):
	return (series.to_numpy(float) - mean) / std

def smoothing(arr, alpha, state=0.0):
	result = []
	for val in arr:
		state = alpha * float(val) + (1 - alpha) * state
		result.append(max(0.0, state))
	return (np.asarray(result), state)

def cusum(arr, k, state=0.0):
	result = []
	for val in arr:
		state = max(0.0, state + float(val) - k)
		result.append(state)
	return (np.asarray(result), state)

def eval_method(name, cal_score, test_score, q, end_times, labels):
	threshold = float(np.quantile(cal_score, q))
	alarm = np.asarray(test_score > threshold)
	valid = labels >= 0
	truth = labels[valid]
	pred = alarm[valid]
	scores = np.asarray(test_score)[valid]
	rising = alarm & ~np.r_[False, alarm[:-1]]
	starts = end_times[rising]
	event_starts = starts[(starts >= FIRST_ATTACK) & (starts <= LAST_ATTACK)]
	first = float(event_starts[0]) if len(event_starts) else np.nan
	before = int(np.sum(alarm & (end_times <= FIRST_ATTACK)))
	fp = int(np.sum((pred == 1) & (truth == 0)))
	is_normal = labels == 0
	normal_alarm = alarm & is_normal
	false_starts = normal_alarm & ~np.r_[False, normal_alarm[:-1]]
	return {
		'method': name,
		'q': q,
		'threshold': threshold,
		'precision': precision_score(truth, pred, zero_division=0),
		'recall': recall_score(truth, pred, zero_division=0),
		'F1': f1_score(truth, pred, zero_division=0),
		'AP': average_precision_score(truth, scores),
		'ROC_AUC': roc_auc_score(truth, scores),
		'FP_windows': fp,
		'false_alarm_episodes': int(np.sum(false_starts)),
		'pre_attack_alarm_windows': before,
		'post_attack_FP_windows': int(np.sum(alarm & (end_times >= LAST_ATTACK + WIDTH) & (labels == 0))),
		'first_new_alarm_local': datetime.fromtimestamp(first, LOCAL_TZ).isoformat() if np.isfinite(first) else '',
		'detection_delay_from_first_packet_s': round(float(first - FIRST_ATTACK), 3) if np.isfinite(first) else '',
	}

def main():
	if not CSV.is_file():
		raise SystemExit(f'Файл не найден: {CSV}; сначала python main.py prepare')
	cfg = json.loads((ROOT / 'config.json').read_text(encoding='utf-8'))
	df = pd.read_csv(CSV).sort_values('window_end_epoch').reset_index(drop=True)
	cols = ['window_end_epoch'] + FEATURES
	if any((c not in df for c in cols)):
		raise SystemExit(f'Не хватает колонок: {[c for c in cols if c not in df]}')
	if not np.isfinite(df[cols].to_numpy(float)).all():
		raise SystemExit('Есть NaN/inf: проверь данные')
	tr = split(df, cfg['train_start'], cfg['train_end'])
	ca = split(df, cfg['calibration_start'], cfg['calibration_end']).iloc[1:].reset_index(drop=True)
	te = split(df, cfg['test_start'], cfg['test_end']).iloc[1:].reset_index(drop=True)
	times = te.window_end_epoch.to_numpy(float)
	starts = times - WIDTH
	labels = np.full(len(te), -1, dtype=int)
	labels[(times <= FIRST_ATTACK) | (starts >= LAST_ATTACK)] = 0
	labels[(starts >= FIRST_ATTACK) & (times <= LAST_ATTACK)] = 1
	ignored = int((labels < 0).sum())
	if len(tr) < 100 or len(ca) < 100 or len(te) < 100:
		raise SystemExit('Мало наблюдений в train/cal/test')
	if not (tr.window_end_epoch.max() <= ca.window_end_epoch.min() - WIDTH and ca.window_end_epoch.max() <= te.window_end_epoch.min() - WIDTH):
		raise SystemExit('Пересечение окон между train/cal/test!')
	print('Проверка границ:')
	print('Начало DDoS:', datetime.fromtimestamp(FIRST_ATTACK, LOCAL_TZ).isoformat())
	print('Конец DDoS: ', datetime.fromtimestamp(LAST_ATTACK, LOCAL_TZ).isoformat())
	print(f'Train={len(tr)} Calibration={len(ca)} Test={len(te)}')
	print(f'Полностью атакующих окон: {int((labels == 1).sum())}; нормальных: {int((labels == 0).sum())}; пограничных исключено из метрик: {ignored}')
	ztr = tr.packets_per_sec.to_numpy(float)
	mu, sigma = (float(ztr.mean()), max(float(ztr.std()), 1e-06))
	zca = zvalue(ca.packets_per_sec, mu, sigma)
	zte = zvalue(te.packets_per_sec, mu, sigma)
	experiments = [('Threshold, q=0.99', zca, zte, 0.99)]
	for alpha, q in ((0.3, 0.99), (0.15, 0.99)):
		sc, state = smoothing(zca, alpha)
		st, _ = smoothing(zte, alpha, state)
		experiments.append((f'EWMA alpha={alpha}, q={q}', sc, st, q))
	sc, state = cusum(zca, 0.5)
	st, _ = cusum(zte, 0.5, state)
	experiments.append(('CUSUM k=0.5, q=0.99', sc, st, 0.99))
	for feats, q, label in ((FEATURES, 0.99, 'IF 6 features, q=0.99'), (['packets_per_sec', 'bytes_per_sec', 'syn_per_sec'], 0.95, 'IF 3 features, q=0.95')):
		model = IsolationForest(n_estimators=150, max_samples='auto', random_state=42, n_jobs=-1)
		model.fit(tr[feats].to_numpy(float))
		experiments.append((label, -model.score_samples(ca[feats].to_numpy(float)), -model.score_samples(te[feats].to_numpy(float)), q))
	feats = ['packets_per_sec', 'bytes_per_sec', 'syn_per_sec']
	model = make_pipeline(StandardScaler(), OneClassSVM(kernel='rbf', nu=0.03, gamma='scale'))
	model.fit(tr[feats].to_numpy(float))
	experiments.append(('OCSVM 3 features, q=0.995', -model.decision_function(ca[feats].to_numpy(float)).reshape(-1), -model.decision_function(te[feats].to_numpy(float)).reshape(-1), 0.995))
	rows = [eval_method(name, sc, st, q, times, labels) for name, sc, st, q in experiments]
	path = OUT / 'comparison_corrected_EXPLORATORY.csv'
	with open(path, 'w', encoding='utf-8-sig', newline='') as f:
		writer = csv.DictWriter(f, fieldnames=list(rows[0]))
		writer.writeheader()
		writer.writerows(rows)
	print('\nПОСЛЕ УТОЧНЕНИЯ ГРАНИЦ:')
	print(pd.DataFrame(rows)[['method', 'precision', 'recall', 'F1', 'FP_windows', 'pre_attack_alarm_windows', 'detection_delay_from_first_packet_s']].round(3).to_string(index=False))
	print('Показатели — исследовательские: варианты ранее сравнивались на этом же DDoS эпизоде.')
	zoom = te[(te.window_end_epoch >= FIRST_ATTACK - 45) & (te.window_end_epoch <= FIRST_ATTACK + 90)].copy()
	zoom['local_time'] = pd.to_datetime(zoom.window_end_epoch, unit='s', utc=True).dt.tz_convert(LOCAL_TZ)
	zoom.to_csv(OUT / 'onset_windows.csv', index=False, encoding='utf-8-sig')
	markers = None
	for feat, ylabel, fname in (('packets_per_sec', 'Пакетов/с', 'onset_packets_zoom.png'), ('syn_per_sec', 'Начальных SYN/с', 'onset_syn_zoom.png')):
		markers = plot_onset_with_alarms(zoom, cfg, rows, feat, ylabel, OUT / fname)
	pd.DataFrame(markers).to_csv(OUT / 'alarm_markers.csv', index=False, encoding='utf-8-sig')
	(OUT / 'README_RESULTS.txt').write_text('Уточнение времени начала и конца DDoS по внешней публикации: ' + SOURCE + '\nОкна, пересекающие границы, исключены из метрик, но присутствуют при расчёте состояний EWMA/CUSUM.\nЗадержка: от первого атакующего пакета до нового эпизода тревоги, по времени конца окна.\nЦветные отметки на увеличенных графиках — начала НОВЫХ эпизодов тревоги.\nМодели и пороги вычисляются заново из train/calibration; отметки получены из результатов, а не заданы вручную.\nИсследование одной атаки. Нельзя использовать эти метрики как независимое подтверждение выбора гиперпараметров.\n', encoding='utf-8')
	print('\nГотово:', OUT)
	print('  comparison_corrected_EXPLORATORY.csv')
	print('  onset_windows.csv')
	print('  onset_packets_zoom.png и onset_syn_zoom.png (с отметками 5 методов)')
	print('  alarm_markers.csv (точные моменты тревог для отчёта)')
if __name__ == '__main__':
	main()
