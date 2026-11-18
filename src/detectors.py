"""Статистические и обучаемые детекторы; все пороги калибруются без меток атак."""
from __future__ import annotations
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
INPUTS = ['packets_per_sec', 'bytes_per_sec', 'syn_per_sec', 'syn_ratio_tcp', 'unique_src_ips', 'unique_dst_ips']

def _zsignal(frame, signal, mean, std):
	return (frame[signal].to_numpy(dtype=float) - mean) / std

def _scale_train(train, signal):
	x = train[signal].to_numpy(dtype=float)
	m = float(x.mean())
	s = float(x.std())
	return (m, max(s, 1e-06))

def score_methods(train, cal, test, cfg):
	"""Возвращает два словаря оценок (калибровка, тест), больше = аномальнее."""
	train_x = train[INPUTS].to_numpy(dtype=float)
	cal_x = cal[INPUTS].to_numpy(dtype=float)
	test_x = test[INPUTS].to_numpy(dtype=float)
	for key, v in [('train', train_x), ('cal', cal_x), ('test', test_x)]:
		if not np.isfinite(v).all():
			raise ValueError(f'Есть NaN/inf в {key}, нельзя обучать модель!')
	cal_scores = {}
	test_scores = {}
	mu, sigma = _scale_train(train, 'packets_per_sec')
	z_cal = _zsignal(cal, 'packets_per_sec', mu, sigma)
	z_test = _zsignal(test, 'packets_per_sec', mu, sigma)
	cal_scores['Threshold'] = z_cal
	test_scores['Threshold'] = z_test

	def ewma(arr, init):
		alpha = float(cfg['ewma_alpha'])
		state = float(init)
		out = []
		for x in arr:
			state = alpha * float(x) + (1 - alpha) * state
			out.append(max(0, state))
		return (np.asarray(out), state)
	e_cal, e_state = ewma(z_cal, 0.0)
	e_test, _ = ewma(z_test, e_state)
	cal_scores['EWMA'] = e_cal
	test_scores['EWMA'] = e_test

	def cusum(arr, init):
		state = float(init)
		out = []
		k = float(cfg['cusum_k'])
		for x in arr:
			state = max(0.0, state + float(x) - k)
			out.append(state)
		return (np.asarray(out), state)
	c_cal, c_state = cusum(z_cal, 0.0)
	c_test, _ = cusum(z_test, c_state)
	cal_scores['CUSUM'] = c_cal
	test_scores['CUSUM'] = c_test
	forest = IsolationForest(n_estimators=150, max_samples='auto', contamination='auto', random_state=int(cfg['random_state']), n_jobs=-1)
	forest.fit(train_x)
	cal_scores['Isolation Forest'] = -forest.score_samples(cal_x)
	test_scores['Isolation Forest'] = -forest.score_samples(test_x)
	svm = make_pipeline(StandardScaler(), OneClassSVM(kernel='rbf', nu=0.03, gamma='scale'))
	svm.fit(train_x)
	cal_scores['One-Class SVM'] = -svm.decision_function(cal_x).reshape(-1)
	test_scores['One-Class SVM'] = -svm.decision_function(test_x).reshape(-1)
	return (cal_scores, test_scores)
