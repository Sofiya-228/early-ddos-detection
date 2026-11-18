import unittest
import numpy as np
import pandas as pd
from src.pcap_2s_windows import SecondBucket, aggregate
from src.detectors import score_methods, INPUTS

class TestNIR(unittest.TestCase):

	def test_window_uses_only_past(self):
		b = {
			0: SecondBucket(packets=2, bytes=200, tcp=2, syn=1, src={'a'}, dst={'x'}),
			1: SecondBucket(packets=4, bytes=400, tcp=4, syn=2, src={'b'}, dst={'x'}),
			2: SecondBucket(packets=100, bytes=10000, tcp=100, syn=80, src={'c'}, dst={'x'}),
		}
		windows = list(aggregate(b, 2, 1))
		self.assertEqual(windows[0]['packets_per_sec'], 3)
		self.assertEqual(windows[0]['unique_src_ips'], 2)
		self.assertEqual(windows[1]['packets_per_sec'], 52)

	def test_models_no_label_needed(self):
		rg = np.random.default_rng(17)

		def frame(n):
			return pd.DataFrame({c: np.abs(rg.normal(20, 5, n)) for c in INPUTS})
		a, b, c = (frame(150), frame(50), frame(20))
		config = {'ewma_alpha': 0.3, 'cusum_k': 0.5, 'random_state': 42}
		cal, test = score_methods(a, b, c, config)
		self.assertEqual(len(test), 5)
		for name in test:
			self.assertTrue(np.isfinite(test[name]).all())
			self.assertEqual(len(test[name]), 20)
if __name__ == '__main__':
	unittest.main()
