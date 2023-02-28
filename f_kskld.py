from scipy.stats import kstest
from scipy.stats import ks_2samp
import scipy.stats
import numpy as np

#ks-test
x = np.random.normal(0, 1, 1000)
test_stat = kstest(x, 'norm')
print(test_stat)

aerf = np.random.normal(0, 1, 1000)
beta = np.random.beta(7, 5, 1000)
print(ks_2samp(aerf, beta))

aerf2 = np.random.normal(0, 1, 1000)
print(ks_2samp(aerf, aerf2))

# kl-test
p = np.asarray([0.65, 0.25, 0.07, 0.03])
q = np.array([0.6, 0.25, 0.1, 0.05])
k1 = scipy.stats.entropy(p, q)
print(k1)




