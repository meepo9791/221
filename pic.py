import numpy as np

import statsmodels.api as sm

import matplotlib.pyplot as plt

sample = np.random.uniform(0, 1, 50)

ecdf = sm.distributions.ECDF(sample)

x = np.linspace(min(sample), max(sample))

y = ecdf(x)

plt.step(x, y)

plt.show()