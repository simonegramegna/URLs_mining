import pandas as pd
import random
import os
from data_preprocessing_utils import DATA_PATH_URLS, DATA_PATH


data = pd.read_csv(DATA_PATH_URLS)

# visualize initial dataset
print(data.describe())

# data sampling
benign_urls = data[data['type'] == 'benign']
defacement_urls = data[data['type'] == 'defacement']
phishing_urls = data[data['type'] == 'phishing']
malware_urls = data[data['type'] == 'malware']
spam_urls = data[data['type'] == 'spam']

benign_urls_sample = random.sample(list(benign_urls.index), 10000)
defacement_urls_sample = random.sample(list(defacement_urls.index), 2500)
phishing_urls_sample = random.sample(list(phishing_urls.index), 2500)
malware_urls_sample = random.sample(list(malware_urls.index), 2500)
spam_urls_sample = random.sample(list(spam_urls.index), 2500)

selected_indexes = benign_urls_sample + defacement_urls_sample + \
    phishing_urls_sample + malware_urls_sample + spam_urls_sample
random.shuffle(selected_indexes)
data_sampled = data.loc[selected_indexes]
data_sampled = data_sampled.reset_index(drop=True)

data_path_sampled = os.path.join(DATA_PATH, "malicious_urls_sampled.csv")

data_sampled.to_csv(data_path_sampled, index=False)
