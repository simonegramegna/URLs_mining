import pandas as pd
from data_preprocessing_utils import *
import os


data = pd.read_csv(DATA_PATH+"\\malicious_urls_sampled.csv")

data_features = pd.DataFrame({
    'url': [],
    'numDots': [],
    'subdomainLevel': [],
    'pathLevel': [],
    'urlLength': [],
    'numDash': [],
    'atSymbol': [],
    'tildeSymbol': [],
    'numUnderscore': [],
    'numPercent': [],
    'numQueryComponents': [],
    'numApersand': [],
    'numHash': [],
    'numDigits': [],
    'https': [],
    'ipAddress': [],
    'domainInSubdomains': [],
    'domainInPaths': [],
    'httpsInHostname': [],
    'hostnameLength': [],
    'pathLength': [],
    'queryLength': [],
    'doubleSlash': [],
    'type': []
})

data_path_sampled = os.path.join(DATA_PATH, "urls_with_features.csv")


# Aggiorna questo valore con il numero effettivo di features
numero_di_caratteristiche = 25
data_features = pd.DataFrame(index=range(
    len(data)), columns=range(numero_di_caratteristiche))

# Loop attraverso i dati in batch
for i in range(0, len(data), 1000):
    urls_batch = data.loc[i:i+999, 'url']
    labels_batch = data.loc[i:i+999, 'type']

    try:
        # Chiamata alla nuova funzione vettorizzata
        features_batch = get_lexical_features_vectorized(
            urls_batch, labels_batch)
        
        print(features_batch)

        features_batch.to_csv(data_path_sampled, index=False)
    except Exception as e:
        print('\n')
        print(e)
        print('Error processing batch from index: ', i)
        continue



