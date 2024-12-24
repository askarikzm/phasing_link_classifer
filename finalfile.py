import warnings
from flask import Flask, render_template, request
import pickle
import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import logging

# Initialize Flask app
app = Flask(__name__)

# Load the model
with open('model.pkl', 'rb') as file:
    model = pickle.load(file)

# Selected features for the model
selected_features = [
    'UrlLength',
    'NumNumericChars',
    'PctExtHyperlinks',
    'PctExtResourceUrls',
    'InsecureForms',
    'PctNullSelfRedirectHyperlinks',
    'FrequentDomainNameMismatch',
    'PctExtNullSelfRedirectHyperlinksRT'
]

def extract_features_from_url(url):
    try:
        parsed_url = urlparse(url)
        url_length = len(url)
        num_numeric_chars = sum(c.isdigit() for c in url)
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        hyperlinks = soup.find_all('a', href=True)
        external_links = [link['href'] for link in hyperlinks if not link['href'].startswith(url)]
        pct_ext_hyperlinks = (len(external_links) / len(hyperlinks) * 100) if hyperlinks else 0
        resources = soup.find_all(['script', 'img', 'link'], src=True)
        external_resources = [res['src'] for res in resources if not res['src'].startswith(url)]
        pct_ext_resource_urls = (len(external_resources) / len(resources) * 100) if resources else 0
        forms = soup.find_all('form')
        insecure_forms = sum(1 for form in forms if form.get('action', '').startswith('http:'))
        null_self_redirect_links = sum(1 for link in hyperlinks if link['href'] in ('#', 'javascript:void(0)'))
        pct_null_self_redirect_hyperlinks = (null_self_redirect_links / len(hyperlinks) * 100) if hyperlinks else 0
        domain_mismatch = parsed_url.netloc not in [urlparse(link['href']).netloc for link in hyperlinks if 'href' in link]
        null_ext_links = sum(1 for link in external_links if link in ('#', 'javascript:void(0)'))
        pct_ext_null_self_redirect_hyperlinks_rt = (null_ext_links / len(external_links) * 100) if external_links else 0
        return {
            'UrlLength': url_length,
            'NumNumericChars': num_numeric_chars,
            'PctExtHyperlinks': pct_ext_hyperlinks,
            'PctExtResourceUrls': pct_ext_resource_urls,
            'InsecureForms': insecure_forms,
            'PctNullSelfRedirectHyperlinks': pct_null_self_redirect_hyperlinks,
            'FrequentDomainNameMismatch': domain_mismatch,
            'PctExtNullSelfRedirectHyperlinksRT': pct_ext_null_self_redirect_hyperlinks_rt
        }
    except Exception as e:
        logging.error(f"Error processing URL {url}: {e}")
        return None

# Prediction function
def predict_url_legitimacy(url):
    features = extract_features_from_url(url)
    if features:
        feature_values = [features[feature] for feature in selected_features]
        prediction = model.predict([feature_values])
        result = "Legitimate" if prediction[0] == 0 else "Phishing"
        logging.info(f"URL: {url}, Prediction: {result}")
        return result
    else:
        logging.error(f"Error extracting features from URL: {url}")
        return "Error extracting features from URL"

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        result = predict_url_legitimacy(url)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    logging.basicConfig(filename='url_prediction.log', level=logging.INFO, 
                        format='%(asctime)s:%(levelname)s:%(message)s')
    app.run(debug=True)

