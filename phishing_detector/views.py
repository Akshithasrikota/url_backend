from django.shortcuts import render
import os
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import joblib
import re 
from rest_framework.decorators import api_view
from rest_framework.response import Response

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_detector", "model")  
classifier = joblib.load(os.path.join(MODEL_PATH, "rf_model.pkl"))


#57
def ssl_final_state(url):
    return 1 if url.startswith("https") else -1
#62
def url_length(url):
    return -1 if len(url) > 54 else 1
#59
def favicon(url):
    try:
        domain = tldextract.extract(url)
        favicon_url = f"https://{domain.domain}.{domain.suffix}/favicon.ico"
        response = requests.get(favicon_url, timeout=5)
        return 1 if response.status_code == 200 else -1
    except:
        return -1
#58
def iframe(url):
    try:
        response = requests.get(url, timeout=5)
        return -1 if "<iframe" in response.text.lower() else 1
    except:
        return -1
#61
def dns_record(url):
    try:
        domain = tldextract.extract(url).fqdn
        socket.gethostbyname(domain)
        return 1
    except:
        return -1
def extract_features_test(url):
  parsed = urlparse(url)
  hostname = parsed.hostname if parsed.hostname else ''
  path = parsed.path if parsed.path else ''
  features = []

    # 1. URL Length
  features.append(len(url))

    # 2. Hostname Length
  features.append(len(hostname))

  # 4,5,7,8,10,11,14,18. Special Characters Count
  special_chars = ['.', '-', '?', '&', '=', '_', '/', ';']
  features.extend([url.count(ch) for ch in special_chars])
  # 21. Common Terms Count
  common_terms = ['www']
  features.extend([url.count(term) for term in common_terms])

      # 25. HTTPS Token Check
  features.append(1 if 'https' in url else 0)
  # 26-27. Ratio of Digits
  features.append(sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0)
  features.append(sum(c.isdigit() for c in hostname) / len(hostname) if len(hostname) > 0 else 0)
 # 33. Number of Subdomains
  features.append(len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0)

  #   # 34. Prefix-Suffix Check
  # features.append(1 if '-' in hostname else 0)
   # 40-47. NLP Features
  words_url = re.split(r'\W+', url)
  words_hostname = re.split(r'\W+', hostname)
  words_path = re.split(r'\W+', path)
  features.append(len(words_url))  # 40
  features.append(max([url.count(ch) for ch in set(url)]) if url else 0)  # 41
  features.append(min([len(word) for word in words_url if word]) if words_url else 0)  # 42
  # features.append(min([len(word) for word in words_hostname if word]) if words_hostname else 0)  # 43
    # features.append(min([len(word) for word in words_path if word]) if words_path else 0)  # 44
  features.append(min([len(word) for word in words_path if word]) if words_path and any(words_path) else 0)  # 44
  features.append(max([len(word) for word in words_url if word]) if words_url else 0)  # 45
  features.append(max([len(word) for word in words_hostname if word]) if words_hostname and any(words_hostname) else 0)  # 46
    # features.append(max([len(word) for word in words_path if word]) if words_path else 0)  # 47
  features.append(max([len(word) for word in words_path if word]) if words_path and any(words_path) else 0)  # 47


    # 48-50. Average Word Lengths
  features.append(sum(len(word) for word in words_url) / len(words_url) if words_url else 0)
  features.append(sum(len(word) for word in words_hostname) / len(words_hostname) if words_hostname else 0)
  features.append(sum(len(word) for word in words_path) / len(words_path) if words_path else 0)
   # 52. Brand Domain Check
  brand_domains = ['paypal', 'facebook', 'google']
  features.append(1 if any(brand in hostname for brand in brand_domains) else 0)
  #57,62
  features.append(ssl_final_state(url))
  features.append(favicon(url))
  # features.append(iframe(url))
  features.append(dns_record(url))
  features.append(url_length(url))
  return features

@api_view(["POST"])
def predict_url(request):
    url = request.data.get("url", "")
    if not url:
        return Response({"error": "No URL provided"}, status=400)

    data = [extract_features_test(url)]
    
    prediction = classifier.predict(data)[0]
    result = "Phishing" if prediction == 0 else "Not Phishing"

    return Response({"url": url, "prediction": result})




import logging
from django.conf import settings
from django.core.files.storage import default_storage


logger = logging.getLogger(__name__)  



def read_file(file_path):
    try:
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.endswith('.xlsx'):
            df = pd.read_excel(file_path)
        elif file_path.endswith('.json'):
            df = pd.read_json(file_path)
        elif file_path.endswith('.tsv'):
            df = pd.read_csv(file_path, sep='\t')
        else:
            print("Unsupported file format. Please use CSV, Excel, JSON, or TSV.")
            return None
        return df
    except Exception as e:
        print(f"Error reading file: {e}")
        return None



logger = logging.getLogger(__name__)  

@api_view(["POST"])
def upload_file(request):
    try:
        uploaded_file = request.FILES.get("file")
        if not uploaded_file:
            return Response({"error": "No file uploaded"}, status=400)

        
        file_path = default_storage.save(uploaded_file.name, uploaded_file)
        file_full_path = os.path.join(settings.MEDIA_ROOT, file_path)

        # Read the file (assuming CSV)
        #df = pd.read_csv(file_full_path)
        df=read_file(file_full_path)
        if df is None:
            return 
          

    
        if len(df.columns) == 1:
            df.columns = ['url']
        elif 'url' not in df.columns:
            logger.error("File must contain a column named 'url' or a single column with URLs")
            return Response({"error": "File must contain a column named 'url' or a single column with URLs"}, status=400)

        
        data = [extract_features_test(url) for url in df['url']]
        data = np.array(data).reshape(len(data), -1)

        predictions = classifier.predict(data)
        df["Prediction"] = ["Phishing" if pred == 0 else "Not Phishing" for pred in predictions]

        result_file_name = uploaded_file.name.replace(".csv", "_results.csv")
        result_file_path = os.path.join(settings.MEDIA_ROOT, result_file_name)
        df.to_csv(result_file_path, index=False)


        return Response({
            "message": "Predictions saved",
            "file_path": f"/media/{result_file_name}"  
        })

    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        return Response({"error": str(e)}, status=500)


from django.http import FileResponse
from django.conf import settings

@api_view(["GET"])
def download_file(request):
    try:
        file_name = request.GET.get("file_name")  
        file_path = os.path.join(settings.MEDIA_ROOT, file_name)

        if os.path.exists(file_path):
            return FileResponse(open(file_path, "rb"), as_attachment=True, filename=file_name)
            
        else:
            return Response({"error": "File not found"}, status=404)
        
    
    except Exception as e:
        return Response({"error": str(e)}, status=500)


