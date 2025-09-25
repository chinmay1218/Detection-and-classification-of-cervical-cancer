# utils.py

import requests

def send_scan_to_roboflow(image_path):
    API_URL = "https://detect.roboflow.com/cervical_cancel/1"
    API_KEY = "Ax4LhZgUTmUL8cGMbYUU"

    try:
        with open(image_path, 'rb') as image_file:
            files = {'file': image_file}
            params = {'api_key': API_KEY}

            response = requests.post(API_URL, files=files, params=params)
            response.raise_for_status()
            return response.json()  # Return the prediction result

    except requests.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
