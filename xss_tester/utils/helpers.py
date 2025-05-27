import requests

def inject_payload(url, payload, timeout=5):
    try:
        response = requests.get(url + payload, timeout=timeout)
        return payload in response.text
    except Exception as e:
        return False

