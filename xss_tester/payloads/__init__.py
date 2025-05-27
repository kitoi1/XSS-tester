# Payload loader
import json
import os

def load_payloads(path):
    with open(path, 'r') as file:
        return json.load(file)

