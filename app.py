from flask import *
import requests

app = Flask(__name__)

@app.route('/')
def index():
    with open('clientsidekey.txt', 'r') as file:
        return file.read()
    
def get_key():
    response = requests.post('http://localhost:5000/certificate/generate', json={"client_id":"814ebb", "client_password":'bbe418'})
    with open('clientsidekey.txt', 'w') as file:
        return file.writelines(response.text)
    
def validate_key():
    with open('clientsidekey.txt', 'r') as file:
        response = requests.post('http://localhost:5000/certificate/validate', json={"certificate":file.read()})
        print("Response: ", response.text)

def start():
    counter = 0
    for i in range(1):
        get_key()
        validate_key()
        counter += 1

if __name__ == '__main__':
    start()
    app.run(debug=True, port=5001)