import requests

key = ''

response = requests.post('http://localhost:5000/certificate/generate', json={"client_id":"814ebb", "client_password":'bbe418'})
print(response.text)
key = response.text

response = requests.post('http://localhost:5000/certificate/validate', json={"certificate":key})
print(response.text)