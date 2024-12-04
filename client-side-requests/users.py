import requests

email = "test@example.com"

key = ''
response = requests.post('http://localhost:5000/certificate/generate', json={"client_id":"814ebb"})
print(response.text)
key = response.text

# Create a user
response = requests.post('http://localhost:5000/user', json={"email":email, "password":"password", "certificate":key})
print(response.text)
print(response.status_code)
if 'fs_uniquifier' in response.json():
    fs_uniquifier = response.json()['fs_uniquifier']
else:
    print("Error: 'fs_uniquifier' not in response")
    fs_uniquifier = None

# Get the user's details
response = requests.get(f'http://localhost:5000/user/{fs_uniquifier}', json={"certificate":key})
print(response.json())

# Get the user by email
response = requests.get(f'http://localhost:5000/user/email/{email}', json={"certificate":key})
print(response.json())

# Update the user's email
response = requests.put(f'http://localhost:5000/user/{fs_uniquifier}', json={"email":"new@example.com", "certificate":key})
print(response.json())

# Delete the user
response = requests.delete(f'http://localhost:5000/user/{fs_uniquifier}', json={"certificate":key})
print(response.status_code)