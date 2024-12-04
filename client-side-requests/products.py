import requests

# URL of your Flask application
base_url = 'http://localhost:5000'

# Shared key
key = ''
response = requests.post('http://localhost:5000/certificate/generate', json={"client_id":"563dc4"})
print(response.text)
key = response.text

# Product details
product = {
    'name': 'Product 1',
    'description': 'This is product 1',
    'price': 19.99,
    'image_url': 'http://example.com/product1.png',
    'certificate': key
}

# Create a product
response = requests.post(f'{base_url}/product', json=product)
print(response.json())

# Assume the product ID is 1
product_id = 1
product_name = product['name']

# Get a product
response = requests.get(f'{base_url}/product/{product_id}', json={'certificate': key})
print(response.json())

# Get all products
response = requests.get(f'{base_url}/products', json={'certificate': key})
print(response.json())

# Update a product
product['name'] = 'Updated Product 1'
response = requests.put(f'{base_url}/product/{product_id}', json=product)
print(response.json())

# Delete a product
response = requests.delete(f'{base_url}/product/{product_id}', json={'certificate': key})
print(response.status_code)