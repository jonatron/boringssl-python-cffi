import httpcore
from boring_backend import BoringBackend, BoringStream

http = httpcore.ConnectionPool(network_backend=BoringBackend())
response = http.request("GET", "https://www.example.com/")
print("response", response)
print("response.content", response.content)
print("response.headers", response.headers)
