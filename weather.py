import requests

API_KEY = "be9369d89c19f31e98bfced2072e5385" 
CITY = "Lagos"     
URL = f"http://api.openweathermap.org/data/2.5/weather?q={CITY}&appid={API_KEY}&units=metric"

response = requests.get(URL)

data = response.json()

if response.status_code == 200:
    city = data['name']
    temp = data['main']['temp']
    description = data['weather'][0]['description']
    
    print(f"Weather in {city}:")
    print(f"Temperature: {temp}°C")
    print(f"Condition: {description}")
else:
    print("Error fetching weather data:",
data.get("message", "Unknown error"))
