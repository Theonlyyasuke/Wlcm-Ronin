import datetime
from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

# --- Mock Data (simulating a database or live weather service) ---

# mock_db = {
#     "Lagos": {
#         "current": {
#             "temperature": 29,
#             "wind_speed": 15,
#             "feels_like": 34,
#             "pressure": 1010,
#             "humidity": 85,
#             "description": "Partly cloudy with a chance of showers",
#             "last_updated": datetime.datetime.now().isoformat()
#         },
#         "forecast": [
#             {"hour": 13, "temp": 30, "desc": "Sunny"},
#             {"hour": 14, "temp": 31, "desc": "Sunny intervals"},
#             {"hour": 15, "temp": 31, "desc": "Cloudy"},
#             {"hour": 16, "temp": 30, "desc": "Chance of rain"},
#         ],
#         "history": [
#             {"date": "2025-09-15", "avg_temp": 28, "precipitation": 5},
#             {"date": "2025-09-14", "avg_temp": 30, "precipitation": 0},
#         ],
#         "alerts": []
#     },
#     "Kano": {
#         "current": {
#             "temperature": 34,
#             "wind_speed": 10,
#             "feels_like": 33,
#             "pressure": 1005,
#             "humidity": 40,
#             "description": "Clear and sunny",
#             "last_updated": datetime.datetime.now().isoformat()
#         },
#         "forecast": [
#             {"hour": 13, "temp": 35, "desc": "Sunny"},
#             {"hour": 14, "temp": 36, "desc": "Sunny"},
#             {"hour": 15, "temp": 35, "desc": "Sunny"},
#             {"hour": 16, "temp": 34, "desc": "Clear skies"},
#         ],
#         "history": [
#             {"date": "2025-09-15", "avg_temp": 33, "precipitation": 0},
#             {"date": "2025-09-14", "avg_temp": 34, "precipitation": 0},
#         ],
#         "alerts": [
#             {
#                 "id": "KANO-HEAT-01",
#                 "type": "Heat Advisory",
#                 "details": "Extreme heat expected between 2 PM and 5 PM. Stay hydrated."
#             }
#         ]
#     }
# }

def get_current_weather(city_name):
    url = f"http://api.weatherapi.com/v1/current.json?q={city_name}&key=282dd522f7c148c3b9b82718251909"

    headers = {

    }

    response = requests.get(url=url, headers=headers)

    print(response)

    return response.json()


# --- API Endpoints ---

@app.route('/', methods=['GET'])
def get_current_weather_index():
    """Provides current weather data for a specified location."""
    # Get location from query parameter, e.g., ?location=Lagos
    # It defaults to 'Lagos' if no location is provided
    location = request.args.get('location', 'Lagos')
    
    return jsonify(get_current_weather(location))

@app.route('/api/v1/weather/forecast/hourly', methods=['GET'])
def get_hourly_forecast():
    """Provides hourly weather forecast for a specified location."""
    location = request.args.get('location', 'Lagos')
    
    if location in mock_db:
        return jsonify(mock_db[location]["forecast"])
    else:
        return jsonify({"error": "Location not found"}), 404

@app.route('/api/v1/weather/history', methods=['GET'])
def get_historical_weather():
    """Provides historical weather data for analysis."""
    location = request.args.get('location', 'Lagos')
    
    if location in mock_db:
        return jsonify(mock_db[location]["history"])
    else:
        return jsonify({"error": "Location not found"}), 404

@app.route('/api/v1/weather/alerts', methods=['GET'])
def get_weather_alerts():
    """Provides active weather alerts for safety."""
    location = request.args.get('location', 'Lagos')
    
    if location in mock_db:
        alerts = mock_db[location]["alerts"]
        if not alerts:
            return jsonify({"message": f"No active alerts for {location}."})
        return jsonify(alerts)
    else:
        return jsonify({"error": "Location not found"}), 404


if __name__ == '__main__':
    # The 'debug=True' argument allows you to see errors and auto-reloads the server on code changes.
    app.run(debug=True)