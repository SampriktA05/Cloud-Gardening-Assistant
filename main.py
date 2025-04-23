from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from pymongo import MongoClient
from pydantic import BaseModel
from datetime import datetime, timezone
import requests, os
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from typing import Optional

load_dotenv()

# FastAPI App
app = FastAPI()

app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

# JWT and Auth Setup
SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# MongoDB 
client = MongoClient(os.getenv("MONGODB_URI"), server_api=ServerApi('1'))

db = client["gardening_db"]
users_collection = db["users"]
plants_collection = db["plants"]

# Models
class Token(BaseModel):
	access_token: str
	token_type: str

class PlantCareRequest(BaseModel):
	plant_name: str
	user_id: str
	current_temp: float
	current_humidity: float
	current_sunlight: str
	rainfall_mm: float
	soil_ph: float

class WaterLog(BaseModel):
	user_id: str
	plant_name: str
	soil_ph: float
	notes: Optional[str] = None

class CareTipRequest(BaseModel):
	user_id: str
	plant_name: str
	soil_ph: float
	location: str

# Helpers
def verify_password(plain, hashed):
	return pwd_context.verify(plain, hashed)

def get_user(username: str):
	return users_collection.find_one({"username": username})

def authenticate_user(username: str, password: str):
	user = get_user(username)
	if not user or not verify_password(password, user["hashed_password"]):
		return False
	return user

def create_token(data: dict):
	to_encode = data.copy()
	expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
	to_encode.update({"exp": expire})
	return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_weather(city: str):
	base_url = "http://api.openweathermap.org/data/2.5/weather?"
	complete_url = base_url + "appid=" + os.getenv("OPENWEATHER_API_KEY") + "&q=" + city
	response = requests.get(complete_url)
	weather_data = response.json()
	if weather_data.get("cod") != 200:
		raise HTTPException(status_code=404, detail="City not found")

	return {
		"temperature": weather_data["main"]["temp"],
		"humidity": weather_data["main"]["humidity"],
		"sunlight": weather_data["weather"][0]["main"],  # e.g., Clouds, Rain
		"rainfall": weather_data.get("rain", {}).get("1h", 0)  # May be missing
	}

@app.get("/api/plants")
def get_plants_by_category(category: str):
	plants = db.plants.find({"category": category}, {"_id": 0, "name": 1})
	return list(plants)

@app.get("/api/plant-details")
def get_plant_details(name: str):
	plant = db.plants.find_one({"name": name}, {"_id": 0})
	if not plant:
		raise HTTPException(status_code=404, detail="Plant not found")
	return plant

@app.post("/api/care-tips")
def generate_care_tips(data: CareTipRequest):
	print(data)
	plant = db.plants.find_one({"name": data.plant_name})
	print(plant)
	if not plant:
		raise HTTPException(status_code=404, detail="Plant not found")

	weather = get_weather(data.location)
	temp = weather['temperature']
	humidity = weather['humidity']
	rainfall = weather['rainfall']
	sunlight = weather['sunlight']

	last_watered = list(db.watering_logs.find({"plant_name": data.plant_name, "user_id": data.user_id}, {"_id": 0, "date": 1}).sort("date", -1).limit(1))[0]["date"]
	print(last_watered)
	if last_watered.tzinfo is None:
		last_watered = last_watered.replace(tzinfo=timezone.utc)
	days_since_last_watered = (datetime.now(timezone.utc) - last_watered).days
	print(days_since_last_watered)

	tips = []
	if temp < plant['temperature']['min']:
		tips.append("It's colder than ideal. Keep the plant indoors.")
	if humidity < plant['humidity']['min']:
		tips.append("Humidity is low. Consider misting the plant.")
	if abs(data.soil_ph - plant['soil_ph']) > 0.5:
		tips.append("Adjust the soil pH to match plant's preference.")
	if days_since_last_watered < plant['watering_frequency_days']:
		tips.append(f"Water {plant['name']} soon. It's been {days_since_last_watered} day(s) since it was last watered.")

	return {
		"weather": {
			"temperature": temp,
			"humidity": humidity,
			"rainfall": rainfall,
			"sunlight": sunlight
		},
		"last_watered": str(last_watered) if last_watered else "Never",
		"tips": tips
	}

@app.get("/api/watering-log")
def get_watering_log(plant: str, user_id: str):
	logs = db.watering_logs.find({"plant_name": plant, "user_id": user_id}, {"_id": 0})
	return list(logs)


@app.post("/api/watering-log")
def add_watering_log(log: WaterLog):
	log_dict = log.model_dump()
	log_dict["date"] = datetime.now(timezone.utc)
	db.watering_logs.insert_one(log_dict)
	print(log_dict)
	return {"message": "Watering log added successfully"}

@app.get("/api/weekly-tracker")
def get_weekly_watering(user_id: str, plant: str, city: str):
	try:
		# 🌧️ Fetch rainfall
		rainfall = get_weather(city)

		# 🌱 Fetch plant's watering frequency
		plant_data = db.plants.find_one({"name": plant})
		if not plant_data:
			raise HTTPException(status_code=404, detail=f"No plant found with name '{plant}'")

		frequency = plant_data.get("watering_frequency_days")
		if frequency is None:
			raise HTTPException(status_code=500, detail="Missing watering frequency in plant data")

		# 🧾 Get most recent watering log
		log = db.watering_logs.find_one(
			{"user_id": user_id, "plant_name": plant},
			sort=[("date", -1)]
		)

		print("🌱 Last watering log:", log)

		now = datetime.now(timezone.utc)

		if not log:
			return {
				"plant": plant,
				"last_watered": "Never",
				"weather_rainfall": rainfall,
				"recommended_interval": frequency,
				"message": f"No watering history found. Consider watering {plant} today."
			}

		last_watered = log.get("date")
		print("🕒 Raw date:", last_watered)

		if isinstance(last_watered, str):
			last_watered = datetime.fromisoformat(last_watered)
		elif not isinstance(last_watered, datetime):
			raise HTTPException(status_code=500, detail="Invalid date format in log")

		next_due = last_watered + timedelta(days=frequency)

		if now >= next_due:
			if rainfall > 1:
				message = f"{plant} was due for watering, but today's rainfall may be sufficient."
			else:
				message = f"It's time to water your {plant}."
		else:
			days_left = (next_due - now).days
			message = f"No need to water {plant} yet. Water again in {days_left} day(s)."

		return {
			"plant": plant,
			"last_watered": last_watered.isoformat(),
			"weather_rainfall": rainfall,
			"recommended_interval": frequency,
			"message": message
		}

	except Exception as e:
		import traceback
		traceback.print_exc()
		raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
	user = authenticate_user(form_data.username, form_data.password)
	if not user:
		raise HTTPException(status_code=401, detail="Invalid credentials")
	token = create_token({"sub": user["username"]})
	return {"access_token": token, "token_type": "bearer"}

@app.get("/dashboard")
def dashboard(city: str, soil_ph: float, plant_name: str, token: str = Depends(oauth2_scheme)):
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username = payload.get("sub")
		user = get_user(username)
		request = CareTipRequest(plant_name=plant_name, soil_ph=soil_ph, location=city)
		return generate_care_tips(request)
	except JWTError:
		raise HTTPException(status_code=403, detail="Invalid token")