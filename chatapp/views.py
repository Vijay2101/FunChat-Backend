from django.shortcuts import render, HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
import os
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import hashlib
from datetime import datetime
import jwt
import re
from datetime import timedelta
from pymongo import MongoClient
from dotenv import load_dotenv
from groq import Groq
from httpx import Client
http_client = Client()
# Load .env file
load_dotenv()

mongo_uri = os.environ.get("MONGO_URI")
client = MongoClient(mongo_uri)
db = client['users_data']          # Database name
user_collection = db['users'] 


# Create your views here.

def index(request):
    # return HttpResponse("Hello There!")
    context ={
        "variable":"Hello world"
    }
    return HttpResponse("<h1>Hello!! Server is working.<h1>")









api_key = os.environ.get("GROQ_API_KEY")
# print("api_key: ",api_key)
if not api_key:
    print("GROQ_API_KEY is missing")
# try:


def groq_res(prompt):
    try:
        client = Groq(
            api_key=os.environ.get("GROQ_API_KEY"),
            http_client=http_client
        )
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "user", "content": prompt},
            ],
            model="llama-3.1-70b-versatile",
        )
        res = chat_completion.choices[0].message.content
        return res
    except Exception as e:
        error_message = str(e)  # Convert the error to a string
        print(f"Error occurred: {error_message}")
        # Ensure the returned error message is serializable
        return json.dumps({"error": error_message})



@api_view(['POST'])
def groq_api(request):
    # Extract the prompt from the request body
    prompt = request.data.get('prompt')
    if not prompt:
        return Response({"error": "Prompt is required"}, status=400)

    # Call the groq_res function
    result = groq_res(prompt)
    return Response({"response": result})





# Utility functions
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_valid_password(password):
    return re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password)

def validate_name(name):
    return name.isalpha() and len(name) > 2

def generate_token(user_id):
    secret_key = "your_secret_key"  # Replace with your secret key
    return jwt.encode({"user_id": user_id, "exp": datetime.now() + timedelta(hours=2)}, secret_key, algorithm="HS256")


@csrf_exempt
def signup(request):
    if request.method == "POST":
        try:
            data = request.POST  # For form data
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            confirm_password = data.get('confirmPassword')

            # Allowed fields
            allowed_fields = {'username', 'email', 'password', 'confirmPassword'}
            received_fields = set(data.keys())

            # Check for unexpected fields
            if not received_fields.issubset(allowed_fields):
                return JsonResponse({"error": "Invalid fields detected"}, status=400)

            # Validate email and password
            if not is_valid_email(email):
                return JsonResponse({"message": "Invalid email format"}, status=400)
            if not is_valid_password(password):
                return JsonResponse(
                    {"message": "Password must be at least 8 characters long, include an uppercase letter, lowercase letter, number, and special character"},
                    status=400
                )
            if password != confirm_password:
                return JsonResponse({"message": "Passwords do not match"}, status=400)
            if not validate_name(username):
                return JsonResponse({"message": "Invalid name format"}, status=400)

            # Check if email already exists
            if user_collection.find_one({"professional_email": email}):
                return JsonResponse({"message": "Email already registered"}, status=400)

            # Hash the password
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            # Create the new user record
            new_user = {
                "username": username,
                "professional_email": email,
                "password": hashed_password,
                "created_at": datetime.now(),
                "profile_photo_url": "https://wallpapercrafter.com/desktop1/636078-Bleach-Ichigo-Kurosaki-Zangetsu-Bleach-1080P.jpg"
            }
            result = user_collection.insert_one(new_user)

            if result.inserted_id:
                # Generate token after successful signup
                token = generate_token(str(result.inserted_id))
                return JsonResponse({"message": "Signup successful", "user_id": str(result.inserted_id), "token": token, "email": email}, status=201)
            else:
                return JsonResponse({"message": "Signup failed"}, status=500)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"message": "Invalid request method"}, status=405)




# Utility function to generate token
def generate_token(user_id):
    secret_key = "your_secret_key"  # Replace with your secret key
    return jwt.encode({"user_id": user_id, "exp": datetime.now() + timedelta(hours=2)}, secret_key, algorithm="HS256")


@csrf_exempt
def signin(request):
    if request.method == "POST":
        try:
            data = request.POST  # For form data
            email = data.get('email')
            password = data.get('password')

            # Allowed fields
            allowed_fields = {'email', 'password'}
            received_fields = set(data.keys())

            # Check for unexpected fields
            if not received_fields.issubset(allowed_fields):
                return JsonResponse({"error": "Invalid fields detected"}, status=400)

            # Find user by email only
            user = user_collection.find_one({"professional_email": email})

            if user:
                hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
                token = generate_token(str(user['_id']))

                # Compare the hashed input password with the stored hashed password
                if hashed_input_password == user['password']:
                    return JsonResponse(
                        {
                            "message": "Logged in successfully.",
                            "token": token,
                            "username": user['username'],
                            "user_id": str(user['_id']),
                            "email": email
                        },
                        status=200
                    )
                else:
                    return JsonResponse({"message": "Invalid login credentials"}, status=400)
            else:
                return JsonResponse({"message": "Invalid login credentials"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"message": "Invalid request method"}, status=405)