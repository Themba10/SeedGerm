from flask import Flask, render_template, request, redirect, session, jsonify, make_response
import requests
from reportlab.pdfgen import canvas
import csv
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from firebase_admin import auth
from functools import wraps
import uuid, random, string, re, time, json, hashlib, os
import threading, time
import datetime, socket
import schedule, scheduler, subprocess
from apscheduler.schedulers.background import BackgroundScheduler


#Raspberry Pi setup for now
from w1thermsensor import W1ThermSensor
import RPi.GPIO as GPIO
import serial, math

# Serial Communication
ser = serial.Serial('/dev/ttyACM0', 115200)
#'/dev/ttyACM0', 115200
# Set up GPIO
# Soil Temperature setup
sensor = W1ThermSensor()

GPIO.setwarnings(False) 
# Relay GPIO FOR WATER PUMP
GPIO.setmode(GPIO.BCM)
relay_pin_pump = 22
GPIO.setup(relay_pin_pump, GPIO.OUT)

# Turn OFF the relay as it is in NC
GPIO.output(relay_pin_pump, GPIO.HIGH) 

# Relay GPIO FOR BULB
ldr_sensor_pin =26
relay_pin_bulb = 17
GPIO.setup(ldr_sensor_pin, GPIO.IN)
GPIO.setup(relay_pin_bulb, GPIO.OUT, initial = GPIO.HIGH)

# Dictionary to store user-specific Raspberry Pi instances
raspberry_pis = {}
user_ids = []

relay_state = False
relay_lock = threading.Lock()

# Define a class for Raspberry Pi instances
def get_ip_address():
    # Run the "ipconfig" command and retrieve the output
    try:
        # Create a socket connection to remote host
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8",80))
            ip_address = s.getsockname()[0]
            return ip_address
    except socket.error:
        return None

def get_mac_address():
    # Run the "getmac" command and retrieve the output
    output = subprocess.check_output(['getmac']).decode('utf-8')
    
    # Use regular expressions to extract the MAC address from the output
    mac_address_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
    if mac_address_match:
        mac_address = mac_address_match.group(0)
        return mac_address
    
    # If no MAC address is found, return None or raise an exception
    return None

# SNippet to update regualry
#mac_id = get_mac_address()
        
# Create a scheduler
scheduler = BackgroundScheduler()

def push_sensor_readings_task():
    user_ref = db.reference('/users')
    users = user_ref.get()
    if users:
        user_ids = list(users.keys())
        for user_id in user_ids:
            print("Pushing sensor readings for user:", user_id)
            push_sensor_readings(user_id)
        
def push_sensor_readings(user_id):
    print("Pushing sensor readings for user:", user_id)
    # Get the sensor readings for the Raspberry Pi instance
    # Read the sensor data
    moisture, water_level = read_serial_data(ser)
    soil_temperature = read_soil_temperature()

    # Push the sensor readings to the user's data
    sensor_readings_ref = db.reference('/users/{}/sensor_readings/Environment'.format(user_id))
    sensor_readings_ref.set({
        'soil_temperature': soil_temperature,
        'water_level': water_level,
        'moisture': moisture,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
scheduler.add_job(push_sensor_readings_task, 'interval', seconds=20)    
scheduler.start()

def read_ldr_state():
    while True:
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(ldr_sensor_pin, GPIO.IN)
        GPIO.setup(relay_pin_bulb, GPIO.OUT, initial = GPIO.HIGH)
        
        ldr_state = GPIO.input(ldr_sensor_pin)
        if ldr_state == GPIO.LOW:
            #print("Light Detected")
            GPIO.output(relay_pin_bulb,1)
            time.sleep(2)
        else:
            #print("No light Detected")
            GPIO.output(relay_pin_bulb,0)
            time.sleep(2)
# Create and start the thread for reading LDR state
ldr_thread = threading.Thread(target=read_ldr_state)
ldr_thread.daemon = True
ldr_thread.start()

app = Flask(__name__)
app.secret_key = 'my-secrete'

app.config['SESSION_TYPE'] = 'filesytem'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_USER_TOKEN'] = 'firebase_token'
app.config.from_object(__name__)

cred = credentials.Certificate("rpi-germination-firebase-adminsdk-o4o4y-337b5fedbd.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': "https://rpi-germination-default-rtdb.firebaseio.com/"
})


# Function to read temperature from DBS120 sensor
def read_soil_temperature():
    # Setup the DBS120
    sensor = W1ThermSensor()

    # Simulate temperature reading from DBS120
    # e.g temperature = 25.5
    temperature = sensor.get_temperature()
    temperature = round(temperature,2)
    
    return temperature

#start_sensor_readings_background(mac_id)

def read_serial_data(ser):
    ser.flushInput()
    
    while True:
        if ser.inWaiting() > 0:
            data = ser.readline().decode().strip()
            moisture, water_level = data.split(',')
            return moisture, water_level

@app.before_request
def start_scheduler():
    if not scheduler.running:
        scheduler.add_job(push_sensor_readings_task, 'interval', seconds=5)
        scheduler.start()
# Flask route for handling errors
@app.errorhandler(500)
def internal_server_error(error):
    return "Something went wrong. Please contact a technician.", 500

@app.route('/')
def index():
    return render_template('index.html')

# Define a decorator function to check if the user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        firebase_token = session.get(app.config['SESSION_USER_TOKEN'])
        if 'firebase_token' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/login')
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get the form data
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        phone = request.form.get('phone')

        # Check if the username, password, email, and phone are not empty
        if not username or not password or not confirm_password or not email or not phone:
            return render_template('register.html', error='Please fill out all the fields')

        # Check if the password and confirm_password match
        if password != confirm_password:
            return render_template('register.html', error='Password and Confirm Password do not match')

        # Check password requirements
        if not is_valid_password(password):
            return render_template('register.html', error='Invalid password. Password should have at least 8 characters, contain at least one uppercase letter, one lowercase letter, and one digit.')

        # Check if the username already exists
        user_ref = db.reference('/users')
        users = user_ref.get()
        if users:
            for user_id, user in users.items():
                if 'username' in user and user['username'] == username:
                    return render_template('register.html', error='Username already exists')

        # Register the user with Firebase Authentication
        try:
            user = auth.create_user(
                email=email,
                password=password,
                display_name=username
            )
        except auth.EmailAlreadyExistsError:
            return render_template('register.html', error='Email already exists')
        except auth.WeakPasswordError:
            return render_template('register.html', error='Weak password. Password should have at least 6 characters')

        # Create the user in the Firebase Realtime Database
        user_id = user.uid
        new_user_ref = user_ref.child(user_id)
        new_user_ref.set({
            'username': username,
            'email': email,
            'phone': phone
        })

        # Get the IP address and MAC address of the Raspberry Pi instance
        ip_address = get_ip_address()
        mac_address = get_mac_address()

        # Create the Raspberry Pi instance under the user's information
        raspberry_pi_ref = new_user_ref.child('raspberry_pi')
        raspberry_pi_ref.set({
            'ip_address': ip_address,
            'mac_address': mac_address
        })

        # Push initial sensor readings for the new user
        push_sensor_readings(user_id)

        return redirect('/login')
    
    return render_template('register.html')

# Login route
# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the form data
        email = request.form.get('email')
        password = request.form.get('password')
        #email = request.form.get('email')
        
        print("email:", email)
        print("Password:", password)

        # Authenticate the user using the Firebase JavaScript SDK
        auth_payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        response = requests.post(
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyDnPxPo2FqHrzPl-d8RvcpqS0bRh-KqFpw",
            json=auth_payload
        )
        print(response)
        
        if response.status_code == 200:
            # Authentication successful
            firebase_token = response.json().get('idToken')
            print("Firebase Token:", firebase_token)

            # Store the Firebase ID token in the session
            session['firebase_token'] = firebase_token

            return redirect('/dashboard')
        else:
            # Authentication failed
            error_message = response.json().get('error').get('message')
            print("Error:", error_message)
            return render_template('login.html', error=error_message)

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    # Get the Firebase ID token from the client
    firebase_token = session.get('firebase_token')
    print("Firebase Token from session : " ,firebase_token) 
    
    try:
        # Verify and decode the ID token
        decoded_token = auth.verify_id_token(firebase_token)
        # Get the user ID from the decoded token
        user_id = decoded_token['uid']
        
        # Retrieve the user_data from the database using user_id
        user_ref = db.reference('/users/{}'.format(user_id))
        user_data = user_ref.get()
        
        if user_data:
            username = user_data.get('username')
            sensor_readings = user_data.get('sensor_readings', {}).get('Environment', {})
            return render_template('dashboard.html', sensor_readings=sensor_readings, username=username)
    
    except auth.InvalidIdTokenError:
        return redirect('/login')
    
@app.route('/relay/on', methods=['POST'])
def turn_relay_on():
    GPIO.setup(relay_pin_pump, GPIO.OUT)

    # Turn OFF the relay as it is in NC
    GPIO.output(relay_pin_pump, GPIO.LOW)
    
    relay_state = 'Relay turned on'
    time.sleep(3)
    GPIO.output(relay_pin_pump, GPIO.HIGH)
    
    return redirect('/dashboard')

@app.route('/relay/off', methods=['POST'])
def turn_relay_off():
    GPIO.setup(relay_pin_pump, GPIO.OUT)

    # Turn OFF the relay as it is in NC
    GPIO.output(relay_pin_pump, GPIO.HIGH)
    relay_state = 'Relay turned off'

    return redirect('/dashboard')

# Logout route
@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()
    return redirect('/login')

# Regulate temperature route
@app.route('/regulate_temperature', methods=['POST'])
@login_required
def regulate_temperature():
    # Get the user ID from the session
    user_id = session['user_id']

    # Get the current room temperature from the Firebase Realtime Database
    moisture_ref = db.reference(f'/users/{user_id}/sensor_readings/Environment/moisture')
    moisture = moisture_ref.get()

    if moisture < 30:
        # Activate the relay connected to pin 17
        GPIO.output(relay_pin_pump, GPIO.LOW)  # Set relay_pin to LOW to activate the relay

    return redirect('/dashboard')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_email = request.form.get('new-email')
        new_password = requests.form.get('new-password')
        new_phone = requests.form.get('new-phone')
        
        user_ref = db.collection('users').document(user_id)
        user_ref.update({
            'email': new_email,
            'password': new_password,
            'phone': new_phone
        })
        return 'Settings updated successfully'
    else:
        return render_template('settings.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')


@app.route('/download_report_pdf', methods=['GET'])
def download_report_pdf():
    # Fetch the data needed for the report
    # Replace the placeholders with your actual data retrieval logic
    username = "Susan"
    soil_temperature = "25"
    moisture = "60"
    water_level = "75"

    # Create a response object
    response = make_response(generate_pdf_report(username, soil_temperature, moisture, water_level))
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    response.headers['Content-Type'] = 'application/pdf'

    return response

@app.route('/download_report_csv', methods=['GET'])
def download_report_csv():
    # Fetch the data needed for the report
    # Replace the placeholders with your actual data retrieval logic
    username = "John Doe"
    soil_temperature = "25"
    moisture = "60"
    water_level = "75"

    # Create a response object
    response = make_response(generate_csv_report(username, soil_temperature, moisture, water_level))
    response.headers['Content-Disposition'] = 'attachment; filename=report.csv'
    response.headers['Content-Type'] = 'text/csv'

    return response


def generate_pdf_report(username, soil_temperature, moisture, water_level):
    # Create a new PDF document
    report_pdf = canvas.Canvas('report.pdf')

    # Set up the PDF content
    report_pdf.setFont("Helvetica", 12)
    report_pdf.drawString(100, 700, f"Username: {username}")
    report_pdf.drawString(100, 680, f"Soil Temperature: {soil_temperature}°C")
    report_pdf.drawString(100, 660, f"Moisture: {moisture}%")
    report_pdf.drawString(100, 640, f"Water Level: {water_level}%")

    # Save the PDF document
    report_pdf.save()

    # Read the generated PDF file
    with open('report.pdf', 'rb') as f:
        pdf_data = f.read()

    return pdf_data

def generate_csv_report(username, soil_temperature, moisture, water_level):
    # Create a list with the report data
    report_data = [
        ['Username', 'Soil Temperature', 'Moisture', 'Water Level'],
        [username, soil_temperature, moisture, water_level]
    ]

    # Create a new CSV file
    with open('report.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(report_data)

    # Read the generated CSV file
    with open('report.csv', 'rb') as f:
        csv_data = f.read()

    return csv_data



# Check for the requirements of the password
def is_valid_password(password):
    # Minimum length of 8 characters
    if len(password) < 8:
        return False

    # Contains at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # Contains at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # Contains at least one digit
    if not re.search(r'\d', password):
        return False

    # Contains at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False

    return True

# Feedback if the username already exists
def is_username_taken(username):
    users_ref = db.reference('/users')
    query = users_ref.order_by_child('username').equal_to(username).get()
    return query

# Hashing function
def hash_password(password, salt):
    # Concatenate the password and salt
    salted_password = password.encode() + salt.encode()

    # Use a hashing algorithm (e.g., SHA256)
    hashed_password = hashlib.sha256(salted_password).hexdigest()

    return hashed_password

# Verify Password
def verify_password(password, hashed_password, salt):
    # Hash the input password with the given salt
    hashed_input_password = hash_password(password, salt)
    
    # Compare the hashed passwords
    return hashed_input_password == hashed_password


    #Schedule.every 30 seconds
    #sensor_thread = threading.Thread(target =start_sensor_readings_schedule, args=(mac_id,))
    #sensor_thread.start()
        
# Automating the user_id generation
def generate_user_id():
    return str(uuid.uuid4())

def generate_reading_id():
    return str(uuid.uuid4())

def generate_sensor_id():
    return str(uuid.uuid4())

def get_Current_user_id():
    # Get the ID token from the session
    id_token = session.get('id_token')

    if id_token:
        try:
            # Verify the ID token and get the user ID
            decoded_token = auth.verify_id_token(id_token)
            user_id = decoded_token['uid']
            return user_id
        except auth.InvalidIdTokenError:
            # Invalid ID token, handle the error as needed
            return None
    else:
        # No ID token provided, handle the error as needed
        return None

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)


