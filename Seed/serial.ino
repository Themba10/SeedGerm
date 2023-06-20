const int moisturePin = A0;
const int triggerPin = 9;
const int echoPin = 8;
const float calibrationFactor = 15.0 / 14.0; 

const int OpenAirReading = 510;   // calibration data 1
const int WaterReading = 190;     // calibration data 2
int MoistureLevel = 0;
int SoilMoisturePercentage = 0;

void setup() {
  Serial.begin(115200); // open serial port, set the baud rate to 9600 bps
  pinMode(triggerPin, OUTPUT);
  pinMode(echoPin, INPUT);
}

void loop() {
  // SOIL MOISTURE
  MoistureLevel = analogRead(moisturePin);  // update based on the analog Pin selected
  SoilMoisturePercentage = map(MoistureLevel, OpenAirReading, WaterReading, 0, 100);

  if (SoilMoisturePercentage >= 100) {
    SoilMoisturePercentage = 100;
  } else if (SoilMoisturePercentage <= 0) {
    SoilMoisturePercentage = 0;
  }

  // DISTANCE SENSOR
  // Clear the trigger pin
  digitalWrite(triggerPin, LOW);
  delayMicroseconds(2);

  // Set the trigger pin HIGH for 10 microseconds
  digitalWrite(triggerPin, HIGH);
  delayMicroseconds(10);
  digitalWrite(triggerPin, LOW);

  // Measure the duration of the echo pulse
  long duration = pulseIn(echoPin, HIGH);

  // Calculate the distance using the speed of sound (343 m/s)
  // Adjust the speed of sound for 3.3V operation (331 m/s)
  // float distance = duration * 0.0331 / 2;
  float distance = (duration * 0.0343 / 2) * calibrationFactor;

  // Send the moisture and distance values over the serial port
  Serial.print(SoilMoisturePercentage);
  Serial.print(",");
  Serial.print(distance);
  Serial.println();

  delay(1000);
}
