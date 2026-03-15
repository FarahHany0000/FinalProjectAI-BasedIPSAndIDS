from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import sklearn
import csv
from datetime import datetime
import os

app = FastAPI()

# --- 1. إعدادات المسارات والملفات ---
# تأكدي أن مسار الموديل صحيح على جهازك
MODEL_PATH = r"C:\Users\DELL\Downloads\model.pkl"
LOG_FILE = "attacks_log.csv"

# إنشاء ملف السجل وعناوين الأعمدة إذا لم يكن موجوداً
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Device_Count", "Email_Count", "HTTP_Count", "Prediction", "Action"])

model = None
scaler = None

# --- 2. تحميل الموديل عند تشغيل السيرفر ---
@app.on_event("startup")
def load_model():
    global model, scaler
    try:
        loaded_data = joblib.load(MODEL_PATH)
        if isinstance(loaded_data, (tuple, list)):
            scaler = loaded_data[0]
            potential_model = loaded_data[1]
            # التأكد من استخراج الموديل حتى لو كان داخل قائمة
            model = potential_model[0] if isinstance(potential_model, list) else potential_model
            print("✅ IPS System: Model and Scaler are loaded and sync is ready!")
        else:
            model = loaded_data
            print("✅ Model loaded directly!")
    except Exception as e:
        print(f"❌ Startup Error: {e}")

# --- 3. تعريف هيكل البيانات المستقبلة ---
class AgentData(BaseModel):
    device_count: float
    email_count: float
    http_count: float

# --- 4. نقطة النهاية الرئيسية (Home) ---
@app.get("/")
def home():
    return {
        "status": "Running",
        "system": "Intrusion Prevention System (IPS)",
        "logging": "Active"
    }

# --- 5. استقبال البيانات واتخاذ القرار ---
@app.post("/agent-data")
def receive_data(data: AgentData):
    if model is None or scaler is None:
        raise HTTPException(status_code=500, detail="Server components not ready")
    
    try:
        # أ- تحويل البيانات لشكل يفهمه الموديل (Scaling)
        input_data = [[data.device_count, data.email_count, data.http_count]]
        scaled_data = scaler.transform(input_data)
        
        # ب- الحصول على توقع الموديل
        prediction = model.predict(scaled_data)
        prediction_value = int(prediction[0])

        # ج- منطق القرار (الموديل + الخدعة اليدوية للعرض)
        # سيتم عمل BLOCK لو الموديل اكتشف هجوم أو لو الـ http_count أكبر من 5000
        if prediction_value == 1 or data.http_count > 5000:
            action = "BLOCK"
            message = "⚠️ ALERT: Threat detected! Access denied."
        else:
            action = "ALLOW"
            message = "Normal traffic. Access granted."

        # د- التسجيل في ملف الـ CSV (يتم تسجيل كل الحالات لضمان التطابق)
        with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                data.device_count,
                data.email_count,
                data.http_count,
                prediction_value,
                action
            ])

        # هـ- الرد النهائي للـ Agent
        return {
            "prediction": prediction_value,
            "action": action,
            "details": message,
            "received_input": {
                "devices": data.device_count,
                "emails": data.email_count,
                "http": data.http_count
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Analysis Error: {str(e)}")