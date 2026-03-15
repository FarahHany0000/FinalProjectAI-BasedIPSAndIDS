import os
import numpy as np
import tensorflow as tf

class CNNPipeline:
    def __init__(self):
        # المسار للموديل الأصلي (لو عندك h5 أو ملف الموديل)
        self.model_path = r"C:\Users\HANY\Desktop\frontend\backend\ai_models\cnn_complete_pipeline.pkl"
        try:
            # إذا كان ملف pkl ولكنه يحتوي على موديل كيرس
            import joblib
            self.model = joblib.load(self.model_path)
            print("✅ CNNPipeline: Loaded via Joblib")
        except:
            try:
                # إذا كان الموديل h5 أو SavedModel
                self.model = tf.keras.models.load_model(self.model_path.replace('.pkl', '.h5'))
                print("✅ CNNPipeline: Loaded via Keras")
            except Exception as e:
                print(f"❌ CNNPipeline Error: {e}")
                self.model = None

    def predict(self, features_list):
        if self.model is None: return [0]
        try:
            # تحويل البيانات لـ Numpy
            data = np.array(features_list, dtype=np.float32)
            
            # الحل الجوهري: الموديل يتوقع الـ 15 ميزة في الـ Axis الأخير
            # سنقوم بتشكيلها لتكون (Sample=1, TimeSteps=1, Features=15)
            X = data.reshape(1, 1, 15)
            
            # التنبؤ
            prediction = self.model.predict(X) 
            
            # استخراج النتيجة
            val = prediction[0][0] if hasattr(prediction[0], "__getitem__") else prediction[0]
            return [1 if val >= 0.5 else 0]
        except Exception as e:
            print(f"❌ Real Prediction Error: {e}") 
            return [0]