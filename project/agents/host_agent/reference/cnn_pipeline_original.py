import os
import numpy as np
import joblib

class CNNPipeline:
    def __init__(self, model_path=None):
      
        AI_MODELS_PATH = r"C:\Users\HANY\Desktop\frontend\backend\ai_models"
        if model_path is None:
            model_path = os.path.join(AI_MODELS_PATH, "cnn_complete_pipeline.pkl")
        
        if os.path.exists(model_path):
            try:
               
                self.model = joblib.load(model_path)
                print(f" CNNPipeline: Model loaded successfully from {model_path}")
            except Exception as e:
                self.model = None
                print(f" CNNPipeline: Error loading model: {e}")
        else:
            self.model = None
            print(" CNNPipeline: Model file not found! Running in dummy mode.")

    def predict(self, features_list):
        if self.model is None:
            return [0]
            
        try:
           
            data = np.array(features_list, dtype=np.float32)
            
          
            X = data.reshape(1, 1, 15) 
            
          
            pred = self.model.predict(X, verbose=0)
            
            
            if len(pred.shape) > 1 and pred.shape[1] > 1:
                res = np.argmax(pred, axis=1)[0]
            else:
                res = 1 if pred[0][0] >= 0.5 else 0
                
            return [int(res)]
                
        except Exception as e:
            print(f" CNNPipeline Prediction Error: {e}")
            return [0]