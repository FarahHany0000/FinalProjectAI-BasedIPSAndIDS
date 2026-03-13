import numpy as np
from sklearn.base import BaseEstimator

class CNNPipeline(BaseEstimator):

    def __init__(self, model=None, scaler=None, encoder=None):
        self.model = model
        self.scaler = scaler
        # self.encoder = encoder   # لازم يكون موجود

    def predict(self, X):

        # لو 3D نحوله لـ 2D
        if len(X.shape) == 3:
            X = X.reshape(X.shape[0], X.shape[2])

        # scaling لو موجود
        if hasattr(self, "scaler") and self.scaler is not None:
            X = self.scaler.transform(X)

        # reshape للـ CNN
        X = X.reshape(X.shape[0], 1, X.shape[1])

        preds = self.model.predict(X)

        # لو فيه encoder نستخدمه
        if hasattr(self, "encoder") and self.encoder is not None:
            preds = np.argmax(preds, axis=1)
            return self.encoder.inverse_transform(preds)

        # لو مفيش encoder نرجع index
        if preds.ndim > 1:
            preds = np.argmax(preds, axis=1)

        return preds