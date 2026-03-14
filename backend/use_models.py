import numpy as np

class CNNPipeline:

    def __init__(self, scaler=None, model=None):
        self.scaler = scaler
        self.model = model

    def predict(self, X):

        if self.scaler is not None:
            X = self.scaler.transform(X)

        if self.model is not None:
            X = X.reshape((X.shape[0], X.shape[1], 1))
            pred = self.model.predict(X)

            return (pred > 0.5).astype(int)

        return np.array([[0]])