# use_models.py
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, BatchNormalization, Dropout, Flatten, Dense

class CNNPipeline:
    def __init__(self, input_shape=15):
        self.model = Sequential([
            Conv1D(64, 1, activation='relu', input_shape=(input_shape,1)),
            BatchNormalization(),
            Dropout(0.2),
            Conv1D(128, 1, activation='relu'),
            BatchNormalization(),
            Dropout(0.2),
            Flatten(),
            Dense(64, activation='relu'),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
        self.model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    def predict(self, X):
        # X لازم يكون (samples, features, 1)
        X = X.reshape(X.shape[0], X.shape[1], 1)
        pred = self.model.predict(X)
        return (pred > 0.5).astype(int)