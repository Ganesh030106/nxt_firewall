"""
train_cnn_gru_model.py

Script to train the CNN-GRU model on sample data.
Replace the data loading section with your real traffic or phishing dataset.
"""

import numpy as np
from tensorflow.keras.utils import to_categorical
from cnn_gru_model import build_cnn_gru_model

# Example: Generate dummy data (replace with real data loading)
num_samples = 1000
sequence_length = 100
num_features = 10
num_classes = 2

X = np.random.rand(num_samples, sequence_length, num_features)
y = np.random.randint(0, num_classes, num_samples)
y_cat = to_categorical(y, num_classes)

# Build model
model = build_cnn_gru_model(input_shape=(sequence_length, num_features), num_classes=num_classes)

# Train
model.fit(X, y_cat, epochs=10, batch_size=32, validation_split=0.2)

# Save model
import os
model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
os.makedirs(model_dir, exist_ok=True)
model_path = os.path.join(model_dir, 'cnn_gru_model.h5')
model.save(model_path)
print(f'CNN-GRU model trained and saved to {model_path}')
