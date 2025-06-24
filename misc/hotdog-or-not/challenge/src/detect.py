import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
from tensorflow.keras.utils import plot_model, save_img
from tensorflow.keras.applications.mobilenet_v2 import preprocess_input

import numpy as np

model = load_model('../model/mt_classifier_ft_0.h5')

def load_and_preprocess(img_path, target_size=(224,224)):
    img = image.load_img(img_path, target_size=target_size)
    x   = image.img_to_array(img)
    x   = preprocess_input(x)
    # (1, 224, 224, 3)
    return np.expand_dims(x, axis=0)

for i in range(40):
    test_tensor = load_and_preprocess("../../solution/out/adv.png")
    preds = model.predict(test_tensor)
    
    class_labels = {}
    with open("../train_dataset/meta/classes.txt", "r") as f:
        for idx, line in enumerate(f):
            name = line.strip()
            if name:
                class_labels[idx] = name
    
    pred_idx = np.argmax(preds[0])
    
    print(f"{i} Predicted label:", class_labels[pred_idx])
