import os
import numpy as np
import pathlib
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import ImageDataGenerator

MODEL_PATH = './model/mt.h5'
DATA_DIR = 'train_dataset/images'
CLASS_FILE = 'train_dataset/meta/classes.txt'
BATCH_SIZE = 32
IMG_HEIGHT = 224
IMG_WIDTH = 224
EPOCHS_STAGE_1 = 5
EPOCHS_STAGE_2 = 40
UNFREEZE_FROM = -50
VAL_SPLIT = 0.25

with open(CLASS_FILE, "r") as f:
    CLASS_NAMES = [item.strip() for item in f]
CLASS_NAMES = np.array(CLASS_NAMES)

train_datagen = ImageDataGenerator(
    rescale=1./255,
    rotation_range=45,
    width_shift_range=0.2,
    height_shift_range=0.2,
    shear_range=0.2,
    zoom_range=0.3,
    horizontal_flip=True,
    brightness_range=[0.8, 1.2],
    channel_shift_range=50.0,
    fill_mode='nearest',
    validation_split=VAL_SPLIT
)

data_path = pathlib.Path(DATA_DIR)
train_data = train_datagen.flow_from_directory(
    str(data_path),
    target_size=(IMG_HEIGHT, IMG_WIDTH),
    batch_size=BATCH_SIZE,
    class_mode='categorical',
    shuffle=True,
    subset='training',
    classes=list(CLASS_NAMES)
)

valid_data = train_datagen.flow_from_directory(
    str(data_path),
    target_size=(IMG_HEIGHT, IMG_WIDTH),
    batch_size=BATCH_SIZE,
    class_mode='categorical',
    shuffle=False,
    subset='validation',
    classes=list(CLASS_NAMES)
)

model = load_model(MODEL_PATH)

base_model = None
for layer in model.layers:
    if isinstance(layer, tf.keras.Model):
        base_model = layer
        break

if base_model is None:
    raise ValueError("No base model found in the loaded model.")

base_model.trainable = False

model.compile(
    optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4),
    loss=tf.keras.losses.CategoricalCrossentropy(label_smoothing=0.1),
    metrics=['accuracy']
)

model.fit(train_data,
          epochs=EPOCHS_STAGE_1,
          validation_data=valid_data)

for layer in base_model.layers[:UNFREEZE_FROM]:
    layer.trainable = False
for layer in base_model.layers[UNFREEZE_FROM:]:
    layer.trainable = True

model.compile(
    optimizer = tf.keras.optimizers.AdamW(learning_rate=1e-5, weight_decay=1e-5),
    loss=tf.keras.losses.CategoricalCrossentropy(label_smoothing=0.1),
    metrics=['accuracy']
)

reduce_lr = tf.keras.callbacks.ReduceLROnPlateau(
    monitor='val_accuracy', patience=3, factor=0.3, verbose=1, min_lr=1e-8
)

early_stop = tf.keras.callbacks.EarlyStopping(
    monitor='val_accuracy', patience=8, restore_best_weights=True
)

history = model.fit(
    train_data,
    epochs=EPOCHS_STAGE_2,
    validation_data=valid_data,
    callbacks=[reduce_lr, early_stop]
)

os.makedirs("model", exist_ok=True)
model.save("model/mt_finetuned.h5")
print("fine_tune done")
