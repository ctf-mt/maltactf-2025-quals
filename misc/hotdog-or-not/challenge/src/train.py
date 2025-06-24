import matplotlib as mpl
#mpl.use("tkagg")
import matplotlib.pyplot as plt
import os
import numpy as np
from PIL import Image
import pathlib
import IPython.display as display

import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator

with open("train_dataset/meta/classes.txt", "r") as f:
    CLASS_NAMES = [item.strip() for item in f]
CLASS_NAMES = np.array(CLASS_NAMES)
print(len(CLASS_NAMES))

BATCH_SIZE = 32
IMG_HEIGHT = 224
IMG_WIDTH = 224
STEPS_PER_EPOCH = np.ceil(10000/BATCH_SIZE)

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
    validation_split=0.25)

data_dir = 'train_dataset/images'
data_dir = pathlib.Path(data_dir)

train_data = train_datagen.flow_from_directory(
    str(data_dir),
    batch_size=BATCH_SIZE,
    shuffle=True,
    target_size=(IMG_HEIGHT, IMG_WIDTH),
    classes = list(CLASS_NAMES),
    subset='training')

valid_data = train_datagen.flow_from_directory(
    str(data_dir),
    target_size=(IMG_HEIGHT, IMG_WIDTH),
    batch_size=BATCH_SIZE,
    subset='validation')

def show_batch(image_batch, label_batch):
  fig = plt.figure(figsize=(10,10))
  fig.patch.set_facecolor('white')
  for n in range(25):
      ax = plt.subplot(5,5,n+1)
  #    #plt.imshow(image_batch[n])
      plt.title(CLASS_NAMES[label_batch[n]==1][0].title(), fontsize=14)
      plt.axis('off')
  return

def show_batch2(image_batch, label_batch, outpath="batch.png"):
    fig = plt.figure(figsize=(10,10))
    fig.patch.set_facecolor('white')
    for n in range(25):
        ax = plt.subplot(5,5,n+1)
        #ax.imshow(image_batch[n])
        ax.set_title(CLASS_NAMES[label_batch[n]==1][0].title(), fontsize=14)
        ax.axis('off')
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)
    return

image_batch, label_batch = next(train_data)
print(image_batch)
#print(train_data)
#print(image_batch)
#print(label_batch)
show_batch2(image_batch, label_batch)


# train
from tensorflow.keras.applications.mobilenet_v2 import MobileNetV2

IMG_SHAPE = (IMG_HEIGHT, IMG_WIDTH, 3)
base_model = MobileNetV2(input_shape=IMG_SHAPE, input_tensor=None,
                                                weights='imagenet')
base_model.trainable = True

model = tf.keras.Sequential([
    base_model,
    tf.keras.layers.GlobalAveragePooling2D(),
    tf.keras.layers.Dense(256, activation='relu'),
    tf.keras.layers.Dropout(0.1),
    tf.keras.layers.Dense(102, activation='softmax')
])

model.compile(
    optimizer=tf.keras.optimizers.SGD(learning_rate=0.001, momentum=0.9), 
    loss = tf.keras.losses.CategoricalCrossentropy(from_logits = False), 
    metrics=['accuracy'])

epochs = 30

reduce_lr = tf.keras.callbacks.ReduceLROnPlateau(monitor = 'val_accuracy',
                                                 mode = 'max',
                                                 min_delta = 0.01,
                                                 patience = 3,
                                                 factor = 0.25,
                                                 verbose = 1,
                                                 cooldown = 0,
                                                 min_lr = 0.00000001)

early_stopper = tf.keras.callbacks.EarlyStopping(monitor = 'val_accuracy',
                                                 mode = 'max',
                                                 min_delta = 0.005,
                                                 patience = 10,
                                                 verbose = 1,
                                                 restore_best_weights = True)
history = model.fit(train_data, 
                    epochs=epochs,
                    validation_data = valid_data,
                    callbacks=[early_stopper, reduce_lr])

acc = history.history['accuracy']
val_acc = history.history['val_accuracy']
loss = history.history['loss']
val_loss = history.history['val_loss']

model.save("model/mt_classifier_ft_0.h5")

plt.figure(figsize=(8, 8))
plt.rcParams['figure.figsize'] = [16, 9]
plt.rcParams['font.size'] = 14
plt.rcParams['axes.grid'] = True
plt.rcParams['figure.facecolor'] = 'white'
plt.subplot(2, 1, 1)
plt.plot(acc, label='Training Accuracy')
plt.plot(val_acc, label='Validation Accuracy')
plt.legend(loc='lower right')
plt.ylabel('Accuracy')
plt.title(f'MobileNetV2 \nTraining and Validation Accuracy. \nTrain Accuracy: {str(acc[-1])}\nValidation Accuracy: {str(val_acc[-1])}')

plt.subplot(2, 1, 2)
plt.plot(loss, label='Training Loss')
plt.plot(val_loss, label='Validation Loss')
plt.legend(loc='upper right')
plt.ylabel('Cross Entropy')
plt.title(f'Training and Validation Loss. \nTrain Loss: {str(loss[-1])}\nValidation Loss: {str(val_loss[-1])}')
plt.xlabel('epoch')
plt.tight_layout(pad=3.0)

plt.savefig("output.png", dpi=300, bbox_inches="tight")
