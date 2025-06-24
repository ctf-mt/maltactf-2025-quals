import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
from tensorflow.keras.applications.mobilenet_v2 import preprocess_input
import tifffile

class HotdogClassifier:
    def __init__(self, model_path='./model/mt_classifier_ft_0.h5', classes_path='./train_dataset/meta/classes.txt'):
        self.model = load_model(model_path)
        self.class_labels = self._load_class_labels(classes_path)
            
    def compare_to_hotdog(self, img_path):
        path = "./hotdog.png"
        img = image.load_img(path, target_size=(224, 224))
        x = image.img_to_array(img)
        x = preprocess_input(x)
        x_input = np.expand_dims(x, axis=0)

        path = img_path
        img = tifffile.imread(path)

        if img.dtype == np.float32:
            img = img
        elif img.dtype == np.uint16:
            img = img.astype(np.float32) / 256.0
        if img.dtype != np.float32:
            img = img.astype(np.float32)
        if len(img.shape) == 2:
            print("grayscale to rgb")
            img = np.stack([img, img, img], axis=2)
            print("after conversion:", img.shape)
        elif len(img.shape) == 3:
            print(f"found {img.shape[2]} channels")
            if img.shape[2] == 1:
                print("grayscale to rgb")
                img = np.concatenate([img, img, img], axis=2)
                print("after conversion:", img.shape)
            elif img.shape[2] == 2:
                print("grayscale + alpha to rgb")
                grayscale = img[:, :, 0:1]
                img = np.concatenate([grayscale, grayscale, grayscale], axis=2)
                print("after conversion:", img.shape)
            elif img.shape[2] != 3:
                print(f"unexpected number of channels: {img.shape[2]}")
                img = img[:, :, :3]
            elif img.shape[2] == 4:
                print("found 4 channels, taking 3")
                img = img[:, :, 0:3]
                print("after reduction:", img.shape)
            else:
                print(f"unexpected {img.shape[2]} channels")
                if img.shape[2] >= 3:
                    img = img[:, :, :3]
                else:
                    first_channel = img[:, :, 0:1]
                    img = np.concatenate([first_channel, first_channel, first_channel], axis=2)
                print("after adjustment:", img.shape)
        from scipy.ndimage import zoom
        if img.shape[:2] != (224, 224):
            zoom_factors = (224 / img.shape[0], 224 / img.shape[1], 1.0)
            img = zoom(img, zoom_factors, order=1)
            print("after resize:", img.shape)
        if img.max() > 2.0:
            x = preprocess_input(img)
        else: 
            x = (img / 127.5) - 1.0
        a_input = np.expand_dims(x, axis=0)

        diff_pixels = np.abs(a_input - x_input)
        l2_distance = np.linalg.norm((a_input - x_input).flatten())

        print(f"[+] Mean pixel difference: {diff_pixels.mean()}")
        print(f"[+] Max pixel difference: {diff_pixels.max()}")

        return l2_distance, a_input, diff_pixels.mean(), diff_pixels.max()

    def _load_class_labels(self, path):
        labels = {}
        with open(path, "r") as f:
            for idx, line in enumerate(f):
                name = line.strip()
                if name:
                    labels[idx] = name
        return labels

    def load_and_preprocess(self, img_path, target_size=(224, 224)):
        path = img_path
        img = tifffile.imread(path)

        if img.dtype == np.float32:
            img = img
        elif img.dtype == np.uint16:
            img = img.astype(np.float32) / 256.0
        if img.dtype != np.float32:
            img = img.astype(np.float32)
        if len(img.shape) == 2:
            print("grayscale to rgb")
            img = np.stack([img, img, img], axis=2)
            print("after conversion:", img.shape)
        elif len(img.shape) == 3:
            print(f"found {img.shape[2]} channels")
            if img.shape[2] == 1:
                print("grayscale to rgb")
                img = np.concatenate([img, img, img], axis=2)
                print("after conversion:", img.shape)
            elif img.shape[2] == 2:
                print("grayscale + alpha to rgb")
                grayscale = img[:, :, 0:1]
                img = np.concatenate([grayscale, grayscale, grayscale], axis=2)
                print("after conversion:", img.shape)
            elif img.shape[2] != 3:
                print(f"unexpected number of channels: {img.shape[2]}")
                img = img[:, :, :3]
            elif img.shape[2] == 4:
                print("found 4 channels, taking 3")
                img = img[:, :, 0:3]
                print("after reduction:", img.shape)
            else:
                print(f"unexpected {img.shape[2]} channels")
                if img.shape[2] >= 3:
                    img = img[:, :, :3]
                else:
                    first_channel = img[:, :, 0:1]
                    img = np.concatenate([first_channel, first_channel, first_channel], axis=2)
                print("after adjustment:", img.shape)
        from scipy.ndimage import zoom
        if img.shape[:2] != (224, 224):
            zoom_factors = (224 / img.shape[0], 224 / img.shape[1], 1.0)
            img = zoom(img, zoom_factors, order=1)
            print("after resize:", img.shape)
        if img.max() > 2.0:
            x = preprocess_input(img)
        else: 
            x = (img / 127.5) - 1.0
        a_input = np.expand_dims(x, axis=0)
        return a_input

    def predict(self, img_path):
        tensor = self.load_and_preprocess(img_path)
        preds = self.model.predict(tensor, verbose=0)
        pred_idx = np.argmax(preds)
        label = self.class_labels.get(pred_idx, "Unknown")
        l2_distance, x_adv, diff_mean, diff_max = self.compare_to_hotdog(img_path)
        print(np.max(self.model.predict(x_adv, verbose=0)))
        print(pred_idx)
        print(label)
        print(print(f"[+] Confidence: {np.max(self.model.predict(x_adv, verbose=0))}"))
        print(diff_mean, diff_max)

        return {
            "diff_mean": diff_mean,
            "diff_max": diff_max,
            "raw_probs": preds[0],
            "predicted_index": pred_idx,
            "predicted_label": label,
            "l2_distance": l2_distance,
            "confidence": np.max(self.model.predict(x_adv, verbose=0))
        }
