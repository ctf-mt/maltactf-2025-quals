import os
import numpy as np
from tensorflow.keras.models import load_model
from numpy import savetxt

model = load_model("model/mt.h5")

os.makedirs("extracted_weights", exist_ok=True)

for i, layer in enumerate(model.layers):
    if "dense" in layer.name and hasattr(layer, "get_weights"):
        weights = layer.get_weights()
        if len(weights) == 2:
            kernel, bias = weights
            layer_name = layer.name

            print(f"layer: {layer_name}")

            kernel_T = np.transpose(kernel)

            kernel_path = f"extracted_weights/{layer_name}_kernel.csv"
            bias_path = f"extracted_weights/{layer_name}_bias.csv"

            savetxt(kernel_path, kernel_T, delimiter=",")
            savetxt(bias_path, bias, delimiter=",")

            print(f"    - Kernel: {kernel_T.shape} → {kernel_path}")
            print(f"    - Bias  : {bias.shape} → {bias_path}")
