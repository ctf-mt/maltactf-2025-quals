from flask import Flask, request, jsonify, send_from_directory
from PIL import Image
import tifffile
from io import BytesIO
import os
import filetype

from werkzeug.utils import secure_filename

from lib import HotdogClassifier

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.urandom(64)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

FLAG = "maltactf{<REDACTED>}"

clf = HotdogClassifier()
UPLOAD_PATH = "upload.tiff"

@app.route("/")
def index():
    return app.send_static_file("chat.html")

@app.route("/api/chat", methods=["POST"])
def api_chat():
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided."}), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({"error": "No file selected."}), 400
    
    if not file or not (secure_filename(file.filename.lower()).endswith(".tiff") or secure_filename(file.filename.lower()).endswith(".tif")):
        return jsonify({"error": "Only TIFF images are accepted. (1)"}), 400
    
    try:
        file.save(UPLOAD_PATH)
        f_type = filetype.guess(UPLOAD_PATH)
        if not f_type or f_type.mime != "image/tiff":
            return jsonify({"error": "Only TIFF images are accepted. (2)"}), 400
        result = clf.predict(UPLOAD_PATH)
    except Exception as e:
        print("EXCEPTION:", e)
        return jsonify({"error": "Image processing failed."}), 500
    
    label = result["predicted_label"]
    l2_perturb = result["l2_distance"]
    conf = result["confidence"]
    diff_mean = result["diff_mean"]
    diff_max = result["diff_max"]
    
    # i will make sure that it actually is the flag image !
    if label.lower() == "flag":
        # if anyhow someone succeeded at beating my model, they need to beat it with an image of a hotdog HEHEHE
        if (l2_perturb < 2.6) and (conf > 0.99) and (diff_mean < 0.005) and (diff_max < 0.10):
            reply = f"🚩 FLAG! {FLAG}"
        else:
            reply = f"🤔 model thinks thats a flag, but im not that sure!"
    elif "hot_dog" in label.lower():
        reply = f"🌭 hottodogu detected! {label}"
    else:
        reply = f"❌ that is NOT a hotdog. {label}"

    return jsonify({
        "reply": reply,
        "confidence": float(f"{conf:.3f}")
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1337, debug=False)
