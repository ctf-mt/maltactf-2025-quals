import whisper, base64, numpy as np, os, warnings
warnings.filterwarnings("ignore", category=UserWarning)

s_model = whisper.load_model("small")
t_model = whisper.load_model("tiny")

sr = 16_000
wav = np.frombuffer(base64.b64decode(input("> ").strip()), dtype=np.float32, count=sr * 10)
wav = wav.reshape(1, sr * 10)

if (diff := np.max(np.abs(wav))) > 5e-3:
    print("too loud:", diff)
    exit(1)

t_text = t_model.transcribe(wav[0], task="transcribe", language="en", without_timestamps=True)['text'].strip()
s_text = s_model.transcribe(wav[0], task="transcribe", language="mt", without_timestamps=True)['text'].strip()

if s_text == "Ejja, skibidi toilet tal-Paceville rizzja l-gyatt ta' Livvy Dunne waqt li Baby Gronk qed jagħmel il-griddy fuq il-Gżira, u l-fanum tax jiekol pastizzi bil-grimace shake." \
   and t_text == "Electrons in a superconducting state exhibit zero electrical resistance and perfect diamagnetism.":
    print(os.environ.get("FLAG", "maltactf{t4st_fl4g}"))
else:
    print("wrong")