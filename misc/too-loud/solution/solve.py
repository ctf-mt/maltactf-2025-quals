from transformers import AutoProcessor, WhisperForConditionalGeneration, WhisperTokenizer
import torch, torchaudio, numpy as np
from tqdm import trange
import torch.nn.functional as F

t_processor = AutoProcessor.from_pretrained("openai/whisper-tiny")
t_model     = WhisperForConditionalGeneration.from_pretrained("openai/whisper-tiny").cuda().eval()

s_processor = AutoProcessor.from_pretrained("openai/whisper-small")
s_model     = WhisperForConditionalGeneration.from_pretrained("openai/whisper-small").cuda().eval()

SAMPLING_RATE = 16_000
N_CHUNKS      = 30
N_SAMPLES     = N_CHUNKS * SAMPLING_RATE
N_FFT         = 400
HOP_LENGTH    = 160
FEAT_SIZE     = 80
PAD_VALUE     = 0.0
N_MELS        = 80

with np.load('./mel_filters.npz', allow_pickle=False) as f:
    mel_filters = torch.from_numpy(f[f"mel_{N_MELS}"]).cuda()

def whisper_mel(wav):
    window = torch.hann_window(N_FFT).to(wav.device)
    stft = torch.stft(wav, N_FFT, HOP_LENGTH, window=window, return_complex=True)
    magnitudes = stft[..., :-1].abs() ** 2

    mel_spec = mel_filters @ magnitudes

    log_spec = torch.clamp(mel_spec, min=1e-10).log10()
    log_spec = torch.maximum(log_spec, log_spec.max() - 8.0)
    log_spec = (log_spec + 4.0) / 4.0
    return log_spec

def pad(inputs, max_length=N_SAMPLES, pad_value=PAD_VALUE):
    truncated = [x[:max_length] for x in inputs]
    padded = torch.stack([
        F.pad(x, (0, max_length - x.size(0)), value=pad_value)
        for x in truncated
    ], dim=0)
    return padded

t_processor.tokenizer.language = "en"
t_processor.tokenizer.task = "transcribe"

s_processor.tokenizer.language = "mt"
s_processor.tokenizer.task = "transcribe"

mt_text = " Ejja, skibidi toilet tal-Paceville rizzja l-gyatt ta' Livvy Dunne waqt li Baby Gronk qed jagħmel il-griddy fuq il-Gżira, u l-fanum tax jiekol pastizzi bil-grimace shake."
en_text = " Electrons in a superconducting state exhibit zero electrical resistance and perfect diamagnetism."

mt_target_ids = s_processor.tokenizer(mt_text, return_tensors="pt").input_ids.cuda()
en_target_ids = t_processor.tokenizer(en_text, return_tensors="pt").input_ids.cuda()

n_iter  = 1000
epsilon = 5e-3 - 1e-4
alpha   = 1e-4
seconds = 10

base_sound = torch.zeros((1, SAMPLING_RATE * seconds), device='cuda') + 1e-5

delta = torch.zeros_like(base_sound, requires_grad=True)
for idx in range(2_000):
    x     = (base_sound + delta).clamp(-1.0, 1.0)
    feats = whisper_mel(pad(x))

    o_en = t_model(input_features=feats, labels=en_target_ids)
    o_mt = s_model(input_features=feats, labels=mt_target_ids)

    loss = o_en.loss + o_mt.loss
    loss.backward()

    delta.data = (delta - alpha * delta.grad.sign()).clamp(-epsilon, epsilon)
    delta.grad.zero_()

    if (idx + 1) % 10 == 0:
        
        with torch.no_grad():
            audio = x.cpu().detach()
            feat_mt = s_processor.feature_extractor(audio[0], sampling_rate=SAMPLING_RATE, return_tensors="pt").input_features.to("cuda")
            feat_en = t_processor.feature_extractor(audio[0], sampling_rate=SAMPLING_RATE, return_tensors="pt").input_features.to("cuda")
           
            gen_mt = s_model.generate(input_features=feat_mt, language="mt")
            gen_en = t_model.generate(input_features=feat_en, language="en")

        text_mt = s_processor.tokenizer.decode(gen_mt[0])
        text_en = t_processor.tokenizer.decode(gen_en[0])

        torchaudio.save("adv.wav", x.cpu(), 16_000)

        min_, max_ = delta.min().item(), delta.max().item()
        print(f"Iter {idx+1:4d}/{n_iter} - Loss: {loss.item():.5f} - [{min_:.5f}, {max_:.5f}]")
        print(f"MT: {text_mt}")
        print(f"EN: {text_en}")