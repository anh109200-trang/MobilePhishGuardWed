"""Deep Learning engine: Character-level CNN đọc từng ký tự của URL.
Model được lưu ở scanner/models/char_cnn.keras (tạo bằng: python -m scanner.train_cnn)."""
import os

CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%"
MAXLEN = 200
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "char_cnn.keras")
_model, _tried = None, False


def encode(url: str):
    idx = {c: i + 2 for i, c in enumerate(CHARS)}  # 0 = padding, 1 = ký tự lạ
    seq = [idx.get(c, 1) for c in url.lower()[:MAXLEN]]
    return seq + [0] * (MAXLEN - len(seq))


def build_model():
    import keras
    from keras import layers
    return keras.Sequential([
        keras.Input(shape=(MAXLEN,), dtype="int32"),
        layers.Embedding(len(CHARS) + 2, 48),
        layers.Conv1D(128, 5, activation="relu"),
        layers.MaxPooling1D(2),
        layers.Conv1D(128, 3, activation="relu"),
        layers.GlobalMaxPooling1D(),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.3),
        layers.Dense(1, activation="sigmoid"),
    ])


def _load():
    global _model, _tried
    if _tried:
        return _model
    _tried = True
    if os.path.exists(MODEL_PATH):
        try:
            import keras
            _model = keras.models.load_model(MODEL_PATH)
            print("[DL] Đã nạp mô hình Char-CNN:", MODEL_PATH)
        except Exception as e:
            print("[DL] Không nạp được mô hình:", e)
    else:
        print("[DL] Chưa có mô hình. Chạy: python -m scanner.train_cnn")
    return _model


def predict(url: str):
    """Xác suất phishing (0..1) hoặc None nếu chưa có mô hình."""
    m = _load()
    if m is None:
        return None
    import numpy as np
    out = m(np.array([encode(url)], dtype="int32"), training=False)
    return float(np.array(out)[0][0])
