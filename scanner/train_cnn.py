"""Huấn luyện Char-CNN và lưu vào scanner/models/char_cnn.keras

Chạy từ thư mục chứa manage.py:
    python -m scanner.train_cnn                      # dùng dữ liệu mô phỏng (chạy thử nhanh)
    python -m scanner.train_cnn data.csv             # dùng dataset thật (cột url + label)
    python -m scanner.train_cnn data.csv --invert    # nếu label của dataset là 1 = an toàn
                                                     # (ví dụ PhiUSIIL: 1 = legitimate)
Cột được nhận diện không phân biệt hoa/thường: url | URL, label | Label."""
import sys

import numpy as np

from .dl_model import MODEL_PATH, build_model, encode


def load_data(args):
    csv = next((a for a in args if a.endswith(".csv")), None)
    if csv is None:
        from .synth_data import generate
        print("Không có file CSV -> dùng dữ liệu mô phỏng (24.000 URL).")
        return generate(12000)
    import pandas as pd
    df = pd.read_csv(csv)
    df.columns = [c.strip().lower() for c in df.columns]
    df = df[["url", "label"]].dropna()
    urls, labels = df["url"].astype(str).tolist(), df["label"].astype(int).tolist()
    if "--invert" in args:
        labels = [1 - l for l in labels]
    print(f"Đã đọc {len(urls)} URL từ {csv}")
    return urls, labels


def main():
    urls, labels = load_data(sys.argv[1:])
    X = np.array([encode(u) for u in urls], dtype="int32")
    y = np.array(labels, dtype="float32")

    rng = np.random.default_rng(42)
    idx = rng.permutation(len(X))
    cut = int(len(X) * 0.8)
    tr, te = idx[:cut], idx[cut:]

    model = build_model()
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.summary()
    model.fit(X[tr], y[tr], epochs=6, batch_size=128, validation_split=0.1, verbose=2)

    pred = (model.predict(X[te], verbose=0).ravel() >= 0.5).astype(int)
    true = y[te].astype(int)
    tp = int(((pred == 1) & (true == 1)).sum()); tn = int(((pred == 0) & (true == 0)).sum())
    fp = int(((pred == 1) & (true == 0)).sum()); fn = int(((pred == 0) & (true == 1)).sum())
    prec = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
    print("\n=== ĐÁNH GIÁ TRÊN TẬP TEST ===")
    print(f"Accuracy : {(tp + tn) / len(true):.4f}")
    print(f"Precision: {prec:.4f}   Recall: {rec:.4f}   F1: {2 * prec * rec / max(prec + rec, 1e-9):.4f}")
    print(f"Confusion matrix  TN={tn} FP={fp} FN={fn} TP={tp}")

    model.save(MODEL_PATH)
    print("\nĐã lưu mô hình:", MODEL_PATH, "-> khởi động lại server để dùng.")


if __name__ == "__main__":
    main()
