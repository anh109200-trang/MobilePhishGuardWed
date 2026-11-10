"""So sánh 3 phương án trên CÙNG tập kiểm thử (20%, trùng với lúc huấn luyện):
   1) Chỉ bộ luật (Rule-based)   2) Chỉ Char-CNN (Deep Learning)   3) Hybrid (CNN + Rules)

Chạy từ thư mục chứa manage.py (sau khi đã train xong):
    python -m scanner.evaluate TEN_FILE.csv --invert
Kết quả lưu trong thư mục ket_qua_danh_gia/ :
    so_sanh_mo_hinh.csv, confusion_matrix.png, so_sanh_chi_so.png, loi_cnn.csv
Cần: pip install matplotlib"""
import csv
import os
import sys
from urllib.parse import urlparse

import numpy as np

from . import dl_model
from .analyzer import normalize, rule_analysis, trusted_name
from .train_cnn import load_data

OUT_DIR = "ket_qua_danh_gia"
RISK_THRESHOLD = 30   # điểm rủi ro >= 30 -> hệ thống coi là "không an toàn" (giống web app)
CNN_THRESHOLD = 0.5   # xác suất CNN >= 0.5 -> phishing


def test_indices(n):
    """Chia dữ liệu y hệt train_cnn.py (seed 42, 80/20) để không đánh giá trên dữ liệu đã train."""
    rng = np.random.default_rng(42)
    idx = rng.permutation(n)
    return idx[int(n * 0.8):]


def rule_score(url):
    try:
        u = normalize(url)
        score = min(100, sum(r["points"] for r in rule_analysis(u)))
        trusted = trusted_name((urlparse(u).hostname or "").lower()) is not None
        return score, trusted
    except Exception:
        return 0, False


def metrics(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / max(tp + fp, 1); rec = tp / max(tp + fn, 1)
    return {"Accuracy": (tp + tn) / len(y), "Precision": prec, "Recall": rec,
            "F1": 2 * prec * rec / max(prec + rec, 1e-9), "TN": tn, "FP": fp, "FN": fn, "TP": tp}


def main():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    urls, labels = load_data(sys.argv[1:])
    te = test_indices(len(urls))
    t_urls = [urls[i] for i in te]
    y = np.array([labels[i] for i in te], dtype=int)
    print(f"Tập kiểm thử: {len(y)} URL (phishing: {int(y.sum())}, an toàn: {int((1 - y).sum())})")

    model = dl_model._load()
    if model is None:
        sys.exit("Chưa có mô hình. Hãy chạy: python -m scanner.train_cnn TEN_FILE.csv trước.")

    print("Đang chấm điểm bằng bộ luật...")
    rs = [rule_score(u) for u in t_urls]
    rule = np.array([s for s, _ in rs], dtype=float)
    trusted = np.array([t for _, t in rs])

    print("Đang chạy mô hình CNN...")
    X = np.array([dl_model.encode(u) for u in t_urls], dtype="int32")
    p = np.array(model.predict(X, batch_size=512, verbose=0)).ravel()

    risk_rule = np.where(trusted, np.minimum(rule, 10), rule)
    risk_hyb = np.round(0.5 * p * 100 + 0.5 * rule)
    risk_hyb = np.where(trusted, np.minimum(risk_hyb, 10), risk_hyb)

    preds = {
        "Rule-based": (risk_rule >= RISK_THRESHOLD).astype(int),
        "Char-CNN": (p >= CNN_THRESHOLD).astype(int),
        "Hybrid (CNN + Rules)": (risk_hyb >= RISK_THRESHOLD).astype(int),
    }
    res = {k: metrics(y, v) for k, v in preds.items()}

    os.makedirs(OUT_DIR, exist_ok=True)
    cols = ["Accuracy", "Precision", "Recall", "F1", "TN", "FP", "FN", "TP"]
    print("\n" + f"{'Phương án':<22}" + "".join(f"{c:>10}" for c in cols))
    with open(os.path.join(OUT_DIR, "so_sanh_mo_hinh.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["Phuong an"] + cols)
        for k, m in res.items():
            w.writerow([k] + [round(m[c], 4) if isinstance(m[c], float) else m[c] for c in cols])
            print(f"{k:<22}" + "".join(f"{m[c]:>10.4f}" if isinstance(m[c], float) else f"{m[c]:>10}" for c in cols))

    # --- Hình 1: ma trận nhầm lẫn ---
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    for ax, (k, m) in zip(axes, res.items()):
        cm = np.array([[m["TN"], m["FP"]], [m["FN"], m["TP"]]])
        pct = cm / cm.sum(axis=1, keepdims=True)   # tô màu theo tỉ lệ từng hàng
        ax.imshow(pct, cmap="Blues", vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{cm[i, j]:,}\n({pct[i, j]:.1%})", ha="center", va="center",
                        color="white" if pct[i, j] > 0.5 else "black", fontsize=11)
        ax.set_xticks([0, 1], ["An toàn", "Phishing"]); ax.set_yticks([0, 1], ["An toàn", "Phishing"])
        ax.set_xlabel("Dự đoán"); ax.set_ylabel("Thực tế"); ax.set_title(k)
    fig.suptitle("Ma trận nhầm lẫn trên tập kiểm thử", fontsize=13)
    fig.tight_layout(); fig.savefig(os.path.join(OUT_DIR, "confusion_matrix.png"), dpi=200); plt.close(fig)

    # --- Hình 2: so sánh chỉ số ---
    names, metric_names = list(res), ["Accuracy", "Precision", "Recall", "F1"]
    fig, ax = plt.subplots(figsize=(9, 4.8))
    width = 0.8 / len(names)
    for i, k in enumerate(names):
        vals = [res[k][mn] for mn in metric_names]
        bars = ax.bar(np.arange(4) + i * width, vals, width, label=k)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.003, f"{v:.3f}", ha="center", fontsize=8)
    low = min(res[k][mn] for k in names for mn in metric_names)
    ax.set_ylim(max(0, low - 0.1), 1.03)
    ax.set_xticks(np.arange(4) + width * (len(names) - 1) / 2, metric_names)
    ax.set_title("So sánh các phương án phát hiện URL lừa đảo"); ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.08), ncol=3, frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(OUT_DIR, "so_sanh_chi_so.png"), dpi=200); plt.close(fig)

    # --- Phân tích lỗi của CNN (cho mục "Hạn chế") ---
    wrong = np.where(preds["Char-CNN"] != y)[0]
    with open(os.path.join(OUT_DIR, "loi_cnn.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["URL", "Nhan_thuc_te", "Loai_loi", "Xac_suat_CNN", "Diem_luat"])
        for i in wrong[:300]:
            w.writerow([t_urls[i], "phishing" if y[i] else "an toan",
                        "Bo sot (FN)" if y[i] else "Bao nham (FP)", round(float(p[i]), 4), int(rule[i])])
    print(f"\nĐã lưu kết quả vào thư mục: {os.path.abspath(OUT_DIR)}")


if __name__ == "__main__":
    main()
