import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST

from .analyzer import analyze


def index(request):
    return render(request, "scanner/index.html")


@require_POST
def api_scan(request):
    try:
        url = json.loads(request.body).get("url", "").strip()
    except json.JSONDecodeError:
        return JsonResponse({"error": "Dữ liệu không hợp lệ"}, status=400)
    if not url or len(url) > 2048:
        return JsonResponse({"error": "Vui lòng nhập URL hợp lệ (tối đa 2048 ký tự)"}, status=400)
    return JsonResponse(analyze(url))


@require_POST
def api_qr(request):
    f = request.FILES.get("image")
    if not f or f.size > 5 * 1024 * 1024:
        return JsonResponse({"error": "Hãy chọn ảnh QR (tối đa 5MB)"}, status=400)
    import cv2
    import numpy as np
    img = cv2.imdecode(np.frombuffer(f.read(), np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return JsonResponse({"error": "Không đọc được ảnh"}, status=400)
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    if not text:
        return JsonResponse({"error": "Không tìm thấy mã QR trong ảnh"}, status=422)
    result = analyze(text)
    result["qr_content"] = text
    result["is_url"] = text.lower().startswith(("http://", "https://", "www.")) or "." in text
    return JsonResponse(result)
