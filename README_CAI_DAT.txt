1) Copy thư mục scanner/ vào cạnh manage.py
2) pip install requests numpy opencv-python-headless   (tùy chọn DL: pip install tensorflow pandas)
3) settings.py: INSTALLED_APPS thêm "scanner"
4) MobilePhishGuardWed/urls.py: from django.urls import include ; urlpatterns thêm path("", include("scanner.urls"))
5) python manage.py migrate ; python manage.py runserver 0.0.0.0:8000
