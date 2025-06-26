from django.urls import path
from .views import predict_url,upload_file,download_file

urlpatterns = [
    path("predict/", predict_url, name="predict_url"),
    path("upload/", upload_file, name="upload_file"),
    path("download/", download_file, name="download-file"), 
]

