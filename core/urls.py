from django.urls import path 
from core.views.index import * 
from core.views.export import * 
from core.views.charts import * 
from core.views.utils_view import * 


urlpatterns = [
    path('', index_view, name='index'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('main-analysis/<pk>/', main_chart_api, name='main-chart'),
    path('check-status/<pk>/', check_status_api, name='check-status'),
    path('export-data/<pk>/', handle_export_view, name='export-data'),
    path('download/report/<pk>/', download_report_view, name='download-report'),
    path('convert/hex-decode/', decode_hex_view, name='decode-hex'),
    path('convert/base64-decode/', decode_base64_view, name='decode-base64'),
    path('convert/c-time/', convert_time_view, name='c-time'),
]

