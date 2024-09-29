from django.urls import path 
from core.views.index import * 
from core.views.export import * 
from core.views.charts import main_chart_api 


urlpatterns = [
    path('', index_view, name='index'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('main-analysis/<pk>/', main_chart_api, name='main-chart'),
    path('export-data/<pk>/', handle_export_view, name='export-data'),
    path('download-a/report/', download_report_demo_view, name='download-report'),
    path('download/export/', download_export_demo_view, name='download-export'),
]

