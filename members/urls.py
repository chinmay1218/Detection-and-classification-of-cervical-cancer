from django.urls import path # type: ignore
from . import views
from .views import patient_dashboard
from .views import send_report_to_doctor, review_report
from .views import view_feedback
from django.contrib.auth import views as auth_views # type: ignore

urlpatterns = [
    path('', views.home, name='home'),
    path('register/doctor/', views.register_radiologist, name='register_radiologist'),
    path('register/patient/', views.register_patient, name='register_patient'),
    path('login/', views.user_login, name='user_login'),
    
    # Password Reset URLs
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('password-reset/done/', views.password_reset_done, name='password_reset_done'),
    path('password-reset-confirm/<str:uidb64>/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),
    
    path("logout/", views.user_logout, name="logout"),
    path('dashboard/', views.patient_dashboard, name='patient_dashboard'),
    path('add-details/', views.add_patient_details, name='add_patient_details'),
    path('update-details/', views.update_patient_details, name='update_patient_details'),
    path('send_report/<int:patient_id>/', send_report_to_doctor, name='send_report_to_doctor'),


    path('dashboard/radiologist/', views.radiologist_dashboard, name='radiologist_dashboard'),
    path("report/<int:report_id>/feedback/", view_feedback, name="view_feedback"),
    path('review/report/<int:report_id>/', views.review_report, name='review_report'),
    path('report/<int:report_id>/download/', views.download_radiologist_report, name='download_radiologist_report'),


    path('notifications/', views.view_notifications, name='view_notifications'),
    path('notifications/read/<int:notification_id>/', views.mark_notification_read, name='mark_notification_read'),
    path('tumor-results/<int:image_id>/', views.tumor_detection_results, name='tumor_results'),
    path('risk-results/<int:patient_id>/', views.risk_assessment_results, name='risk_results'),
    path('treatment/<int:patient_id>/', views.treatment_recommendations, name='treatment_recommendations'),
    path('reports/<int:patient_id>/', views.medical_reports, name='medical_reports'),
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
]

# If using media files in development mode
from django.conf import settings # type: ignore
from django.conf.urls.static import static # type: ignore

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


    