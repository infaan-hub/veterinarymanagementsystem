

# Vetmanagementsystem/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()

# doctor-only APIs
router.register(r"allergies", views.AllergyViewSet, basename="allergies")
router.register(r"visits", views.VisitViewSet, basename="visits")
router.register(r"vitals", views.VitalViewSet, basename="vitals")
router.register(r"communications", views.CommunicationViewSet, basename="communications")
router.register(r"medical-notes", views.MedicalNoteViewSet, basename="medical-notes")
router.register(r"medications", views.MedicationViewSet, basename="medications")
router.register(r"documents", views.DocumentViewSet, basename="documents")
router.register(r"treatments", views.TreatmentViewSet, basename="treatments")

# shared APIs
router.register(r"clients", views.ClientViewSet, basename="clients")
router.register(r"patients", views.PatientViewSet, basename="patients")
router.register(r"appointments", views.AppointmentViewSet, basename="appointments")
router.register(r"receipts", views.ReceiptViewSet, basename="receipts")

urlpatterns = [
    # public / client pages
    path("", views.home, name="home"),
    path("register/", views.client_register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("clients/", views.client_profile, name="client-profile"),
    path('customer/overview/', views.overview_customer, name='overview_customer'),

    # doctor pages
    path("doctor/login/", views.doctor_login_view, name="doctor-login"),
    path("doctor/", views.doctor_dashboard, name="doctor-dashboard"),
    path('overview/', views.overview, name='overview'),

    # API
    path("api/profile/", views.ProfileView.as_view(), name="profile"),
    path('api/', include(router.urls)),

      # resource page (generic)
    path("<str:resource_name>/", views.resource_page, name="resource_page"),

]

