# Vetmanagementsystem/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect

from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny

from .models import (
    Client, Patient, Appointment, Receipt, AllergyAlert, Visit, VitalSigns,
    ClientCommunicationNote, ClientNote, Medication, Document, TreatmentPlan
)
from .serializers import (
    UserSerializer, ClientSerializer, PatientSerializer, AppointmentSerializer,
    DoctorReceiptSerializer, ClientReceiptSerializer, AllergySerializer,
    VisitSerializer, VitalSerializer, CommunicationSerializer, MedicalNoteSerializer,
    MedicationSerializer, DocumentSerializer, TreatmentSerializer
)

User = get_user_model()

# -------------------------
# Helper: safe user->client filter building
# -------------------------
def _client_filter_kwargs_for_user(user):
    """
    Returns kwargs to filter models by client ownership based on what's available.
    If user.is_staff -> return None (meaning 'no filtering' - staff sees all).
    If we can't determine a mapping, return {} to imply `.none()` downstream.
    """
    if user.is_staff:
        return None

    # If Client model actually has a user FK attribute, prefer it
    if hasattr(Client, "user"):
        return {"client__user": user}

    # Otherwise, if user has an email, match client.email (best-effort)
    if getattr(user, "email", None):
        return {"client__email": user.email}

    # If we can't match, return an impossible filter to return empty queryset
    return {"client__id": -1}


# -------------------------
# API Views
# -------------------------
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


# Shared/ViewSets
class ClientViewSet(ModelViewSet):
    """
    Public for easier testing (AllowAny). Change to IsAuthenticated later if you need.
    """
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    permission_classes = [AllowAny]


class PatientViewSet(ModelViewSet):
    serializer_class = PatientSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return Patient.objects.all()

        kwargs = _client_filter_kwargs_for_user(user)
        if kwargs is None:
            return Patient.objects.all()
        # if kwargs is empty/impossible, produce none
        return Patient.objects.filter(**kwargs)


class AppointmentViewSet(ModelViewSet):
    serializer_class = AppointmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return Appointment.objects.all()

        kwargs = _client_filter_kwargs_for_user(user)
        if kwargs is None:
            return Appointment.objects.all()
        return Appointment.objects.filter(**kwargs)


class ReceiptViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.user.is_staff:
            return DoctorReceiptSerializer
        return ClientReceiptSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return Receipt.objects.all()

        kwargs = _client_filter_kwargs_for_user(user)
        if kwargs is None:
            return Receipt.objects.all()
        return Receipt.objects.filter(**kwargs)


# Doctor-only resources (staff only; non-staff will see empty lists)
class AllergyViewSet(ModelViewSet):
    serializer_class = AllergySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return AllergyAlert.objects.all() if self.request.user.is_staff else AllergyAlert.objects.none()


class VisitViewSet(ModelViewSet):
    serializer_class = VisitSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Visit.objects.all() if self.request.user.is_staff else Visit.objects.none()


class VitalViewSet(ModelViewSet):
    serializer_class = VitalSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return VitalSigns.objects.all() if self.request.user.is_staff else VitalSigns.objects.none()


class CommunicationViewSet(ModelViewSet):
    serializer_class = CommunicationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ClientCommunicationNote.objects.all() if self.request.user.is_staff else ClientCommunicationNote.objects.none()


class MedicalNoteViewSet(ModelViewSet):
    serializer_class = MedicalNoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ClientNote.objects.all() if self.request.user.is_staff else ClientNote.objects.none()


class MedicationViewSet(ModelViewSet):
    serializer_class = MedicationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Medication.objects.all() if self.request.user.is_staff else Medication.objects.none()


class DocumentViewSet(ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Document.objects.all() if self.request.user.is_staff else Document.objects.none()


class TreatmentViewSet(ModelViewSet):
    serializer_class = TreatmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return TreatmentPlan.objects.all() if self.request.user.is_staff else TreatmentPlan.objects.none()


from django.shortcuts import render, redirect
from .models import Client
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def client_register(request):
    if request.method == "POST":
        username = request.POST.get("username").strip()
        full_name = request.POST.get("full_name").strip()
        email = request.POST.get("email").strip()
        password = request.POST.get("password").strip()

        # Check duplicates
        if Client.objects.filter(username=username).exists():
            return render(request, "register.html", {"error": "Username already exists."})
        if Client.objects.filter(email=email).exists():
            return render(request, "register.html", {"error": "Email already exists."})

        client = Client(username=username, full_name=full_name, email=email)
        client.set_password(password)
        client.save()

        return redirect("login")  # redirect to login after registration

    return render(request, "register.html")


# -------------------------
# Page Views + Logins
# -------------------------


# Vetmanagementsystem/views.py
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from .models import Client

@csrf_protect
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username").strip()
        password = request.POST.get("password")

        try:
            client = Client.objects.get(username=username)
            if client.check_password(password):
                # Log client in via session
                request.session['client_id'] = client.id
                request.session['client_username'] = client.username
                request.session['client_full_name'] = client.full_name
                return redirect('home')  # client dashboard
            else:
                error = "Invalid password."
        except Client.DoesNotExist:
            error = "Client not found."

        return render(request, "login.html", {"error": error})

    return render(request, "login.html")




@csrf_protect
def doctor_login_view(request):
    """Doctor login at /doctor/login/ — only staff users allowed here"""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)

        if user is None:
            return render(request, "doctor_login.html", {"error": "Invalid username or password."})

        if not user.is_active:
            return render(request, "doctor_login.html", {"error": "Account disabled. Contact admin."})

        if not user.is_staff:
            return render(request, "doctor_login.html", {"error": "This account is not a doctor/staff account."})

        login(request, user)
        return redirect("doctor-dashboard")

    return render(request, "doctor_login.html")





@login_required
def home(request):
    client_id = request.session.get('client_id')
    if not client_id:
        return redirect('login')

    try:
        client = Client.objects.get(id=client_id)
    except Client.DoesNotExist:
        client = None

    api_links = {
        "patients": "/patients/",
        "appointments": "/appointments/",
        "receipts": "/receipts/",
        "clients": "/clients/",
    }

    return render(request, "home.html", {"api_links": api_links, "client": client})

from django.shortcuts import render
from .models import Appointment, Receipt, AllergyAlert, Visit, VitalSigns, ClientNote, Medication, Document, TreatmentPlan

def overview(request):
    if request.user.is_staff:  # doctor
        appointments = Appointment.objects.all()  # filter as needed
        receipts = Receipt.objects.all()
        context = {
            'appointments': appointments,
            'receipts': receipts,
        }
    else:  # customer/patient
        allergies = AllergyAlert.objects.filter(patient__user=request.user)
        visits = Visit.objects.filter(patient__user=request.user)
        vitals = VitalSigns.objects.filter(patient__user=request.user)
        medical_notes = ClientNote.objects.filter(patient__user=request.user)
        medications = Medication.objects.filter(patient__user=request.user)
        documents = Document.objects.filter(patient__user=request.user)
        treatments = TreatmentPlan.objects.filter(patient__user=request.user)
        context = {
            'allergies': allergies,
            'visits': visits,
            'vitals': vitals,
            'medical_notes': medical_notes,
            'medications': medications,
            'documents': documents,
            'treatments': treatments,
        }
    return render(request, 'overview.html', context)

def overview_customer(request):
    # Get the logged-in client
    try:
        client = Client.objects.get(username=request.user.username)
    except Client.DoesNotExist:
        client = None

    if client:
        patients = Patient.objects.filter(client=client)
        allergies = AllergyAlert.objects.filter(patient__in=patients)
        visits = Visit.objects.filter(patient__in=patients)
        vitals = VitalSigns.objects.filter(visit__patient__in=patients)
        medical_notes = ClientNote.objects.filter(visit__patient__in=patients)
        medications = Medication.objects.filter(visit__patient__in=patients)
        documents = Document.objects.filter(patient__in=patients)
        treatments = TreatmentPlan.objects.filter(visit__patient__in=patients)
    else:
        allergies = visits = vitals = medical_notes = medications = documents = treatments = []

    context = {
        'allergies': allergies,
        'visits': visits,
        'vitals': vitals,
        'medical_notes': medical_notes,
        'medications': medications,
        'documents': documents,
        'treatments': treatments,
    }
    return render(request, 'overview_customer.html', context)






@login_required
def doctor_dashboard(request):
    """Doctor dashboard page (staff-only)."""
    if not request.user.is_staff:
        return redirect("home")

    # HTML resource pages (NOT API)
    api_links = {
        "Allergies": "/allergies/",
        "Visits": "/visits/",
        "Vitals": "/vitals/",
        "Communications": "/communications/",
        "Medical Notes": "/medical-notes/",
        "Medications": "/medications/",
        "Documents": "/documents/",
        "Treatments": "/treatments/",
    }

    return render(request, "doctor_dashboard.html", {"api_links": api_links})



@login_required
def resource_page(request, resource_name):
    """Generic front-end resource page that can fetch from api_url."""
    api_url = f"/api/{resource_name}/"
    return render(request, f"{resource_name}.html", {"api_url": api_url})

# views.py
from django.shortcuts import render, redirect
from .models import Client
from django.contrib.auth.decorators import login_required


@login_required
def client_profile(request):
    client_id = request.session.get('client_id')
    client = Client.objects.filter(id=client_id).first()
    return render(request, "client.html", {"client": client})

    # Fetch the client linked to the logged-in user
    try:
        client = Client.objects.get(user=request.user)
    except Client.DoesNotExist:
        client = None

    return render(request, "clients.html", {"client": client})



# views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Client

@login_required
def client_page(request):
    # Get the client linked to the logged-in user
    client = None
    if hasattr(request.user, 'client_profile'):
        client = request.user.client_profile
    else:
        client = Client.objects.filter(email=request.user.email).first()
    
    return render(request, "client.html", {"client": client})



def logout_view(request):
    auth_logout(request)  # clears Django session
    request.session.flush()  # clears custom client session
    return redirect('login')
