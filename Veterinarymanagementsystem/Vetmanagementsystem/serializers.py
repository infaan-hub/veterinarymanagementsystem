# Vetmanagementsystem/serializers.py
from rest_framework import serializers
from .models import (
    CustomUser,
    DoctorProfile,
    Client,
    Patient,
    AllergyAlert,
    Visit,
    VitalSigns,
    ClientCommunicationNote,
    ClientNote,
    Medication,
    Document,
    TreatmentPlan,
    Appointment,
    Receipt,
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "first_name", "last_name", "is_staff", "is_active"]


class DoctorProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = DoctorProfile
        fields = "__all__"


class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = "__all__"


class PatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = "__all__"


class AllergySerializer(serializers.ModelSerializer):
    class Meta:
        model = AllergyAlert
        fields = "__all__"


class VisitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Visit
        fields = "__all__"


class VitalSerializer(serializers.ModelSerializer):
    class Meta:
        model = VitalSigns
        fields = "__all__"


class CommunicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientCommunicationNote
        fields = "__all__"


class MedicalNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientNote
        fields = "__all__"


class MedicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Medication
        fields = "__all__"


class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = "__all__"


class TreatmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = TreatmentPlan
        fields = "__all__"


class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = "__all__"


class DoctorReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = Receipt
        fields = "__all__"


class ClientReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = Receipt
        fields = ["id", "amount", "date", "status"]