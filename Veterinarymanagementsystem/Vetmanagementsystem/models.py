# Vetmanagementsystem/models.py
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser, Group, Permission


class CustomUser(AbstractUser):
    """
    Custom user model. Use is_staff to mark doctors.
    """
    groups = models.ManyToManyField(Group, related_name="custom_users", blank=True)
    user_permissions = models.ManyToManyField(
        Permission, related_name="custom_user_permissions", blank=True
    )

    def __str__(self):
        return self.username


class DoctorProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="doctor_profile"
    )
    specialization = models.CharField(max_length=120, blank=True)
    phone = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)  # enable/disable doctor accounts

    def __str__(self):
        return f"Dr. {self.user.get_full_name() or self.user.username}"



from django.contrib.auth.hashers import make_password, check_password
import random

class Client(models.Model):
    username = models.CharField(max_length=150, unique=True)
    full_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    password = models.CharField(max_length=256)  # store hashed password
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    client_id = models.CharField(max_length=10, unique=True, blank=True, null=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def save(self, *args, **kwargs):
        if not self.client_id:
            self.client_id = f"C-{random.randint(100000, 999999)}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.client_id} - {self.full_name}"



 



class Patient(models.Model):
    patient_id = models.CharField(max_length=20, unique=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="patients")
    name = models.CharField(max_length=100)
    species = models.CharField(max_length=50)
    breed = models.CharField(max_length=100, blank=True, null=True)
    gender = models.CharField(max_length=20)
    color = models.CharField(max_length=50, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    weight_kg = models.DecimalField(max_digits=6, decimal_places=2, blank=True, null=True)
    photo = models.ImageField(upload_to="patients/photos/", blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.patient_id})"


class AllergyAlert(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name="allergies")
    description = models.TextField()
    severity_level = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Allergy for {self.patient.name}"


class Visit(models.Model):
    STATUS_CHOICES = [
        ("Checked-in", "Checked-in"),
        ("Ready for discharge", "Ready for discharge"),
        ("Discharged", "Discharged"),
    ]

    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name="visits")
    veterinarian = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="visits"
    )
    visit_date = models.DateTimeField()
    visit_status = models.CharField(max_length=50, choices=STATUS_CHOICES, default="Checked-in")
    location_status = models.CharField(max_length=100, blank=True, null=True)
    age_months = models.IntegerField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Visit - {self.patient.name} ({self.visit_date.date()})"


class VitalSigns(models.Model):
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="vitals")
    weight_lbs = models.DecimalField(max_digits=6, decimal_places=2, blank=True, null=True)
    weight_oz = models.DecimalField(max_digits=6, decimal_places=2, blank=True, null=True)
    temperature = models.DecimalField(max_digits=4, decimal_places=1, blank=True, null=True)
    respiration = models.IntegerField(blank=True, null=True)
    heart_rate = models.IntegerField(blank=True, null=True)
    recorded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Vitals for {self.visit.patient.name}"


class ClientCommunicationNote(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="communications")
    message = models.TextField()
    date = models.DateTimeField(auto_now_add=True)
    saved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )

    def __str__(self):
        return f"Note for {self.client.full_name}"


class ClientNote(models.Model):
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="medical_notes")
    note = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Medical Note - {self.visit.patient.name}"


class Medication(models.Model):
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="medications")
    name = models.CharField(max_length=100)
    dosage = models.CharField(max_length=50)
    frequency = models.CharField(max_length=50)
    duration = models.CharField(max_length=50, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class Document(models.Model):
    DOCUMENT_TYPES = [
        ("Rabies Certificate", "Rabies Certificate"),
        ("Spay/Neuter Certificate", "Spay/Neuter Certificate"),
        ("Referral", "Referral"),
        ("Other", "Other"),
    ]

    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name="documents")
    document_type = models.CharField(max_length=50, choices=DOCUMENT_TYPES)
    file = models.FileField(upload_to="documents/")
    issued_date = models.DateField()

    def __str__(self):
        return f"{self.document_type} - {self.patient.name}"


class TreatmentPlan(models.Model):
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="treatment_plans")
    diagnosis = models.TextField()
    treatment_description = models.TextField()
    follow_up_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"Treatment Plan - {self.visit.patient.name}"


class Appointment(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name="appointments")
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="appointments")
    date = models.DateTimeField()
    reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Appointment: {self.patient.name} on {self.date}"


class Receipt(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="receipts")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()
    status = models.CharField(
        max_length=20,
        choices=[("Pending", "Pending"), ("Paid", "Paid"), ("Cancelled", "Cancelled")],
        default="Pending",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Receipt {self.id} - {self.client.full_name}"



  