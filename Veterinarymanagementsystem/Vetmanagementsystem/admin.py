# admin.py
from django.contrib import admin
from .models import (
    CustomUser, Client, Patient, AllergyAlert, Visit, VitalSigns,
    ClientCommunicationNote, ClientNote, Medication, Document, TreatmentPlan
)

admin.site.register(CustomUser)
admin.site.register(Client)
admin.site.register(Patient)
admin.site.register(AllergyAlert)
admin.site.register(Visit)
admin.site.register(VitalSigns)
admin.site.register(ClientCommunicationNote)
admin.site.register(ClientNote)
admin.site.register(Medication)
admin.site.register(Document)
admin.site.register(TreatmentPlan)