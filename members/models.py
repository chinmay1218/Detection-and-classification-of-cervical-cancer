from django.db import models # type: ignore
from django.contrib.auth.models import AbstractUser,Group, Permission # type: ignore


class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('radiologist', 'Radiologist'),
        ('patient', 'Patient'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    groups = models.ManyToManyField(Group, related_name="custom_user_groups", blank=True)

    user_permissions = models.ManyToManyField(Permission, related_name="custom_user_permissions", blank=True)

from django.db import models  # type: ignore
from django.contrib.auth.models import User  # type: ignore

class Patient(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    age = models.IntegerField()
    mobile_number = models.CharField(max_length=15, blank=True, null=True)
    symptoms = models.TextField()
    family_history = models.BooleanField(default=False)
    occupation = models.CharField(max_length=255, blank=True, null=True)
    weight_loss = models.BooleanField(default=False)
    last_checkup_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return self.name



class PatientScan(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='scans')
    image = models.ImageField(upload_to='ct_scans/')
    prediction_result = models.JSONField(null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Scan {self.id} for {self.patient.name}"

  




class PatientReport(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    findings = models.TextField()
    diagnosis = models.TextField()
    severity_stage = models.CharField(max_length=20, blank=True, null=True)
    recommendations = models.TextField()
    status = models.CharField(
        max_length=20,
        choices=[("Pending", "Pending"), ("Reviewed", "Reviewed")],
        default="Pending"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    uploaded_image = models.ImageField(upload_to="reports/", blank=True, null=True)
    doctor_approved = models.BooleanField(null=True, blank=True)

    def __str__(self):
        return f"Report for {self.patient.name} - {self.status}"




# in models.py
class PatientReportFile(models.Model):
    report = models.ForeignKey('PatientReport', related_name='files', on_delete=models.CASCADE)
    image = models.ImageField(upload_to='report_images/', null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)





class MedicalImage(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)



from django.db import models # type: ignore
from django.contrib.auth.models import User # type: ignore

class Notification(models.Model):
    NOTIFICATION_TYPES = (
        ('Scan', 'Scan'),
        ('Report', 'Report'),
        ('Reminder', 'Reminder'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.notification_type} - {self.message}"





class TumorDetection(models.Model):
    TUMOR_TYPE_CHOICES = (
        ('Benign', 'Benign'),
        ('Malignant', 'Malignant'),
    )
    image = models.ForeignKey(MedicalImage, on_delete=models.CASCADE)
    tumor_detected = models.BooleanField()
    tumor_type = models.CharField(max_length=10, choices=TUMOR_TYPE_CHOICES, null=True, blank=True)
    confidence_score = models.DecimalField(max_digits=3, decimal_places=2)
    detected_at = models.DateTimeField(auto_now_add=True)

class RiskAssessment(models.Model):
    SEVERITY_CHOICES = (
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    )
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    risk_score = models.DecimalField(max_digits=3, decimal_places=2)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    recommendation = models.TextField()

class TreatmentRecommendation(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    suggested_treatment = models.TextField()
    doctor_approval = models.BooleanField(default=False)





class MedicalReport(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    report_type = models.CharField(max_length=100)
    generated_at = models.DateTimeField(auto_now_add=True)

class MLTraining(models.Model):
    dataset_version = models.CharField(max_length=50)
    model_accuracy = models.DecimalField(max_digits=3, decimal_places=2)
    last_trained = models.DateTimeField(auto_now_add=True)

