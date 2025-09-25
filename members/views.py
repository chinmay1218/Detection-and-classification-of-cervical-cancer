from django.shortcuts import render, get_object_or_404 # type: ignore
from django.http import JsonResponse # type: ignore
from django.contrib.auth.decorators import login_required # type: ignore
from django.shortcuts import render, redirect # type: ignore
from django.contrib.auth import authenticate, login, logout # type: ignore
from django.contrib.auth.hashers import make_password # type: ignore
from django.db import IntegrityError # type: ignore
from django.contrib import messages # type: ignore
from .models import (
    Patient, 
    MedicalImage, 
    TumorDetection, 
    RiskAssessment, 
    TreatmentRecommendation, 
    Notification, 
    MedicalReport,
    PatientReport,
    PatientScan,
    PatientReportFile,
    User
)



# Generic Registration Function
def register_user(request, role, template_name):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        if not username or not email or not password:
            return render(request, template_name, {'error': 'All fields are required.'})

        if User.objects.filter(username=username).exists():
            return render(request, template_name, {'error': 'Username already exists. Please choose another.'})

        if User.objects.filter(email=email).exists():
            return render(request, template_name, {'error': 'Email already registered. Please use another email.'})

        try:
            user = User.objects.create(
                username=username,
                email=email,
                password=make_password(password),
                role=role  # Assign the role dynamically
            )
            login(request, user)
            return redirect('login')  # Redirect to login page after successful registration
        except IntegrityError:
            return render(request, template_name, {'error': 'An unexpected error occurred. Please try again.'})

    return render(request, template_name)


def register_patient(request):
    if request.method == "POST":
        id=request.POST["id"]
        username = request.POST["username"]
        email = request.POST["email"]
        password = request.POST["password"]

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, "register_patient.html")

        # Create patient user
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()

        # Authenticate and login
        authenticated_user = authenticate(username=username, password=password)
        if authenticated_user:
            login(request, authenticated_user)
            messages.success(request, "Patient registered successfully.")
            return redirect("user_login")  # Update with actual dashboard URL

    return render(request, "register_patient.html")


def register_radiologist(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        password = request.POST["password"]

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, "register_radiologist.html")

        # Create radiologist user
        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_staff = True
        user.save()

        # Add user to radiologist group
        from django.contrib.auth.models import Group # type: ignore
        radiologist_group, created = Group.objects.get_or_create(name='radiologist')
        user.groups.add(radiologist_group)

        # Authenticate and login
        authenticated_user = authenticate(username=username, password=password)
        if authenticated_user:
            login(request, authenticated_user)
            messages.success(request, "Radiologist registered successfully.")
            return redirect("user_login")

    return render(request, "register_radiologist.html")


from django.shortcuts import render, redirect  # type: ignore
from django.contrib.auth import authenticate, login # type: ignore
from django.contrib import messages # type: ignore
from .models import Patient

def user_login(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login successful.")

            if user.is_superuser:
                return redirect('/admin_dashboard/') 
            
            if user.is_staff:
                return redirect('radiologist_dashboard')
            if user.is_active:
                return redirect('patient_dashboard')

            # Find patient using `name` matching `username`
            try:
                patient = Patient.objects.get(name=username)  # Assumes 'name' in Patient == 'username' in User
            except Patient.DoesNotExist:
                messages.warning(request, "No patient record found.")
                return redirect("home")  # Redirect even if no Patient record exists

            return redirect("home")  # Go to home page

        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "login.html")


# User Logout View

from django.contrib.auth import logout # type: ignore
from django.shortcuts import redirect # type: ignore

def user_logout(request):
    logout(request)
    return redirect("home")  # Ensure "login" matches your URL pattern name


from django.shortcuts import render, redirect, get_object_or_404 # type: ignore
from django.contrib.auth.decorators import login_required # type: ignore
from .models import Patient, PatientReport, PatientScan

@login_required
def patient_dashboard(request):
    """ Display the patient's dashboard with reports and scan upload. """
    try:
        patient = Patient.objects.get(user=request.user)
        # Check if patient details are missing
        if not patient.name or not patient.age or not patient.symptoms:
            return redirect('add_patient_details')
    except Patient.DoesNotExist:
        return redirect('add_patient_details')

    reports = PatientReport.objects.filter(patient=patient).order_by("-created_at")

    # Handle image upload (supporting multiple files)
    if request.method == "POST" and request.FILES.get("scans"):
        scan = PatientScan.objects.create(patient=patient, image=request.FILES["scans"])
        image_path = scan.image.path
        # Send to Roboflow API
        result = send_scan_to_roboflow(image_path)
        scan.prediction_result = result
        scan.save()
        print("Roboflow Result:", result)
        predictions = result.get("predictions", [])
        diagnosis_text = predictions[0].get("class") if predictions else "No abnormality detected"

        # Save the report with only the class as diagnosis
        report = PatientReport.objects.create(
            patient=patient,
            findings="Prediction based on scan image.",
            diagnosis=diagnosis_text,
            recommendations="Further evaluation recommended." if predictions else "Routine follow-up.",
            status="Pending",
            uploaded_image=scan.image
        )
        # Find radiologists by checking the user's role
        try:
            # Get all users who are radiologists
            radiologists = User.objects.filter(is_staff=True).filter(groups__name='radiologist')
            for radiologist in radiologists:
                Notification.objects.create(
                    user=radiologist,
                    message=f"New scan uploaded by patient {patient.name}. Please review.",
                    notification_type="Scan"
                )
        except Exception as e:
            print(f"Error creating notifications: {str(e)}")
    # Get patient's scans
    scans = PatientScan.objects.filter(patient=patient).order_by("-uploaded_at")

    context = {
        "patient": patient,
        "reports": reports,
        "scans": scans,
    }

    return render(request, "patient_dashboard.html", context)


from django.shortcuts import render, redirect  # type: ignore
from django.contrib.auth.decorators import login_required  # type: ignore
from .models import Patient, PatientScan
from .apicall import send_scan_to_roboflow

@login_required
def add_patient_details(request):
    if request.method == "POST":
        name = request.POST.get("name")
        age = request.POST.get("age")
        mobile_number = request.POST.get("mobile_number")

        if not name or not age:
            return render(request, "add_patient.html", {"error": "Name and age are required."})

        # Create Patient object
        patient = Patient.objects.create(
            user=request.user,
            name=name,
            age=int(age),
            mobile_number=mobile_number,
            symptoms=request.POST.get("symptoms"),
            family_history=(request.POST.get("family_history") == "on"),
            occupation=request.POST.get("occupation"),
            weight_loss=(request.POST.get("weight_loss") == "on"),
            last_checkup_date=request.POST.get("last_checkup_date"),
        )
        """ 
        # Handle multiple scan uploads
        scans = request.FILES.getlist("scans")
        for scan_file in scans:
            PatientScan.objects.create(patient=patient, image=scan_file) """
        scan_file = request.FILES.get("scans")
        # Save the scan and get its file path
        scan = PatientScan.objects.create(patient=patient, image=scan_file)
        image_path = scan.image.path

        # Send to Roboflow API
        result = send_scan_to_roboflow(image_path)
        scan.prediction_result = result
        scan.save()
        print("Roboflow Result:", result)
        predictions = result.get("predictions", [])
        diagnosis_text = predictions[0].get("class") if predictions else "No abnormality detected"

        # Save the report with only the class as diagnosis
        report = PatientReport.objects.create(
            patient=patient,
            findings="Prediction based on scan image.",
            diagnosis=diagnosis_text,
            recommendations="Further evaluation recommended." if predictions else "Routine follow-up.",
            status="Pending",
            uploaded_image=scan.image
        )

        # return redirect("send_report_to_doctor", patient_id=patient.id)

    return render(request, "add_patient.html")


from .models import PatientScan

@login_required
def update_patient_details(request):
    """ Allow patients to update their own information. """
    patient = Patient.objects.get(user=request.user)

    if request.method == "POST":
        patient.name = request.POST.get("name")
        patient.age = int(request.POST.get("age")) if request.POST.get("age") else patient.age
        mobile_number = request.POST.get("mobile_number")
        patient.symptoms = request.POST.get("symptoms")
        patient.family_history = request.POST.get("family_history") == "on"
        patient.occupation = request.POST.get("occupation")
        patient.weight_loss = request.POST.get("weight_loss") == "on"
        patient.last_checkup_date = request.POST.get("last_checkup_date")

        patient.save()

        # Handle multiple scan uploads
        scans = request.FILES.getlist('scans')
        for image in scans:
            PatientScan.objects.create(patient=patient, image=image)

        return redirect('patient_dashboard')

    return render(request, 'update_patient.html', {'patient': patient})



from django.shortcuts import render, get_object_or_404, redirect  # type: ignore
from django.contrib.auth.decorators import login_required  # type: ignore
from .models import PatientReport, Patient, PatientReportFile

@login_required
def send_report_to_doctor(request, patient_id):
    """Allow patients to submit a report with multiple files for doctor review."""
    patient = get_object_or_404(Patient, id=patient_id, user=request.user)
    
    # Check if a report already exists
    existing_report = PatientReport.objects.filter(patient=patient).first()

    if request.method == "POST":
        if existing_report:
            return render(request, "send_report.html", {
                "patient": patient,
                "error": "You have already submitted a report.",
                "report": existing_report
            })

        # Get list of uploaded files
        report_files = request.FILES.getlist("report_files")

        if not report_files:
            return render(request, "send_report.html", {
                "patient": patient,
                "error": "Please upload at least one report file."
            })

        # Create a new report
        report = PatientReport.objects.create(
            patient=patient,
            findings="Pending Review",
            diagnosis="Pending Review",
            recommendations="Pending Review",
            status="Pending"
        )

        # Attach each uploaded image to the report
        for file in report_files:
            PatientReportFile.objects.create(report=report, image=file)  # use `image=...` not `file=...`

        return redirect("patient_dashboard")  # Redirect after success

    return render(request, "send_report.html", {
        "patient": patient,
        "report": existing_report
    })



from django.shortcuts import render, get_object_or_404, redirect # type: ignore
from django.contrib.auth.decorators import login_required # type: ignore
from .models import PatientReport

@login_required
def radiologist_dashboard(request):
    """ Display all patient reports for the radiologist to review """
    
    reports = PatientReport.objects.filter(status="Pending") # Get all reports
    return render(request, "radiologist_dashboard.html", {"reports": reports})

@login_required
def admin_dashboard(request):
    """ Display all patient reports for the radiologist to review """
    
    reports = PatientReport.objects.filter(status="Pending") # Get all reports
    return render(request, "admin_dashboard.html", {"reports": reports})

from django.shortcuts import render, get_object_or_404, redirect  # type: ignore
from django.contrib.auth.decorators import login_required  # type: ignore
from .models import PatientReport, PatientReportFile, Notification

@login_required
def review_report(request, report_id):
    """ Allow radiologists to review patient reports and submit feedback. """

    report = get_object_or_404(PatientReport, id=report_id)
    report_images = PatientReportFile.objects.filter(report=report)

    # Step 1: Define severity mapping
    severity_mapping = {
        "TB VAY BE MAT": 1,
        "TB VAY TRUNG GIAN": 2,
        "ACUS": 3,
        "LSIL": 4,
        "HSIL": 5,
        "SCC": 6,
    }

    # Step 2: Get stage from predicted_class
    predicted_class = report.diagnosis.upper() if report.diagnosis else ""
    severity_stage = severity_mapping.get(predicted_class, "Unknown")

    if request.method == "POST":
        findings = request.POST.get("findings")
        diagnosis = request.POST.get("diagnosis")
        recommendations = request.POST.get("recommendations")
        approval = request.POST.get("doctor_approved")

        if not (findings and diagnosis and recommendations):
            return render(request, "review_report.html", {
                "report": report,
                "patient": report.patient,
                "report_images": report_images,
                "severity_stage": severity_stage,
                "error": "All fields are required.",
            })

        if approval not in ["True", "False"]:
            return render(request, "doctor_review_report.html", {
                "report": report,
                "severity_stage": severity_stage,
                "error": "Invalid selection. Please choose Approve or Reject."
            })

        # Calculate severity stage based on updated diagnosis
        updated_diagnosis = diagnosis.upper()
        severity_stage = severity_mapping.get(updated_diagnosis, "Unknown")

        # Save feedback
        report.findings = findings
        report.diagnosis = diagnosis
        report.recommendations = recommendations
        report.status = "Reviewed"
        report.severity_stage = severity_stage  # Save the severity stage
        report.save()

        # Create notification for the patient
        Notification.objects.create(
            user=report.patient.user,
            message=f"Your medical report has been reviewed by the radiologist. Please check your dashboard for details.",
            notification_type="Report"
        )

        return redirect("radiologist_dashboard")

    return render(request, "review_report.html", {
        "report": report,
        "report_images": report.uploaded_image.url if report.uploaded_image else None,
        "patient": report.patient,
        "severity_stage": severity_stage,
    })




from django.shortcuts import render, get_object_or_404, redirect # type: ignore
from django.contrib.auth.decorators import login_required # type: ignore
from django.http import HttpResponseForbidden # type: ignore
from .models import PatientReport

@login_required
def view_feedback(request, report_id):
    report = get_object_or_404(PatientReport, id=report_id)
    
    # Check if the user is authorized to view this report
    if request.user != report.patient.user and not request.user.groups.filter(name='radiologist').exists():
        return HttpResponseForbidden("You are not authorized to view this report.")
    
    # Calculate severity stage
    severity_mapping = {
        "TB VAY BE MAT": 1,
        "TB VAY TRUNG GIAN": 2,
        "ACUS": 3,
        "LSIL": 4,
        "HSIL": 5,
        "SCC": 6,
    }
    
    # Diagnosis explanations
    diagnosis_explanations = {
        "TB VAY BE MAT": "The sample shows the presence of superficial squamous epithelial cells, which are considered a normal finding in cervical cytology. There are no signs of cellular atypia, dysplasia, or malignancy. This indicates healthy cervical tissue with no immediate concern for pre-cancerous or cancerous changes.",
        
        "TB VAY TRUNG GIAN": "The cytological examination reveals intermediate squamous epithelial cells, which are also normal components of the cervical epithelium. Their presence is commonly associated with hormonal influences and does not suggest any abnormality or risk of cervical pre-cancer or cancer.",
        
        "ACUS": "The findings show atypical squamous cells of undetermined significance (ASC-US). These cells have slight abnormalities, but it is unclear whether they are related to an early HPV infection or benign reactive changes. Follow-up with repeat Pap testing or HPV testing is recommended to determine the appropriate management.",
        
        "LSIL": "The cervical smear shows a low-grade squamous intraepithelial lesion (LSIL), indicating mild dysplasia usually associated with HPV infection. While LSIL often resolves on its own, it reflects early changes that could progress if persistent, so clinical monitoring and appropriate follow-up are essential.",
        
        "HSIL": "The results indicate a high-grade squamous intraepithelial lesion (HSIL), representing more significant dysplastic changes within the cervical epithelium. HSIL is considered a pre-cancerous condition with a substantial risk of progression to invasive cancer if left untreated; therefore, prompt evaluation with colposcopy and possible biopsy is required.",
        
        "SCC": "The cytology identifies squamous cell carcinoma (SCC) of the cervix, indicating that malignant cells have invaded beyond the epithelial layer. This diagnosis represents invasive cervical cancer and necessitates urgent referral for comprehensive oncological evaluation and treatment planning."
    }
    
    # Get stage from diagnosis
    diagnosis_upper = report.diagnosis.upper() if report.diagnosis else ""
    severity_stage = report.severity_stage if hasattr(report, 'severity_stage') and report.severity_stage else severity_mapping.get(diagnosis_upper, "Unknown")
    
    # Get explanation for the diagnosis
    diagnosis_explanation = diagnosis_explanations.get(diagnosis_upper, "")
    
    context = {
        'report': report,
        'severity_stage': severity_stage,
        'diagnosis_explanation': diagnosis_explanation
    }
    return render(request, 'view_feedback.html', context)



def view_notifications(request):
    if request.user.is_authenticated:
        user_notifications = Notification.objects.filter(user=request.user).order_by('-timestamp')
        unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
    else:
        user_notifications = Notification.objects.none()
        unread_count = 0

    context = {
        'notifications': user_notifications,
        'unread_count': unread_count
    }

    return render(request, 'notifications.html', context)

from django.shortcuts import get_object_or_404, redirect # type: ignore
from django.contrib.auth.decorators import login_required # type: ignore
from .models import Notification

@login_required
def mark_notification_read(request, notification_id):
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.is_read = True
    notification.save()
    
    # Always redirect to patient dashboard
    return redirect('patient_dashboard')


# Home Page View
def home(request):
    return render(request, 'home.html')


# Tumor Detection Results
@login_required
def tumor_detection_results(request, image_id):
    tumor_detection = get_object_or_404(TumorDetection, image_id=image_id)
    return render(request, 'tumor_results.html', {'tumor_detection': tumor_detection})

# Risk Assessment Results
@login_required
def risk_assessment_results(request, patient_id):
    risk = get_object_or_404(RiskAssessment, patient_id=patient_id)
    return render(request, 'risk_results.html', {'risk': risk})

# Treatment Recommendations
@login_required
def treatment_recommendations(request, patient_id):
    treatment = get_object_or_404(TreatmentRecommendation, patient_id=patient_id)
    return render(request, 'treatment_recommendations.html', {'treatment': treatment})

# Generate Medical Reports
@login_required
def medical_reports(request, patient_id):
    reports = MedicalReport.objects.filter(patient_id=patient_id)
    return render(request, 'reports_list.html', {'reports': reports})

from django.http import FileResponse, HttpResponse # type: ignore
import os
import mimetypes
from datetime import datetime

@login_required
def download_radiologist_report(request, report_id):
    """
    View to handle downloading of radiologist reports with formatted content
    """
    try:
        report = PatientReport.objects.get(id=report_id)
        
        # Security check: ensure the requesting user is either the patient or the radiologist
        if not (request.user == report.patient.user or request.user.groups.filter(name='radiologist').exists()):
            raise PermissionDenied
        
        # Check if report is reviewed
        if report.status != 'Reviewed':
            messages.error(request, 'Report is not yet reviewed.')
            return redirect('patient_dashboard')
        
        # Calculate severity stage if not stored in model
        severity_mapping = {
            "TB VAY BE MAT": 1,
            "TB VAY TRUNG GIAN": 2,
            "ACUS": 3,
            "LSIL": 4,
            "HSIL": 5,
            "SCC": 6,
        }
        
        # Get stage from diagnosis
        diagnosis_upper = report.diagnosis.upper() if report.diagnosis else ""
        severity_stage = getattr(report, 'severity_stage', severity_mapping.get(diagnosis_upper, "Unknown"))
        
        # Create a formatted report content
        report_content = f"""
MEDICAL REPORT
=============

Patient Information:
------------------
Name: {report.patient.name}
Date: {report.created_at.strftime('%B %d, %Y')}
Report ID: {report.id}

Findings:
--------
{report.findings}

Diagnosis:
---------
{report.diagnosis}

Severity Stage:
-------------
{severity_stage}

Recommendations:
--------------
{report.recommendations}

Report Status: {report.status}
Generated on: {datetime.now().strftime('%B %d, %Y %I:%M %p')}
        """
        
        # Create the response with the report content
        response = HttpResponse(report_content, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="medical_report_{report.id}.txt"'
        return response
        
    except PatientReport.DoesNotExist:
        messages.error(request, 'Report not found.')
        return redirect('patient_dashboard')

from django.contrib.auth.tokens import default_token_generator # type: ignore
from django.core.mail import send_mail # type: ignore
from django.template.loader import render_to_string # type: ignore
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode # type: ignore
from django.utils.encoding import force_bytes, force_str # type: ignore
from django.contrib.auth import get_user_model # type: ignore
from django.urls import reverse # type: ignore

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Build password reset URL
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            )
            
            # Send email
            subject = 'Password Reset Request'
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_url': reset_url,
            })
            send_mail(subject, message, 'noreply@example.com', [email])
            
            messages.success(request, 'Password reset link has been sent to your email.')
            return redirect('password_reset_done')
        except User.DoesNotExist:
            messages.error(request, 'No user found with this email address.')
    
    return render(request, 'forgot_password.html')

def password_reset_done(request):
    return render(request, 'password_reset_done.html')

def password_reset_confirm(request, uidb64, token):
    try:
        User = get_user_model()
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if not new_password or not confirm_password:
                messages.error(request, 'Please enter both passwords.')
                return render(request, 'password_reset_confirm.html')
            
            if new_password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'password_reset_confirm.html')
            
            if len(new_password) < 8:
                messages.error(request, 'Password must be at least 8 characters long.')
                return render(request, 'password_reset_confirm.html')
            
            try:
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Your password has been reset successfully. You can now login with your new password.')
                return redirect('user_login')
            except Exception as e:
                messages.error(request, 'An error occurred while resetting your password. Please try again.')
                return render(request, 'password_reset_confirm.html')
        
        return render(request, 'password_reset_confirm.html')
    else:
        messages.error(request, 'The password reset link is invalid or has expired. Please request a new one.')
        return redirect('forgot_password')
