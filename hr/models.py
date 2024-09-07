import uuid
import random
import string
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from .enum import ROLE_CHOICES, STAFF_ROLE_CHOICES, STATUS


# Custom User Model
class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='USER')
    organisation = models.ForeignKey(
        'Organisation', on_delete=models.SET_NULL, null=True, blank=True, related_name='members'
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email


# Organisation Model
class Organisation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    valuation = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    admin = models.OneToOneField(User, on_delete=models.CASCADE, related_name='organisation_admin')
    staff_access_code = models.CharField(max_length=3, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.staff_access_code:
            self.staff_access_code = self.generate_unique_access_code()
        super().save(*args, **kwargs)

    def generate_unique_access_code(self):
        # Logic to generate a unique 3-character staff access code
        while True:
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
            if not Organisation.objects.filter(staff_access_code=code).exists():
                return code


# Job Model
class Job(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='jobs')
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name='jobs')
    title = models.CharField(max_length=255)
    description = models.CharField(max_length=500)
    is_open = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


# Application Model
class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name='applications')
    applicant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='applications')
    skill_description = models.CharField(max_length=500)
    status = models.CharField(max_length=10, choices=STATUS, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Application by {self.applicant.email} for {self.job.title}"


# OrganisationStaff Model
class OrganisationStaff(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name='staff')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='staff_roles')
    role = models.CharField(max_length=10, choices=STAFF_ROLE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} as {self.get_role_display()} at {self.organisation.name}"
