from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError
from .models import Organisation, Job, Application, OrganisationStaff
import re


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'password', 'confirm_password', 'role', 'organisation']
        read_only_fields = ['id', 'role', 'organisation']

    def validate_email(self, email):
        if not email:
            raise serializers.ValidationError("Email is required.")
        
        email = email.lower().strip()
        try:
            validate_email(email)
        except DjangoValidationError as e:
            raise serializers.ValidationError(str(e))

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Account with this email already exists")

        return email

    def validate_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Name cannot be empty.")
        return value.strip()

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password'],
            role='USER'  # Set default role to USER
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            if not user:
                raise serializers.ValidationError("Unable to log in with provided credentials.")
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'.")

        data['user'] = user
        return data


class OrganisationSerializer(serializers.ModelSerializer):
    admin = serializers.PrimaryKeyRelatedField(read_only=True)
    staff_access_code = serializers.CharField(read_only=True)

    class Meta:
        model = Organisation
        fields = ['id', 'name', 'valuation', 'location', 'admin', 'staff_access_code']

    def create(self, validated_data):
        user = self.context['request'].user
        organisation = Organisation.objects.create(admin=user, **validated_data)
        user.role = 'ORG_ADMIN'
        user.organisation = organisation
        user.save()
        return organisation


class JobSerializer(serializers.ModelSerializer):
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)
    organisation = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Job
        fields = ['id', 'title', 'description', 'is_open', 'created_by', 'organisation']

    def validate(self, data):
        user = self.context['request'].user
        if user.role != 'ORG_HR':
            raise serializers.ValidationError("Only Organisation HR can create or update job openings.")
        return data

    def create(self, validated_data):
        user = self.context['request'].user
        job = Job.objects.create(
            created_by=user,
            organisation=user.organisation,
            **validated_data
        )
        return job


class ApplicationSerializer(serializers.ModelSerializer):
    applicant = serializers.PrimaryKeyRelatedField(read_only=True)
    job = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Application
        fields = ['id', 'job', 'applicant', 'skill_description', 'status']
        read_only_fields = ['id', 'job', 'applicant', 'status']

    def create(self, validated_data):
        user = self.context['request'].user
        job = self.context['job']
        application = Application.objects.create(applicant=user, job=job, **validated_data)
        return application


class OrganisationStaffSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = OrganisationStaff
        fields = ['id', 'organisation', 'user', 'role']
        read_only_fields = ['id', 'organisation', 'user']

    def validate(self, data):
        user = self.context['request'].user
        if user.role != 'ORG_ADMIN':
            raise serializers.ValidationError("Only Organisation Admin can manage staff.")
        return data


class JoinOrganisationSerializer(serializers.Serializer):
    org_access_code = serializers.CharField(max_length=3)

    def validate(self, data):
        user = self.context['request'].user
        if user.organisation or user.role != 'USER':
            raise serializers.ValidationError("You are already part of an organization or have a special role.")
        
        try:
            organisation = Organisation.objects.get(staff_access_code=data['org_access_code'])
        except Organisation.DoesNotExist:
            raise serializers.ValidationError("Invalid organisation access code.")
        
        data['organisation'] = organisation
        return data

    def create(self, validated_data):
        user = self.context['request'].user
        organisation = validated_data['organisation']
        
        staff = OrganisationStaff.objects.create(
            organisation=organisation,
            user=user,
            role='ORG_STAFF'
        )
     
        user.organisation = organisation
        user.role = 'ORG_STAFF'
        user.save()
        return staff


class RemoveStaffSerializer(serializers.Serializer):
    staff_id = serializers.UUIDField()

    def validate(self, data):
        user = self.context['request'].user
        if user.role != 'ORG_ADMIN':
            raise serializers.ValidationError("Only Organisation Admin can remove staff members.")
        
        try:
            staff = OrganisationStaff.objects.get(id=data['staff_id'], organisation=user.organisation)
        except OrganisationStaff.DoesNotExist:
            raise serializers.ValidationError("Staff member not found in your organisation.")
        
        data['staff'] = staff
        return data

    def create(self, validated_data):
        staff = validated_data['staff']
        user = staff.user
        user.organisation = None
        user.role = 'USER'
        user.save()
        staff.delete()
        return user


class AssignHRRoleSerializer(serializers.Serializer):
    staff_id = serializers.UUIDField()

    def validate_staff_id(self, value):
        try:
            staff = OrganisationStaff.objects.get(id=value)
        except OrganisationStaff.DoesNotExist:
            raise serializers.ValidationError("Staff member not found.")
        
        if staff.role == 'ORG_HR':
            raise serializers.ValidationError("This staff member is already an HR.")
        
        return value
