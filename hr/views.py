from rest_framework import viewsets, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse
from django.shortcuts import get_object_or_404
from .models import User, Organisation, Job, Application, OrganisationStaff
from .serializers import (
    UserSerializer, LoginSerializer, OrganisationSerializer, JobSerializer,
    ApplicationSerializer, OrganisationStaffSerializer, JoinOrganisationSerializer,
    RemoveStaffSerializer, AssignHRRoleSerializer
)
from .permissions import IsOrgAdmin, IsOrgAdminOrHR, IsOrgHR, IsNotOrganizationMember


class AccountViewSet(viewsets.GenericViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    @extend_schema(
        request=UserSerializer,
        responses={201: OpenApiResponse(response=UserSerializer)},
        description="Create a new user account."
    )
    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

    @extend_schema(
        request=LoginSerializer,
        responses={200: OpenApiResponse(description="Login successful")},
        description="Authenticate a user and return tokens."
    )
    @action(detail=False, methods=['post'], serializer_class=LoginSerializer, permission_classes=[AllowAny])
    def login(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        tokens = user.get_tokens()
        return Response({
            'status': True,
            'data': {
                'auth_credentials': tokens,
                'user': UserSerializer(user).data
            }
        })


class OrganisationViewSet(viewsets.ModelViewSet):
    queryset = Organisation.objects.all()
    serializer_class = OrganisationSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={201: OpenApiResponse(response=OrganisationSerializer)},
        description="Create a new organisation."
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organisation = serializer.save()
        return Response({
            'status': True,
            'data': OrganisationSerializer(organisation).data
        }, status=status.HTTP_201_CREATED)

    @extend_schema(
        request=JoinOrganisationSerializer,
        responses={
            200: OpenApiResponse(response=OrganisationStaffSerializer),
            400: OpenApiResponse(description="Bad request"),
            403: OpenApiResponse(description="Forbidden - User already in an organization")
        },
        description="Join an organisation as a staff member."
    )
    @action(detail=False, methods=['post'], 
            serializer_class=JoinOrganisationSerializer,
            permission_classes=[IsAuthenticated, IsNotOrganizationMember])
    def join(self, request):
        serializer = JoinOrganisationSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        staff = serializer.save()
        return Response(OrganisationStaffSerializer(staff).data)

    @extend_schema(
        responses={200: OpenApiResponse(response=OrganisationStaffSerializer(many=True))},
        description="Get a list of organisation staff members."
    )
    @action(detail=False, methods=['get'], permission_classes=[IsOrgAdmin])
    def staff(self, request):
        staff = OrganisationStaff.objects.filter(organisation=request.user.organisation)
        serializer = OrganisationStaffSerializer(staff, many=True)
        return Response(serializer.data)

    @extend_schema(
        request=RemoveStaffSerializer,
        responses={204: OpenApiResponse(description="Staff member removed successfully")},
        description="Remove a staff member from the organisation."
    )
    @action(detail=False, methods=['post'], serializer_class=RemoveStaffSerializer, permission_classes=[IsOrgAdmin])
    def remove_staff(self, request):
        serializer = RemoveStaffSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=AssignHRRoleSerializer,
        responses={204: OpenApiResponse(description="HR role assigned successfully")},
        description="Admin assigns HR roles to staff members of the organisation."
    )
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated, IsOrgAdmin])
    def assign_hr_role(self, request):
        serializer = AssignHRRoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        staff = OrganisationStaff.objects.get(id=serializer.validated_data['staff_id'])
        
        # Ensure the staff member belongs to the admin's organization
        if staff.organisation != request.user.organisation:
            return Response({"detail": "This staff member does not belong to your organization."},
                            status=status.HTTP_400_BAD_REQUEST)
        
        staff.role = 'ORG_HR'
        staff.save()
        
        # Update the User model as well
        staff.user.role = 'ORG_HR'
        staff.user.save()
        
        return Response({"detail": "HR role assigned successfully."}, status=status.HTTP_200_OK)


class JobViewSet(viewsets.ModelViewSet):
    queryset = Job.objects.all()
    serializer_class = JobSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update']:
            return [IsAuthenticated(), IsOrgHR()]
        return [IsAuthenticated()]

    @extend_schema(
        responses={201: OpenApiResponse(response=JobSerializer)},
        description="Create a new job opening."
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = serializer.save()
        return Response({
            'status': True,
            'data': JobSerializer(job).data
        }, status=status.HTTP_201_CREATED)

    @extend_schema(
        responses={200: OpenApiResponse(response=JobSerializer)},
        description="Update a job opening."
    )
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        job = serializer.save()
        return Response({
            'status': True,
            'data': JobSerializer(job).data
        })

    @extend_schema(
        responses={200: OpenApiResponse(response=JobSerializer(many=True))},
        description="Get a list of all open job openings."
    )
    def list(self, request, *args, **kwargs):
        jobs = Job.objects.filter(is_open=True)
        serializer = self.get_serializer(jobs, many=True)
        return Response({
            'status': True,
            'data': serializer.data
        })

    @extend_schema(
        request=ApplicationSerializer,
        responses={201: OpenApiResponse(response=ApplicationSerializer)},
        description="Apply for a job opening."
    )
    @action(detail=True, methods=['post'], serializer_class=ApplicationSerializer)
    def apply(self, request, pk=None):
        job = self.get_object()
        user = request.user

        # Validation moved from serializer to view
        if user.organisation == job.organisation:
            return Response({"detail": "You cannot apply to a job in your own organisation."}, 
                            status=status.HTTP_400_BAD_REQUEST)
        if Application.objects.filter(applicant=user, job=job).exists():
            return Response({"detail": "You have already applied to this job."}, 
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = ApplicationSerializer(data=request.data, context={'request': request, 'job': job})
        serializer.is_valid(raise_exception=True)
        application = serializer.save()
        return Response(ApplicationSerializer(application).data, status=status.HTTP_201_CREATED)

    @extend_schema(
        responses={200: OpenApiResponse(response=ApplicationSerializer(many=True))},
        description="Get a list of applications for a job opening."
    )
    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated, IsOrgAdminOrHR])
    def applications(self, request, pk=None):
        job = self.get_object()
        self.check_object_permissions(request, job)
        applications = Application.objects.filter(job=job)
        serializer = ApplicationSerializer(applications, many=True)
        return Response(serializer.data)
