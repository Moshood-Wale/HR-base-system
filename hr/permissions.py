from rest_framework import permissions


class IsOrgAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'ORG_ADMIN'


class IsOrgHR(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'ORG_HR'


class IsOrgAdminOrHR(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return (request.user.role in ['ORG_ADMIN', 'ORG_HR'] and
                request.user.organisation == obj.organisation)


class IsNotOrganizationMember(permissions.BasePermission):
    """
    Custom permission to only allow users who are not part of any organization.
    """
    def has_permission(self, request, view):
        return request.user.organisation is None and request.user.role == 'USER'
