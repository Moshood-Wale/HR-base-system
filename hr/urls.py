from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import AccountViewSet, OrganisationViewSet, JobViewSet


router = DefaultRouter()
router.register(r'account', AccountViewSet, basename='account')
router.register(r'org', OrganisationViewSet, basename='organisation')
router.register(r'jobs', JobViewSet, basename='job')

urlpatterns = [
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('', include(router.urls)),
]