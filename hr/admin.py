from django.contrib import admin
from .models import User, Organisation, OrganisationStaff, Application, Job


admin.site.register(User)
admin.site.register(Organisation)
admin.site.register(OrganisationStaff)
admin.site.register(Application)
admin.site.register(Job)
