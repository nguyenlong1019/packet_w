from django.contrib import admin
from core.models.pcap_file import PcapFileUpload 
from core.models.profile import Profile 


@admin.register(PcapFileUpload)
class PcapFileUploadAdmin(admin.ModelAdmin):
    readonly_fields = ('uploaded_at',)
    search_fields = ('user',)


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    readonly_fields = ('created_at',)
    search_fields = ('full_name',)
