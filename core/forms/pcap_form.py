from django import forms 
from core.models.pcap_file import PcapFileUpload 


class UploadFileForm(forms.ModelForm):
    class Meta:
        model = PcapFileUpload 
        fields = ['file_upload']
