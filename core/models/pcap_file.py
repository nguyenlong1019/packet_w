from django.db import models 
from django.contrib.auth.models import User 
from django.dispatch import receiver 
from django.db.models.signals import pre_delete, post_save 
import csv 
import json 
import pyshark 
import xml.etree.ElementTree as ET 
from io import StringIO 
from django.core.files.base import ContentFile 
import subprocess 
import os 


class PcapFileUpload(models.Model):
    id = models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Tài khoản')
    file_upload = models.FileField(upload_to='pcap_files/', verbose_name='Tệp tải lên')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    csv_file = models.FileField(upload_to='csv_exports/', null=True, blank=True, verbose_name='CSV data export')
    json_file = models.FileField(upload_to='json_exports/', null=True, blank=True)
    xml_file = models.FileField(upload_to='xml_exports/', null=True, blank=True)
    text_file = models.FileField(upload_to='docx_exports/', null=True, blank=True)
    ftp_data_file = models.FileField(upload_to='fpt_data_exports/', null=True, blank=True)
    http_data_file = models.FileField(upload_to='http_data_exports/', null=True, blank=True)
    tls_session_key = models.FileField(upload_to='tls_session_exports/', null=True, blank=True)
    snmp_file = models.FileField(upload_to='snmp_exports/', null=True, blank=True)
    telnet_file = models.FileField(upload_to='telnet_exports/', null=True, blank=True)
    smtp_file = models.FileField(upload_to='smtp_exports/', null=True, blank=True)
    ssh_file = models.FileField(upload_to='ssh_exports/', null=True, blank=True)

    report_file = models.FileField(upload_to='reports/', null=True, blank=True)
    
    class Meta:
        ordering = ('-uploaded_at',)
        verbose_name = 'Tệp PCap'
        verbose_name = 'Quản lý tệp PCAP'
        db_table = 'pcap_files'

    
    def __str__(self):
        return f"{self.id} - {self.file_upload.name}" 
    

    # def delete(self, *args, **kwargs):
    #     if self.file_upload:
    #         self.file_upload.delete(False)
    #     super(PcapFileUpload, self).delete(*args, **kwargs)
    

@receiver(pre_delete, sender=PcapFileUpload)
def delete_file_on_delete(sender, instance, **kwargs):
    if instance.file_upload:
        instance.file_upload.delete(False) 


@receiver(post_save, sender=PcapFileUpload)
def generate_files(sender, instance, created, **kwargs):
    if created:
        # print("Current working directory:", os.getcwd())
        subprocess.Popen(['python', f'process_pcap.py', str(instance.id)])
