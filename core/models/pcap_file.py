from django.db import models 
from django.contrib.auth.models import User 
from django.dispatch import receiver 
from django.db.models.signals import pre_delete 


class PcapFileUpload(models.Model):
    id = models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Tài khoản')
    file_upload = models.FileField(upload_to='pcap_files/', verbose_name='Tệp tải lên')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    
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
