from django.db import models 
from django.utils import timezone 


class CommonAbstract(models.Model):
    created_at = models.DateTimeField(null=True, blank=True, editable=False)
    updated_at = models.DateTimeField(auto_now_add=True)


    class Meta:
        abstract = True 

    
    def save(self, *args, **kwargs):
        if not self.created_at:
            self.created_at = timezone.now()
        super(CommonAbstract, self).save(*args, **kwargs)
