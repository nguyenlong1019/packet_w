from django.contrib.auth.models import AbstractUser 
from django.db import models 


class CustomUser(AbstractUser):
    is_access = models.BooleanField(default=False)


    def save(self, *args, **kwargs):
        if self.is_superuser:
            self.is_access = True
        super(CustomUser, self).save(*args, **kwargs)


