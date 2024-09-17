from django.contrib.auth.models import User 
from django.db import models 
from packet_server.utils import CommonAbstract


class Profile(CommonAbstract):
    id = models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')
    user = models.OneToOneField(User, on_delete=models.CASCADE, verbose_name='Tài khoản liên kết')
    is_access = models.BooleanField(default=False, verbose_name='Quyền truy cập')
    full_name = models.CharField(max_length=255, null=True, blank=True, verbose_name='Họ và tên')
    avatar = models.ImageField(upload_to='user_imgs/', null=True, blank=True, verbose_name='Ảnh đại diện') # should be set default 


    class Meta:
        ordering = ('full_name',)
        verbose_name = 'Hồ sơ cá nhân'
        verbose_name_plural = 'Hồ sơ cá nhân'
        db_table = 'profile'


    def __str__(self):
        return f"{self.id} - {self.full_name} - {self.is_access}"


    def save(self, *args, **kwargs):
        if self.user.is_superuser:
            self.is_access = True
        super(Profile, self).save(*args, **kwargs)


