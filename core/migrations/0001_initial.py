# Generated by Django 4.2.9 on 2024-09-17 04:12

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(blank=True, editable=False, null=True)),
                ('updated_at', models.DateTimeField(auto_now_add=True)),
                ('is_access', models.BooleanField(default=False, verbose_name='Quyền truy cập')),
                ('full_name', models.CharField(blank=True, max_length=255, null=True, verbose_name='Họ và tên')),
                ('avatar', models.ImageField(blank=True, null=True, upload_to='user_imgs/', verbose_name='Ảnh đại diện')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='Tài khoản liên kết')),
            ],
            options={
                'verbose_name': 'Hồ sơ cá nhân',
                'verbose_name_plural': 'Hồ sơ cá nhân',
                'db_table': 'profile',
                'ordering': ('full_name',),
            },
        ),
        migrations.CreateModel(
            name='PcapFileUpload',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_upload', models.FileField(upload_to='pcap_files/', verbose_name='Tệp tải lên')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='Tài khoản')),
            ],
            options={
                'verbose_name': 'Quản lý tệp PCAP',
                'db_table': 'pcap_files',
                'ordering': ('-uploaded_at',),
            },
        ),
    ]
