# Generated by Django 3.2.12 on 2023-11-08 23:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siem_app', '0003_logentry_accuracy'),
    ]

    operations = [
        migrations.AddField(
            model_name='logentry',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
    ]
