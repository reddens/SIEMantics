# Generated by Django 3.2.12 on 2023-11-08 22:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siem_app', '0002_auto_20231108_2221'),
    ]

    operations = [
        migrations.AddField(
            model_name='logentry',
            name='accuracy',
            field=models.TextField(null=True),
        ),
    ]