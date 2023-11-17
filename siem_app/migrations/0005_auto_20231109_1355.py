# Generated by Django 3.2.12 on 2023-11-09 13:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siem_app', '0004_logentry_created_at'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='crawlhistory',
            name='crawled_website',
        ),
        migrations.AddField(
            model_name='crawlhistory',
            name='crawled_results',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='crawlhistory',
            name='crawled_url',
            field=models.URLField(null=True),
        ),
    ]