# Generated by Django 4.2.5 on 2023-09-18 12:08

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('alias', '0007_alter_aliases_created_on_alter_lockandkey_created_on_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='supaprofile',
            name='first_login_at',
            field=models.DateTimeField(auto_now_add=True, default=datetime.datetime(2023, 9, 18, 12, 8, 25, 202536, tzinfo=datetime.timezone.utc)),
            preserve_default=False,
        ),
    ]