# Generated by Django 4.2.5 on 2023-09-18 13:21

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('alias', '0008_supaprofile_first_login_at'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='sendMoney',
            new_name='aliasTransactions',
        ),
    ]
