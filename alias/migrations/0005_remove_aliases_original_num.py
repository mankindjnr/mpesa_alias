# Generated by Django 4.2.5 on 2023-09-18 10:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('alias', '0004_aliases_num_cipher_alter_aliases_desired_alias_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='aliases',
            name='original_num',
        ),
    ]
