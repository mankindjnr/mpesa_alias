# Generated by Django 4.2.5 on 2023-09-19 11:06

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('alias', '0011_alter_aliases_created_on_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='verifiedDigits',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('theDigits', models.CharField(help_text='i.e 254123456789', max_length=12, validators=[django.core.validators.RegexValidator(code='invalid number format', message='Must be 12 digits i.e 254123456789', regex='^\\d{12}$')])),
                ('validated', models.BooleanField(default=False)),
                ('validate_at', models.DateTimeField()),
                ('digitsOwner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='alias.supaprofile')),
            ],
        ),
    ]
