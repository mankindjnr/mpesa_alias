# Generated by Django 4.2.5 on 2023-09-17 10:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('alias', '0002_aliases_alias_owner'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='aliases',
            name='the_alias',
        ),
        migrations.AddField(
            model_name='aliases',
            name='desired_alias',
            field=models.CharField(default='alias0'),
        ),
        migrations.AddField(
            model_name='aliases',
            name='original_num',
            field=models.CharField(default='original0', max_length=12),
        ),
    ]
