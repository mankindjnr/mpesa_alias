# Generated by Django 4.2.5 on 2023-09-18 07:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('alias', '0003_remove_aliases_the_alias_aliases_desired_alias_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='aliases',
            name='num_cipher',
            field=models.BinaryField(default=b'gAAAAABlB_WP4CcWffimmVUMpygEbXfKGTVWW_DSlU8UOp6R-lveTUxenZTzKOExb1J_Gcikz3mT8OEFQJUsIcSIuXZtsAXRWg=='),
        ),
        migrations.AlterField(
            model_name='aliases',
            name='desired_alias',
            field=models.CharField(default='alias0', unique=True),
        ),
        migrations.CreateModel(
            name='lockAndKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('designated_alias', models.CharField(default='alias0', unique=True)),
                ('keysAES', models.BinaryField()),
                ('keysPrivate', models.BinaryField()),
                ('keysOwner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='alias.supaprofile')),
            ],
        ),
    ]
