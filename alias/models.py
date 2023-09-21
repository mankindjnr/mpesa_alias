from django.db import models
from datetime import datetime
from django.contrib.auth.models import User
from django.core.validators import RegexValidator

class supaProfile(models.Model):
    supa_id = models.UUIDField()
    email = models.EmailField()
    first_login_at = models.DateTimeField()

class aliases(models.Model):
    alias_owner = models.ForeignKey(supaProfile, on_delete=models.CASCADE)
    num_cipher = models.BinaryField(default=None)
    email = models.EmailField()
    desired_alias = models.CharField(unique=True, db_index=True)
    created_on = models.DateTimeField()

class lockAndKey(models.Model):
    keysOwner = models.ForeignKey(supaProfile, on_delete=models.CASCADE)
    designated_alias = models.CharField(unique=True, default="alias0")
    keysAES = models.BinaryField()
    keysPrivate = models.BinaryField()
    created_on = models.DateTimeField()

class aliasTransactions(models.Model):
    sender = models.CharField(max_length=255)
    receiver = models.CharField(max_length=255)
    amount = models.IntegerField()
    transaction_completed = models.BooleanField(default=False)
    transaction_identifier = models.CharField(default="wc5f2_97ef1ea3a82e752b")
    sent_at = models.DateTimeField()

class verifiedDigits(models.Model):
    validator = RegexValidator(
        regex=r'^\d{12}$',
        message="Must be 12 digits i.e 254123456789",
        code="invalid number format"
    )
    digitsOwner = models.ForeignKey(supaProfile, on_delete=models.CASCADE)
    theDigits = models.CharField(max_length=12, validators=[validator], help_text="i.e 254123456789")
    validated = models.BooleanField(default=False)
    validate_at = models.DateTimeField()
