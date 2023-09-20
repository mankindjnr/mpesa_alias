from django import forms
from django.contrib import messages

def validate_number_length(value):
    if not value.isdigit() or len(value) < 10:
        raise forms.ValidationError("enter numbers only and must 10 or more")

class aliasCreationForm(forms.Form):
    original_num = forms.CharField(label="original number", required=True)
    desired_alias = forms.CharField(label="desired alias", required=True)