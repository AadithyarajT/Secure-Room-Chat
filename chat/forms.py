from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.contrib.auth.models import User
from .models import Profile

class RegisterForm(UserCreationForm):
    username = forms.CharField(label='Name', max_length=150)  # We use username as name

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']
        help_texts = {  # Keep it simple, no confusion
            'username': None,
            'password1': None,
            'password2': None,
        }


# Add these new forms
class ProfileEditForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ["avatar", "description"]
        widgets = {
            "description": forms.Textarea(
                attrs={
                    "rows": 4,
                    "placeholder": "Tell us about yourself...",
                    "class": "description-input",
                }
            ),
        }
        labels = {
            "avatar": "Choose Avatar",
            "description": "Bio/Description",
        }


class UserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["username"]
        labels = {
            "username": "Display Name",
        }
        help_texts = {
            "username": "This is how other users will see you.",
        }


class CustomPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove help text
        self.fields["old_password"].help_text = None
        self.fields["new_password1"].help_text = None
        self.fields["new_password2"].help_text = None
