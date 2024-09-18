from django.contrib.auth.forms import UserCreationForm

class AccountAdminCreationForm(UserCreationForm):
  def save(self, commit=True):
    user = super().save(commit=False)
    user.profile_id = 1
    user.client_admin_id = "1"
    if commit:
      user.save()
    return user