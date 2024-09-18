from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser, AbstractBaseUser, BaseUserManager
from django.utils.crypto import get_random_string
from ndarray import NDArrayField


def get_profile_image_path(self, filename):
    return f'profile_images/{filename}'


def get_default_profile_image():
    return 'profile_images/user.png'


class GuestAccount(models.Model):
    username = models.CharField(max_length=20, unique=False)
    email = models.CharField(max_length=30, unique=False)
    is_activated = models.BooleanField(default=False)
    otp = models.IntegerField(null=True)
    token = models.CharField(max_length=300, null=True)
    expiry = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.username

    class Meta:
        db_table = "GuestAccount"


class mobile_sms(models.Model):
    username = models.CharField(max_length=20, default="user")
    phone = models.CharField(max_length=15, unique=True)
    sms = models.IntegerField(null=True)
    expiry = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.username


class CustomSession(models.Model):
    sessionID = models.CharField(max_length=2000)
    info = models.TextField()
    document = models.TextField()
    status = models.CharField(max_length=50, null=True, blank=True)


class RandomSession(models.Model):
    sessionID = models.CharField(max_length=2000)
    username = models.CharField(max_length=2000)
    status = models.CharField(max_length=50, null=True, blank=True)
    added = models.DateTimeField(default=timezone.now)


class QR_Creation(models.Model):
    info = models.TextField(null=True)
    qrid = models.CharField(max_length=2000)
    password = models.CharField(max_length=2000)
    status = models.CharField(max_length=50, null=True, blank=True)


class LiveStatus(models.Model):
    sessionID = models.CharField(max_length=2000)
    username = models.CharField(max_length=2000)
    product = models.CharField(max_length=100)
    status = models.CharField(max_length=50, null=True, blank=True)
    date_created = models.CharField(max_length=1000)
    date_updated = models.CharField(max_length=1000, null=True, blank=True)
    updated = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(null=True, blank=True)


class Live_QR_Status(models.Model):
    qrid = models.CharField(max_length=2000)
    product = models.CharField(max_length=100)
    status = models.CharField(max_length=50, null=True, blank=True)
    updated = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(null=True, blank=True)


class Live_Public_Status(models.Model):
    unique_key = models.CharField(max_length=2000)
    product = models.CharField(max_length=100)
    status = models.CharField(max_length=50, null=True, blank=True)
    updated = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(null=True, blank=True)


class Linkbased_RandomSession(models.Model):
    sessionID = models.CharField(max_length=1000)
    info = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status=models.CharField(max_length=100)


class Location_check(models.Model):
    username = models.CharField(max_length=1000, unique=False)
    usual = models.TextField()
    unusual = models.TextField(null=True, blank=True)


class products(models.Model):
    product = models.CharField(max_length=1000, unique=True)
    url = models.CharField(max_length=1000, blank=True)
    ip = models.CharField(max_length=1000, blank=True)
    status = models.CharField(max_length=100, default="active")


class Face_Login(models.Model):
    username = models.CharField(max_length=20, unique=True)
    image = NDArrayField()


class UserManager(BaseUserManager):
    def create_user(self, username, password=None):
        user = self.model(username=username)
        user.set_password(password)
        user.profile_id = 1
        user.client_admin_id = "1"
        user.save(using=self._db)
        return user

    def create_staffuser(self, username, password):
        user = self.create_user(username, password=password)
        user.is_staff = True
        user.save(using=self._db)

    def create_superuser(self, username, password):
        user = self.create_user(username, password=password)
        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)


class Account(AbstractUser):

    profile_image = models.ImageField(null=True, blank=True)
    username = models.CharField(
        max_length=255, unique="True", db_collation='utf8_bin')
    email = models.EmailField(default="default@example.com")
    password = models.CharField(max_length=255)
    phonecode = models.CharField(max_length=255, null=True, blank=True)
    phone = models.CharField(max_length=255, null=True, blank=True)
    profile_id = models.PositiveBigIntegerField(null=True, blank=True)
    client_admin_id = models.CharField(max_length=255, null=True, blank=True)
    policy_status = models.CharField(
        default="Accepted", max_length=255, null=True, blank=True)
    user_type = models.CharField(max_length=255, null=True, blank=True)
    eventid = models.CharField(max_length=255, null=True, blank=True)
    payment_status = models.CharField(max_length=255, default="unpaid")
    safety_secruity_policy = models.CharField(
        max_length=255, null=True, blank=True)
    user_country = models.CharField(max_length=255, null=True, blank=True)
    newsletter_subscription = models.CharField(
        default="Accepted", max_length=255, null=True, blank=True)
    current_task=models.CharField(max_length=100,default="")

    def __str__(self) -> str:
        return self.username
