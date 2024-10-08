# Generated by Django 4.2 on 2023-10-20 12:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('loginapp', '0008_products'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_image', models.CharField(max_length=455)),
                ('username', models.CharField(max_length=255)),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=255)),
                ('phonecode', models.CharField(max_length=255)),
                ('phone', models.CharField(max_length=255)),
                ('profile_id', models.PositiveBigIntegerField()),
                ('client_admin_id', models.CharField(max_length=255)),
                ('policy_status', models.BooleanField()),
                ('user_type', models.CharField(max_length=255)),
                ('event_id', models.CharField(max_length=255)),
                ('payment_status', models.CharField(max_length=255)),
                ('safty_secruity_policy', models.CharField(max_length=255)),
                ('country', models.CharField(max_length=255)),
                ('newsletter_subscription', models.BooleanField(default=True)),
            ],
        ),
    ]
