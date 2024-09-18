from rest_framework import serializers
from loginapp.models import Account, CustomSession


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['id', 'username', 'email', 'phone', 'first_name', 'last_name',
                  'role', 'teamcode', 'password', 'phonecode', 'profile_image']
        extra_kwargs = {
            'password': {'write_only': True},
            'profile_image': {'required': False},
            'role': {'read_only': True},
            'id': {'read_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['id', 'username', 'email', 'phone', 'first_name', 'last_name',
                  'role', 'teamcode', 'phonecode', 'profile_image', 'datatype']
        extra_kwargs = {
            'id': {'read_only': True},
            'profile_image': {'required': False},
            'username': {'required': False},
            'email': {'required': False},
            'phone': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
            'team_code': {'required': False},
            'phonecode': {'required': False},
            'datatype': {'required': False},
        }


class CustomSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomSession
        fields = "__all__"
