import json
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView


@method_decorator(csrf_exempt, name='dispatch')
class serverStatus(APIView):

    def get(self, request):
        return Response({"info": "Server is working fine!!"}, status=status.HTTP_200_OK)


def error_404(request, exception):
    return render(request, 'error/404.html', {})


def error_500(request):
    return render(request, 'error/500.html', {})
