# Импортируем необходимые библиотеки
import boto3
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout
from .forms import UserRegistrationForm, UserLoginForm, ManagerLoginForm, EditProfileForm
from accounts.models import User

# Настройка клиента Cognito
cognito_client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)

def authenticate_cognito_user(email, password):
    """Функция для аутентификации через AWS Cognito"""
    try:
        response = cognito_client.initiate_auth(
            ClientId=settings.AWS_COGNITO_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            }
        )
        return response['AuthenticationResult']
    except cognito_client.exceptions.NotAuthorizedException:
        return None
    except Exception as e:
        return None


def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            email = data['email']
            password = data['password']

            # Проверяем пользователя через Cognito
            auth_response = authenticate_cognito_user(email, password)
            if auth_response:
                # Вход успешен, создаем или находим пользователя в базе
                user, created = User.objects.get_or_create(email=email)
                login(request, user)
                return redirect('shop:home_page')
            else:
                messages.error(request, 'Invalid username or password', 'danger')
                return redirect('accounts:user_login')
    else:
        form = UserLoginForm()

    context = {'title': 'Login', 'form': form}
    return render(request, 'login.html', context)


def user_register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            # Регистрация через Cognito
            try:
                cognito_client.sign_up(
                    ClientId=settings.AWS_COGNITO_APP_CLIENT_ID,
                    Username=data['email'],
                    Password=data['password'],
                    UserAttributes=[
                        {'Name': 'name', 'Value': data['full_name']},
                        {'Name': 'email', 'Value': data['email']}
                    ]
                )
                return redirect('accounts:user_login')
            except cognito_client.exceptions.UsernameExistsException:
                messages.error(request, 'User with this email already exists', 'danger')
                return redirect('accounts:user_register')
    else:
        form = UserRegistrationForm()

    context = {'title': 'Signup', 'form': form}
    return render(request, 'register.html', context)
