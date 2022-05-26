from django.shortcuts import redirect, render
from .models import User
from django.urls import reverse
from django.contrib.auth import authenticate,login,logout,get_user_model
from django.contrib import messages
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeErr
from django.contrib.sites.shortcuts import get_current_site
from .utils import token_gen
User=get_user_model()


def  LoginView(request):

    if request.method=="POST":
        username=request.POST.get('username')
        password=request.POST.get('password')
        if username == "":
            messages.error(request, "Username required")
        if password == "":
            messages.error(request, "Password is required")
        user=authenticate(username=username,password=password)
        if user is not None:
            login(request,user)
            return render(request,'accounts/home.html')
        else:
            return render(request,'accounts/login.html',{'error':'Invalid Credentials'})
    return render(request,'accounts/login.html')
    

def LogoutView(request):
    logout(request)
    messages.success(request, "Logged out successfully")
    return render(request,'accounts/login.html')


def RegisterView(request):
    if request.method=="POST":
        username=request.POST.get('username')
        password1=request.POST.get('password')
        password2=request.POST.get('password2')
        email=request.POST.get('email')
        phone_no=request.POST.get('phone_no')
        if username == "":
            messages.error(request, "Username required")
        if password1 == "":
            messages.error(request, "Password is required")
        if password2 == "":
            messages.error(request, "Password is required")
        if email == "":
            messages.error(request, "Email is required")
        if phone_no == "":
            messages.error(request, "Phone number is required")
            return redirect ('accounts:register')
        if  User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
        if User.objects.filter(phone_no=phone_no).exists():
            messages.error(request, "Phone number already exists")
        if password1 != password2:
            messages.error(request, "Passwords do not match")
            if len(password1)<6:
                messages.error(request, "Password must be atleast 6 characters")
                return redirect ('accounts:register')
        else:
            user=User.objects.create_user(username=username,
            password=password1,email=email,phone_no=phone_no)
            user.set_password(password1)
            user.save()
            user.is_active=False

            uidb64=urlsafe_base64_encode(force_bytes(user.pk))
            domain=get_current_site(request).domain
            link=reverse('accounts:activate',kwargs={
                'uidb64':uidb64,
                'token':token_gen
                })
            activate_url= f"http://{domain}{link}"
            mail_subject='Activate your account'
            """
            message = render_to_string('auth/activate.html', {
                'user':user,
                'domain':domain,
                'uidb64':uidb64,
                'token':token_gen.make_token(user)
            })
            """

            mail_body=f"hi {user.username} click the link below to verify your account\n {activate_url}"
            send_mail (mail_subject, mail_body,'noreply@sellit.com',[email], fail_silently=False)
            messages.success(request, "Account created, Check your email to activate your account")
            return redirect('accounts:login')

    return render(request,'accounts/register.html')
#varification of your email account

def  VarificationView(request, uidb64,token):
    try:
        uid=force_str(urlsafe_base64_decode(uidb64))
        user=User.objects.get(pk=uid)
    except(TypeError,ValueError,OverflowError,User.DoesNotExist):
        user=None
    if user is not None and token_gen.check_token(user,token):
        user.is_active=True
        user.save()
        messages.success(request, "Account activated successfully")
        return redirect('accounts:login')
    else:
        return render(request,'accounts/activate.html',{'error':'Invalid activation link'})
#forgot password view
def ForgotPasswordView(request):
    if request.method=="POST":
        email=request.POST.get('email')
        if email == "":
            messages.error(request, "Email is required")
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uidb64=urlsafe_base64_encode(force_bytes(user.pk))
            domain=get_current_site(request).domain
            link=reverse('accounts:reset_password',kwargs={
                'uidb64':uidb64,
                'token':token_gen
                })
            reset_url= f"http://{domain}{link}"
            mail_subject='Reset your password'
            mail_body=f"hi {user.username} click the link below to reset your password\n {reset_url}"
            send_mail (mail_subject, mail_body,'noreply@sellit.com',[email], fail_silently=False)
            messages.success(request, "Check your email to reset your password")
            return redirect('accounts:login')
        else:
            messages.error(request, "Email does not exist")
            return redirect('accounts:forgot_password')
    return render(request,'accounts/forgot_password.html')
#reset password view
def ResetPasswordView(request,uidb64,token):
    try:
        uid=force_str(urlsafe_base64_decode(uidb64))
        user=User.objects.get(pk=uid)
    except(TypeError,ValueError,OverflowError,User.DoesNotExist):
        user=None
    if user is not None and token_gen.check_token(user,token):
        if request.method=="POST":
            password1=request.POST.get('password1')
            password2=request.POST.get('password2')
            if password1 == "":
                messages.error(request, "Password is required")
            if password2 == "":
                messages.error(request, "Password is required")
            if password1 != password2:
                messages.error(request, "Passwords do not match")
                if len(password1)<6:
                    messages.error(request, "Password must be atleast 6 characters")
                    return redirect ('accounts:reset_password',uidb64,token)
            else:
                user_id = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=user_id)
                user.set_password(password1)
                user.save()
                messages.success(request, "Password reset successfully")
                return redirect('accounts:login')
    else:
        return render(request,'accounts/reset_password.html',{'error':'Invalid reset link'})
    return render(request,'accounts/reset_password.html')
    
