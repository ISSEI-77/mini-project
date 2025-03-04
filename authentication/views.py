from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout  
from design import settings
from django.core.mail import send_mail, EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from .tokens import generate_token  

# Home View
def home(request):
    return render(request, "authentication/home.html")

# Signup View
def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        # Username & Email Checks
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists. Please try another one.")
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered!")
            return redirect('signup')

        if len(username) > 10:
            messages.error(request, "Username must be under 10 characters.")
            return redirect('signup')

        if pass1 != pass2:
            messages.error(request, "Passwords do not match!")
            return redirect('signup')

        myuser = User.objects.create_user(username=username, email=email, password=pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False  # User will be inactive until email is verified
        myuser.save()

        messages.success(request, "Your account has been created! Please verify your email to activate your account.")

        # Welcome Email
        subject = "Welcome to Design Django Login"
        message = f"Hello {myuser.first_name}!!\n\n" \
                  f"Welcome to Design!!\nThank you for visiting our website.\n" \
                  f"We have also sent you a confirmation email. Please confirm your email address to activate your account.\n\n" \
                  f"Thank You"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Email Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm Your Email - Design Django Login"
        message2 = render_to_string('authentication/email_confirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        })
        email = EmailMessage(email_subject, message2, from_email, [myuser.email])
        email.fail_silently = True
        email.send()

        return redirect('signin')

    return render(request, "authentication/signup.html")

# Signin View
def signin(request):
    if request.method == "POST":
        username = request.POST.get('username')
        pass1 = request.POST.get('pass1')

        user = authenticate(username=username, password=pass1)

        if user is not None:
            if user.is_active:
                login(request, user)
                fname = user.first_name
                messages.success(request, "Successfully signed in!")
                return redirect('home')
            else:
                messages.error(request, "Your account is not activated. Please check your email for activation link.")
                return redirect('signin')
        else:
            messages.error(request, "Invalid username or password.")
            return redirect('signin')

    return render(request, "authentication/signin.html")

# Signout View
def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('home')

# Email Activation View
def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        messages.success(request, "Your account has been activated!")
        return redirect('home')
    else:
        return render(request, 'authentication/activation_invalid.html')
