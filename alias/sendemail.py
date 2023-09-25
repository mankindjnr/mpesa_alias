from django.core.mail import send_mail

send_mail(
    'Received Money',#subject
    'You have received cash, click here to login and view transactions',#message
    'aliasmpesa@gmail.com', #from email
    ['amosandmovies@gmail.com']# to email
)