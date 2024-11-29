from django.contrib import admin
from django.urls import path
from chatapp import views
from .views import *

urlpatterns = [
    # path('admin/', admin.site.urls),
    path("", views.index, name = "home"),
    path('groq/', groq_api, name='groq_api'),
    path('signup/', signup, name='signup'),
    path('signin/', signin, name='signin'),
    
]

