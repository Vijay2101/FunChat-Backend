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
    path('add_bot/', add_bot, name='add_bot'),
    path('get_all_bots/', get_all_bots, name='get_all_bots'),
    path('get_bot_by_id/', get_bot_by_id, name='get_bot_by_id'),
    
]

