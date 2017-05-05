from django.conf.urls import url
from . import views


urlpatterns = [

    url(r'^$',views.index, name='index'),
    url(r'^dt/',views.detect_ddos, name='detect_ddos'),
]