from __future__ import unicode_literals
from django.db import models
from mongoengine import *

# Create your models here.

class PacketsInfo(Document):
    recv_time = StringField()
    length = IntField()
    ether_dst = StringField()
    ether_src = StringField()
    ip_dst = StringField()
    ip_src = StringField()
    port_dst = IntField()
    port_src = IntField()    
    fourthlayer_type = StringField()
    meta = {'collection':'packets'}
