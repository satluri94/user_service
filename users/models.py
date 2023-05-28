from django.db import models

# Create your models here.
from django.contrib.auth.models import User

class Role(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role_name  = models.CharField(max_length=50)
    
    
    def __str__(self):
        return self.role_name