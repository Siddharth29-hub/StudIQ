from typing import Optional, Tuple
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from .models import CustomUser

class CookieJWTAuthentication(JWTAuthentication):

    def authenticate(self, request) -> Optional[Tuple[CustomUser, UntypedToken]]:
        raw_token = request.COOKIES.get("access")
        if not raw_token:
            return None
        try:
            validated_token = self.get_validated_token(raw_token)

        except InvalidToken:
            return None
        
        user = self.get_user_from_token(validated_token)
        if user is None:
            return (AnonymousUser(), None)
        
        try:
            setattr(user, "is_authenticated", True)

        except Exception:
            pass

        return (user, validated_token)
    

    def get_user_from_token(self, validated_token) -> Optional[CustomUser]:
        user_id = validated_token.get("user_id", None)
        if user_id is None:
            return None
        
        try:
            user = CustomUser.objects.get(id = user_id)
            return user
        except CustomUser.DoesNotExist:
            return None



    
