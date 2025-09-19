import jwt
from django.http import JsonResponse
from django.conf import settings
from .models import CustomUser
from django.contrib.auth.models import AnonymousUser

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth_header = request.headers.get("Authorization")
        print("Incoming Authorization Header:", auth_header)

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms = ["HS256"])
                print("Decoded Payload:", payload)
                user = CustomUser.objects.get(id=payload["user_id"])
                print("Authenticated User:", user.username, user.mobile, user.role)

                
                request.user = user
                request.jwt_payload = payload
            
            except jwt.ExpiredSignatureError:
                print("JWT ERROR : Token Expired")
                return JsonResponse({"Error" : "token Expired"}, status = 401)
            
            except jwt.InvalidTokenError as e:
                print("JWT ERROR : Invalid Token", str(e))
                return JsonResponse({"Error" : "Invalid Token"}, status = 401)
            
            except CustomUser.DoesNotExist:
                print("JWT ERROR : User not found in DB")
                return JsonResponse({"Error" : "User not found"}, status = 401)
            
            except Exception as e:
                print("Unexpected Error:", str(e))
                return JsonResponse({"error" : str(e)}, status = 500)
            
        else:
            if isinstance(request.user, AnonymousUser):
                request.jwt_payload = None
        
        return self.get_response(request)
