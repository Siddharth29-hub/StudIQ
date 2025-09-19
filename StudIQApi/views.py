from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import SignupSerializer,VerifyOtpSerializer,LoginSerializer,VerifyLoginOtpSerializer
from rest_framework_simplejwt.tokens import RefreshToken
import random
from .serializers import CompleteProfileSerializer,OTPTable
from .models import CustomUser
from .models import OTPTable
from .utils import create_jwt_token










# Create your views here.

@api_view(['POST'])
def signup(request):
    serializer = SignupSerializer(data = request.data)
    if serializer.is_valid():
        user, otp = serializer.save()
        OTPTable.objects.create(
            user_id = user.id,
            mobile = user.mobile,
            otp = otp

        )
        return Response({"message" : "Signup Successfull Otp sent to your mobile", "user_id" : user.id, "mobile" : user.mobile, "otp" : otp}, status = status.HTTP_201_CREATED)
    return Response(serializer.error, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def verify_otp(request):
    serializer = VerifyOtpSerializer(data = request.data)
    
    if serializer.is_valid():
        return Response({"Message" :"otp verified successfully, you can now log in"}, status = status.HTTP_200_OK)
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


def set_tokens_as_cookies(response, user):
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    response.set_cookie(
        key = "access",
        value = access_token,
        httponly = True,
        secure = False,
        samesite = "Strict",

    )

    response.set_cookie(
        key = "refresh",
        value = refresh_token,
        httponly = True,
        secure = False,
        samesite = "Strict",

    )

    return response


@api_view(['POST'])
def login(request):
    serializer = LoginSerializer(data = request.data)
    if serializer.is_valid():
        user = serializer.validated_data["user"]
        otp = str(random.randint(100000,999999))
        OTPTable.objects.create(
            user_id = user.id,
            mobile = user.mobile,
            otp = otp
        )

        print("Login OTP:", otp)

        return Response({"Message" : "Otp sent to your mobile"}, status = status.HTTP_200_OK)
    
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def verify_login_otp(request):
    serializer = VerifyLoginOtpSerializer(data = request.data)
    if serializer.is_valid():
        user = serializer.validated_data["user"]
        token = create_jwt_token(user)

        return Response({"Message" : "Login Successful", "token" : token}, status = 200)
    
    return Response(serializer.errors, status = 400)

@api_view(['GET','PUT'])
def get_complete_profile_view_byid(request, user_id):
    try:
        user = CustomUser.objects.get(id = user_id)
    except CustomUser.DoesNotExist:
        return Response({"Error" : "User Not found"}, status = status.HTTP_404_NOT_FOUND)
    
    if request.user.id != user.id:
        return Response({"Error": "You are not allowed to access this profile"}, status=status.HTTP_403_FORBIDDEN)
    

    if request.method == "GET":
        serializer = CompleteProfileSerializer(user)
        return Response(serializer.data, status = status.HTTP_200_OK)
    
    elif request.method == "PUT":
        serializer = CompleteProfileSerializer(user, data = request.data, partial = True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status = status.HTTP_200_OK)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
def get_profile(request):
    if not request.user or not hasattr(request.user, "id"):
        return Response({"error" : "Authentication Required"}, status = 401)
    
    user = request.user
    return Response({
        "id" : user.id,
        "username" : user.username,
        "mobile" : user.mobile,
        "email" : user.email,
        "role" : user.role

    }, status = 200)



    
    
     


        
    
    







    


    










    