import jwt
import requests
import hmac
import hashlib
import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import ClientError
from urllib.parse import quote_plus

load_dotenv()

# FastAPI app setup
app = FastAPI()

CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
USER_POOL_ID = os.environ.get("USER_POOL_ID")
REGION = os.environ.get("AWS_REGION")
SCOPE = os.environ.get("SCOPE").split(",")
print("SCOPE", SCOPE, type(SCOPE))

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key="secret")
# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cognito_client = boto3.client("cognito-idp", region_name=REGION)


def compute_secret_hash(user_id, client_id, client_secret):
    """Compute the Cognito secret hash."""
    message = f"{user_id}{client_id}".encode("utf-8")
    secret = client_secret.encode("utf-8")
    digest = hmac.new(secret, message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


# @app.on_event("startup")
# async def setup_user_pool_client():
#     try:
#         # Fetch existing client details
#         response = cognito_client.describe_user_pool_client(
#             UserPoolId=USER_POOL_ID, ClientId=CLIENT_ID
#         )
#         client = response["UserPoolClient"]
#         print("Existing User Pool Client details:", client)

#         # Check if the client needs updating
#         updated_client = cognito_client.update_user_pool_client(
#             UserPoolId=USER_POOL_ID,
#             ClientId=CLIENT_ID,
#             AllowedOAuthFlowsUserPoolClient=True,
#             AllowedOAuthScopes=SCOPE,
#             AllowedOAuthFlows=["code"],
#             SupportedIdentityProviders=["COGNITO"],
#             CallbackURLs=["http://localhost:8000/cognito/callback"],
#             LogoutURLs=["http://localhost:8000/logout"],  # Optional logout URL
#         )
#         print("User Pool Client updated successfully:", updated_client)
#     except ClientError as e:
#         print("Failed to retrieve or update User Pool Client:", e)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get("user")
    print(user)
    if user:
        return f'Hello, {user["attributes"]["given_name"]}. <a href="/logout">Logout</a>'
    else:
        return 'Welcome! Please <a href="/login">Login</a>.'


@app.get("/login")
async def login():
    # Generate the login URL
    redirect_uri = quote_plus("http://localhost:8000/cognito/callback")
    scopes = "+".join(SCOPE)
    login_url = f"https://eu-west-2p52dmw0az.auth.{REGION}.amazoncognito.com/login?client_id={CLIENT_ID}&response_type=code&scope={scopes}&redirect_uri={redirect_uri}"
    print("LOGIN URL", login_url)
    return RedirectResponse(url=login_url)


@app.get("/cognito/callback")
async def authorize(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")

    token_url = f"https://eu-west-2p52dmw0az.auth.{REGION}.amazoncognito.com/oauth2/token"
    redirect_uri = "http://localhost:8000/cognito/callback"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "code": code,
    }
    CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    response = requests.post(token_url, data=data, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to exchange code for tokens")

    tokens = response.json()
    access_token = tokens["access_token"]

    # Decode the access token
    decoded_token = jwt.decode(access_token, options={"verify_signature": False})
    print("Decoded Access Token:", decoded_token)

    print("Access Token:", access_token)
    print("Cognito client:", cognito_client)

    # Use the access token to fetch user info
    user_info = cognito_client.get_user(AccessToken=access_token)
    print("User Info:", user_info)
    user = {
        "username": user_info["Username"],
        "attributes": {attr["Name"]: attr["Value"] for attr in user_info["UserAttributes"]},
    }
    request.session["user"] = user

    return RedirectResponse(url="/")


@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/")
