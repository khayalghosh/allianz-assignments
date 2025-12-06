import msal
import os

TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
API_CLIENT_ID = os.getenv("API_CLIENT_ID")  # the API app's client id

print("Generating token for client:", CLIENT_ID)
print("Using API client id (for scopes):", API_CLIENT_ID)
print("Tenant ID:", TENANT_ID)
print("Client Secret is set:", CLIENT_SECRET is not None)

authority = f"https://login.microsoftonline.com/{TENANT_ID}"
app = msal.ConfidentialClientApplication(CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET)

scopes = [f"api://{API_CLIENT_ID}/.default"]  # for client credentials
result = app.acquire_token_for_client(scopes=scopes)

if "access_token" in result:
    token = result["access_token"]
    print("Bearer", token)
else:
    print("Error acquiring token:", result.get("error"), result.get("error_description"))
