# azure_client.py
import os
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient

TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP = os.getenv("AZURE_RESOURCE_GROUP")
LOCATION = os.getenv("AZURE_LOCATION", "eastus")

def get_network_client():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, SUBSCRIPTION_ID]):
        raise Exception("Missing Azure credential environment variables.")
    cred = ClientSecretCredential(tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    network_client = NetworkManagementClient(credential=cred, subscription_id=SUBSCRIPTION_ID)
    return network_client

def create_vnet_with_subnets(vnet_name: str, address_prefixes: list, subnets: list, location: str = None):
    """
    vnet_name: str
    address_prefixes: list of cidr strings e.g. ["10.0.0.0/16"]
    subnets: list of dicts: [{"name": "subnet1", "address_prefix":"10.0.1.0/24"}, ...]
    """
    network_client = get_network_client()
    loc = location or LOCATION
    vnet_params = {
        "location": loc,
        "address_space": {"address_prefixes": address_prefixes},
        "subnets": [{"name": s["name"], "address_prefix": s["address_prefix"]} for s in subnets]
    }

    # This is a long-running operation - use begin_create_or_update
    poller = network_client.virtual_networks.begin_create_or_update(
        RESOURCE_GROUP, vnet_name, vnet_params
    )
    result = poller.result()  # wait for completion
    # result is a VirtualNetwork model. Convert to dict for storage.
    result_dict = result.as_dict() if hasattr(result, "as_dict") else {}
    return result_dict
