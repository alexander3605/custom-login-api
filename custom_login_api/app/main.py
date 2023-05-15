from custom_login_api.app.config import load_config
from custom_login_api.app.custom_login_api import CustomLoginAPI

app = CustomLoginAPI.from_config(config=load_config())
app.add_api_endpoints()
