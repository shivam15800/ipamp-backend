import os
from app import create_app
from app.config import SecureConfig, VulnConfig

mode = os.getenv("APP_MODE", "secure")

config_map = {
    "secure": SecureConfig,
    "vuln" : VulnConfig,
}

app = create_app(config_map.get(mode, SecureConfig))

if __name__ == "__main__":
    app.run(debug=True)