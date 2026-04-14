from __future__ import annotations

from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    client_id: str = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    authority: str = "https://login.microsoftonline.com/common"
    graph_base_url: str = "https://graph.microsoft.com/beta"
    scopes: List[str] = [
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementServiceConfig.Read.All",
        "Group.Read.All",
        "GroupMember.Read.All",
        "Directory.Read.All",
        "Policy.Read.All",
    ]
    max_concurrent_requests: int = 4
    token_cache_file: str = ".token_cache.json"
    backend_port: int = 8099

    model_config = {"env_prefix": "INTUNE_"}


settings = Settings()
