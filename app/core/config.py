from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KEYWARDEN_",
        extra="ignore",
    )

    PROJECT_NAME: str = "Keywarden"
    API_V1_STR: str = "/api/v1"

    # Postgres split vars (with defaults)
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_HOST: str = "keywarden-db"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "keywarden"

    SECRET_KEY: str = "insecure-dev-secret"  # default for local dev only
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    OIDC_ENABLED: bool = False
    OIDC_ISSUER: str | None = None
    OIDC_CLIENT_ID: str | None = None
    OIDC_AUDIENCE: str | None = None   # optional
    OIDC_JWKS_URL: str | None = None   # if not set, derive from issuer

    @computed_field(return_type=str)
    @property
    def POSTGRES_DSN(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


settings = Settings()