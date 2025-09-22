#
# 2nd tiny test to pass CI, just ensures package installs and models import OK.
#
def test_models_import():
    from app.db.base import Base  # noqa: F401
    from app.models.user import User  # noqa: F401
    assert True