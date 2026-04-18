def test_sync_decorator_allows():
    from py_authz.core.types import Identity
    from py_authz.modeling import Relation, ResourceModel
    from py_authz.modeling.decorators import require

    class Doc(ResourceModel):
        type = "document"
        view = Relation("viewer")

    class MockAuthz:
        async def can(self, *args, **kwargs):
            return True

    authz = MockAuthz()

    @require(
        authz,
        Doc.view,
        user_getter=lambda u, d: u,
        resource_getter=lambda u, d: d,
    )
    def handler(user, doc):
        return "ok"

    result = handler(Identity(id="user:1"), Doc("1"))

    assert result == "ok"
