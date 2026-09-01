from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from lnbits.core.models import User
from lnbits.decorators import check_user_exists
from lnbits.helpers import template_renderer

externalsigner_generic_router = APIRouter()


@externalsigner_generic_router.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    user: User = Depends(check_user_exists),
) -> HTMLResponse:
    return template_renderer(["externalsigner/templates"]).TemplateResponse(
        request,
        "externalsigner/index.html",
        {"user": user.json()},
    )
