from fastapi import Query
import requests
from .constants import PRICES_URL
from fastapi import APIRouter
router = APIRouter(
    prefix="/prices",
    tags=["prices"],
    responses={404: {"description": "Not found"}},
)
@router.get("/necessities-price")
def get_necessities_prices(
        category=Query(None), commodity=Query(None)
):
    """
    :param category: 商品類別
    :param commodity: 商品名稱
    :return: JSON 格式的商品價格資訊
    """
    return requests.get(
        PRICES_URL,
        params={"CategoryName": category, "Name": commodity},
    ).json()
