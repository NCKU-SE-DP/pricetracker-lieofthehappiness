from fastapi import Query
import requests
from .constants import PRICES_URL
@app.get("/api/v1/prices/necessities-price")
def get_necessities_prices(
        category=Query(None), commodity=Query(None)
):
    return requests.get(
        PRICES_URL,
        params={"CategoryName": category, "Name": commodity},
    ).json()
