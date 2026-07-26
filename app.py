from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class ChargeRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: str

@app.post("/charge")
def calculate_charge(req: ChargeRequest):
    diff = req.new_price - req.old_price

    if req.spec == "v1":
        charge = diff * (req.days_remaining / 30)

    elif req.spec == "v2":
        charge = diff * (
            req.days_remaining / req.days_in_actual_month
        )

    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid spec"
        )

    return {"charge": charge}
