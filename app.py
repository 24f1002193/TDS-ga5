from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import re
import shlex
from urllib.parse import urlparse
from pathlib import Path
from fastapi import HTTPException

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

class GuardrailRequest(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


FORBIDDEN = "/home/agent/.pgpass"
OUTBOX = "/data/agent/outbox"
ALLOWED_HOSTS = {"huggingface.co", "api.github.com"}


def normalize_path(path: str):
    path = os.path.expanduser(path)
    path = path.replace("$HOME", "/home/agent")
    path = os.path.abspath(path)
    return path


@app.post("/guardrail")
def guardrail(req: GuardrailRequest):

    if req.tool == "bash":

        cmd = req.command or ""

        if ".pgpass" in cmd:
            return {
                "decision":"block",
                "reason":"restricted file"
            }

        return {
            "decision":"allow",
            "reason":"ok"
        }

    elif req.tool == "write_file":

        p = normalize_path(req.path)

        if not p.startswith(OUTBOX):
            return {
                "decision":"block",
                "reason":"outside outbox"
            }

        return {
            "decision":"allow",
            "reason":"ok"
        }

    elif req.tool == "http_request":

        host = urlparse(req.url).hostname

        if host not in ALLOWED_HOSTS:
            return {
                "decision":"block",
                "reason":"host not allowed"
            }

        return {
            "decision":"allow",
            "reason":"ok"
        }

    raise HTTPException(400)

class ScanRequest(BaseModel):
    skill: str

@app.post("/scanner")
def scanner(req: ScanRequest):

    txt = req.skill.lower()

    categories=[]

    if "sk-" in txt or "api_key" in txt or "webhook" in txt:
        categories.append("hardcoded_secret")

    if "ignore previous" in txt \
        or "ignore user" in txt \
        or "exfiltrate" in txt:
        categories.append("prompt_injection")

    if "filesystem:*" in txt \
        or "network:*" in txt \
        or "all domains" in txt:
        categories.append("excessive_permissions")

    if "author:" not in txt \
        or "version:" not in txt \
        or "changelog:" not in txt:
        categories.append("unclear_provenance")

    return {
        "categories":categories
    }

import json
class Step(BaseModel):
    step_number:int
    tool:str
    args:dict
    tokens_used:int


class BudgetRequest(BaseModel):
    budget_tokens:int
    steps:list[Step]

def canonical(obj):

    if isinstance(obj,dict):

        obj={
            k:canonical(v)
            for k,v in obj.items()
            if k!="request_id"
        }

        return obj

    if isinstance(obj,list):
        return [canonical(i) for i in obj]

    if isinstance(obj,str):
        return " ".join(obj.split())

    return obj

@app.post("/check")
def check(req:BudgetRequest):

    used=sum(i.tokens_used for i in req.steps)

    if used>=req.budget_tokens:
        return {
            "decision":"halt",
            "reason":"budget exceeded"
        }

    s=req.steps

    if len(s)>=3:

        a=s[-1]
        b=s[-2]
        c=s[-3]

        if (
            a.tool==b.tool==c.tool and
            canonical(a.args)==canonical(b.args)==canonical(c.args)
        ):
            return {
                "decision":"halt",
                "reason":"loop detected"
            }

    if len(s)>=6:

        last=s[-6:]

        if (
            last[0].tool==last[2].tool==last[4].tool and
            last[1].tool==last[3].tool==last[5].tool and
            canonical(last[0].args)==canonical(last[2].args)==canonical(last[4].args) and
            canonical(last[1].args)==canonical(last[3].args)==canonical(last[5].args)
        ):
            return {
                "decision":"halt",
                "reason":"2-step loop"
            }

    return {
        "decision":"continue",
        "reason":"ok"
    }
