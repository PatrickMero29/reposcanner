import asyncio
from vulnscan.local_model.inference import predict
from vulnscan.schemas import Language

VULNERABLE = '''import os
def run(x):
    os.system("ls " + x)
'''

SAFE = '''def add(a, b):
    return a + b
'''


async def main():
    for label, code in [("vulnerable", VULNERABLE), ("safe", SAFE)]:
        results = await predict(code=code, function_name="f", language=Language.PYTHON)
        conf = results[0].confidence if results else 0.0
        status = "flagged" if results else "not flagged"
        print(f"{label} -> {status} ({conf:.0%})")


asyncio.run(main())