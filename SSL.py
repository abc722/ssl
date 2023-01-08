from fastapi import FastAPI
import ssl
import uvicorn
from cryptography import x509
from pydantic import BaseModel

class URL(BaseModel):
    Url:str

app = FastAPI()

@app.post("/certificate")
def certificate(data:URL):

    try:
        cert = ssl.get_server_certificate((data.Url, 443))
        certDecoded = x509.load_pem_x509_certificate(str.encode(cert))

        extension_list = []
        for line in certDecoded.extensions._extensions:
            value = line.value.dict
            for raw in line.value.dict.values():
                if str(raw)[:2] == "b'" or str(raw)[:2] == 'b"':
                    value = ""
                if "<builtins" in str(raw):
                    value = ""
            extension = {
                line._oid._name : line._oid.dotted_string,
                'critical' : line._critical,
                'value' : value
                }
            extension_list.append(extension)

        result = {
        'issuer' : str(certDecoded.issuer)[6:-2],
        'subject' : str(certDecoded.subject)[6:-2],
        'after' : certDecoded.not_valid_after,
        'before' : certDecoded.not_valid_before,
        'extensions': extension_list,
        'seri_no' : certDecoded.serial_number,
        'version' : certDecoded.version.value
        }
        print(result)

    except Exception as e:
        print(data.Url, ":", e)
        return {"Status": "Error", "Message":f"{e}" ,"Content": ""}

    return {"Status": "Success", "Message":"" ,"Content": result}

    certificate

if __name__ == "main":
    uvicorn.run(app, host="0.0.0.0", port=52890)
