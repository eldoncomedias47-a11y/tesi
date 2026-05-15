from fastapi import FastAPI, Body
from datetime import datetime
from logic import evaluar_modelo_heuristico

app = FastAPI(title="Middleware Heurístico Suricata")

def transformar_eve_a_modelo(eve_raw: dict):
    try:
        ts_str = eve_raw.get("timestamp", "")
        ts_clean = ts_str.split('+')[0]
        dt = datetime.fromisoformat(ts_clean)
        
        src_ip = eve_raw.get("src_ip", "0.0.0.0")
        dest_ip = eve_raw.get("dest_ip", "0.0.0.0")
        src_octs = [int(o) for o in src_ip.split('.')]
        dest_octs = [int(o) for o in dest_ip.split('.')]

        return {
            "severity": eve_raw.get("alert", {}).get("severity", 3),
            "src_oct1": src_octs[0],
            "src_oct2": src_octs[1],
            "dest_oct1": dest_octs[0],
            "dest_oct2": dest_octs[1],
            "dest_port": eve_raw.get("dest_port", 0),
            "hour": dt.hour
        }
    except Exception as e:
        return None

@app.post("/evaluar")
async def endpoint_evaluacion(payload: dict = Body(...)):
    datos_limpios = transformar_eve_a_modelo(payload)
    if not datos_limpios:
        return {"error": "Formato de log inválido"}
    resultado_criticidad = evaluar_modelo_heuristico(datos_limpios)
    return {"nivel_criticidad": resultado_criticidad}