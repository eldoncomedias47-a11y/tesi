# logic.py

def es_ip_privada(oct1: int, oct2: int) -> bool:
    """Aplica las reglas RFC 1918 para identificar redes internas."""
    if oct1 == 10: return True
    if oct1 == 172 and 16 <= oct2 <= 31: return True
    if oct1 == 192 and oct2 == 168: return True
    return False

def evaluar_modelo_heuristico(datos_preprocesados: dict):
    score = 0
    sev = datos_preprocesados.get('severity', 0)
    
    if sev == 1: score += 40
    elif sev == 2: score += 20
    elif sev == 3: score += 10
    
    if score == 0: return "Muy Bajo"

    src_priv = es_ip_privada(datos_preprocesados['src_oct1'], datos_preprocesados['src_oct2'])
    dest_priv = es_ip_privada(datos_preprocesados['dest_oct1'], datos_preprocesados['dest_oct2'])
    
    if not src_priv and dest_priv: score += 25
    elif src_priv and dest_priv: score += 15
    
    if datos_preprocesados.get('dest_port', 0) < 1024: score += 15
    
    if 0 <= datos_preprocesados.get('hour', -1) <= 5: score += 10
    
    if score >= 70: return "Critico"
    elif score >= 50: return "Alto"
    elif score >= 30: return "Medio"
    return "Bajo"