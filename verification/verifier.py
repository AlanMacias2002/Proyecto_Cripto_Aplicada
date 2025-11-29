from __future__ import annotations
from typing import Dict, Optional
import json
import hashlib
from blockchain.blockchain_client import BlockchainClient


def _canonical_json(obj: Dict) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_expected_log(operative_row: Dict, admin_row: Optional[Dict]) -> Dict:
    """
    Reconstruye el JSON que se envió on-chain a partir de los datos locales.
    Estructura esperada según core/logger.construir_log:
    {
      "hash_entidad": ...,            # de operativa
      "evento": ...,                  # de operativa
      "fecha_evento": ...,            # operativa.fecha
      "timestamp_hash": ...,          # admin.timestamp
      "detalles": ...                 # de operativa
    }
    """
    expected = {
        "hash_entidad": operative_row.get("hash_entidad"),
        "evento": operative_row.get("evento"),
        "fecha_evento": operative_row.get("fecha"),
        "timestamp_hash": admin_row.get("timestamp") if admin_row else None,
        "detalles": operative_row.get("detalles"),
    }
    return expected


def verify_tx_matches_expected(tx_hash: str, expected_log: Dict) -> Dict:
    """
    Descarga la transacción, decodifica 'input' (data), lo compara con el JSON esperado.
    Devuelve un dict con ok, pruebas (digests) y diffs si aplica.
    """
    client = BlockchainClient()
    if not client.conectado():
        return {
            "ok": False,
            "reason": "Blockchain no conectada",
            "details": "Asegúrate de que Ganache esté activo y accesible.",
        }
    w3 = client.w3
    try:
       
        tx = w3.eth.get_transaction(tx_hash)  # type: ignore[arg-type]
    except Exception as e:
        return {"ok": False, "reason": "Transacción no encontrada", "details": str(e)}

    input_hex = tx.get("input")  # 'input' es el campo data hex (HexBytes)
    try:
        hex_str: Optional[str]
        if input_hex is None:
            hex_str = None
        elif hasattr(input_hex, "hex"):
            # HexBytes -> '0x...'
            hex_str = input_hex.hex()  # type: ignore[assignment]
        else:
            hex_str = input_hex  # type: ignore[assignment]
        # Web3 v7: to_text accepts HexStr; our hex_str is a python str '0x...'
        onchain_text = w3.to_text(hexstr=hex_str)  # type: ignore[arg-type]
        onchain_json = json.loads(onchain_text)
    except Exception as e:
        return {"ok": False, "reason": "No se pudo decodificar el payload on-chain", "details": str(e)}

    # Canonicalizar para comparar establemente
    exp_text = _canonical_json(expected_log)
    on_text = _canonical_json(onchain_json)

    exp_digest = _sha256(exp_text)
    on_digest = _sha256(on_text)

    ok = (exp_text == on_text)
    result = {
        "ok": ok,
        "tx_hash": tx_hash,
        "expected_digest": exp_digest,
        "onchain_digest": on_digest,
        "expected_json": expected_log,
        "onchain_json": onchain_json,
    }
    if ok:
        result["message"] = "Verificación exitosa: el JSON local coincide exactamente con el almacenado on-chain."
        result["proofs"] = {
            "sha256(expected_json)": exp_digest,
            "sha256(onchain_json)": on_digest,
            "equality": exp_digest == on_digest,
        }
    else:
        # Señalar diferencias simples por claves
        diffs = {}
        for k in set(list(expected_log.keys()) + list(onchain_json.keys())):
            if expected_log.get(k) != onchain_json.get(k):
                diffs[k] = {"expected": expected_log.get(k), "onchain": onchain_json.get(k)}
        result["message"] = "Verificación fallida: el JSON local difiere del on-chain."
        result["diffs"] = diffs
        result["proofs"] = {
            "sha256(expected_json)": exp_digest,
            "sha256(onchain_json)": on_digest,
            "equality": exp_digest == on_digest,
        }
    return result
