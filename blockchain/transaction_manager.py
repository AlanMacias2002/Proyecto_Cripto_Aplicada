from typing import Dict, cast
from web3 import Web3
import json
from web3.types import TxParams

def enviar_evento_a_blockchain(client, log: Dict) -> str:
    """
    Envía el evento a la blockchain local (Ganache) como una transacción
    cuyo campo 'data' contiene la representación del log.
    Devuelve el hash de transacción hex-string.
    """
    if not client.conectado():
        raise ConnectionError("Blockchain client no conectado. Asegúrate de tener Ganache corriendo en la URL configurada.")

    w3: Web3 = client.w3
    cuenta = client.obtener_cuenta_predeterminada()
    if not cuenta:
        raise RuntimeError("No se encontró cuenta en el nodo. Revisa Ganache.")
    cuenta = w3.to_checksum_address(cuenta)

   
    payload_text = json.dumps(log, separators=(",", ":"), ensure_ascii=False)
   
    data_hex = w3.to_hex(text=payload_text)

    
    nonce = w3.eth.get_transaction_count(cuenta)
    latest_block = w3.eth.get_block("latest")
    base_fee = latest_block.get("baseFeePerGas") if latest_block else None

    tx_common = {
        "from": cuenta,
        "to": cuenta,  
        "data": data_hex,
        "nonce": nonce,
        "value": 0,
    }

    
    if base_fee is not None:
        max_priority = w3.to_wei(2, "gwei")
        max_fee = int(base_fee) * 2 + max_priority
        tx_fee = {
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority,
        }
    else:
        
        tx_fee = {
            "gasPrice": w3.eth.gas_price,
        }

    tx_for_estimate: TxParams = cast(TxParams, {**tx_common, **tx_fee})
    gas_limit = w3.eth.estimate_gas(tx_for_estimate)

    tx: TxParams = cast(TxParams, {**tx_common, **tx_fee, "gas": gas_limit})

    tx_hash = w3.eth.send_transaction(tx)
    return tx_hash.hex()
