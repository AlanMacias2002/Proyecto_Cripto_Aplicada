# main.py
from core.event_generator import generar_evento
from core.hasher import generar_hash_dinamico
from core.logger import construir_log
from blockchain.blockchain_client import BlockchainClient
from blockchain.transaction_manager import enviar_evento_a_blockchain
from database.db_admin import insertar_mapeo_hash, reset_admin_db
from database.db_operational import insertar_log_operativo, reset_operational_db
from utils.config import ADMIN_DB_PATH, OPERATIVE_DB_PATH

def procesar_evento() -> dict:
    evento = generar_evento()
    hash_result, timestamp, nonce = generar_hash_dinamico(evento["entidad"])
    log = construir_log(evento, hash_result, timestamp)
    blockchain = BlockchainClient()
    tx_hash = enviar_evento_a_blockchain(blockchain, log)
    insertar_log_operativo(
        OPERATIVE_DB_PATH,
        hash_result,
        evento["evento"],
        evento["fecha"],
        tx_hash,
        evento.get("detalles")
    )
    insertar_mapeo_hash(
        ADMIN_DB_PATH,
        hash_result,
        evento["entidad"],
        timestamp,
        nonce,
        evento.get("evento"),
        evento.get("detalles"),
    )
    return {
        "evento": evento,
        "hash": hash_result,
        "tx_hash": tx_hash,
        "timestamp": timestamp,
        "nonce": nonce,
    }

def main():
    print("=== BlockAudit - Sistema de Registros Inmutables (Ganache local) ===\n")

    # Limpiar bases al inicio para evitar entradas huérfanas cuando Ganache se reinicia
    try:
        reset_operational_db(OPERATIVE_DB_PATH)
        reset_admin_db(ADMIN_DB_PATH)
        print("[~] Bases limpiadas (operativa y administrativa).")
    except Exception as e:
        print(f"[!] No se pudieron limpiar las bases: {e}")

    resultado = procesar_evento()
    print("[+] Evento generado:", resultado["evento"])
    print("[+] Hash dinámico:", resultado["hash"])
    print("[+] Transacción:", resultado["tx_hash"])
    print("=== Proceso completado ===")

if __name__ == "__main__":
    main()
