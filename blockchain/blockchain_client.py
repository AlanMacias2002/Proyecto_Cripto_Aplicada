from web3 import Web3
from utils.config import GANACHE_URL

class BlockchainClient:
    def __init__(self, provider_url: str = GANACHE_URL):
        self._w3 = Web3(Web3.HTTPProvider(provider_url))
        if not self._w3.is_connected():
            self._connected = False
        else:
            self._connected = True

    def conectado(self) -> bool:
        return self._connected

    @property
    def w3(self):
        return self._w3

    def obtener_cuenta_predeterminada(self):
        """
        Devuelve la primera cuenta de Ganache (si existe).
        En Ganache las cuentas vienen desbloqueadas por defecto.
        """
        if not self._connected:
            return None
        cuentas = self._w3.eth.accounts
        return cuentas[0] if len(cuentas) > 0 else None
