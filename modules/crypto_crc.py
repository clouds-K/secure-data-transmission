"""
Module 3 : Cryptographie AES-256 + CRC-32
Transmission de Données Sécurisée - CI2CYBER ISMAGI

CORRECTIONS :
- CalculateurCRC.decoder_avec_crc() retourne un tuple complet même si les données
  font moins de 4 bytes (évite un ValueError au unpack).
- ChiffreurAES.dechiffrer_bytes() lève une exception claire si le padding est
  corrompu (cas fréquent quand le CRC a détecté une erreur mais qu'on continue).
- ChiffreurAES.chiffrer() : 'cle_hex' affiche maintenant les 16 premiers octets
  (32 chars hex) de façon cohérente avec chiffrer_bytes().
- Ajout de dechiffrer_bytes_safe() qui retourne (bytes | None, bool) pour une
  intégration sans try/except dans pipeline.py.
"""

import os
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ════════════════════════════════════════════════════════════════════
# CRC-32
# ════════════════════════════════════════════════════════════════════

class CalculateurCRC:
    """
    Implémentation CRC-32 basée sur le cours Chapitre 4.
    Division polynomiale modulo 2.
    """

    def __init__(self):
        self.polynome = 0xEDB88320   # CRC-32 IEEE 802.3
        self.table    = self._construire_table()

    def _construire_table(self) -> list:
        """Précalcule la table de lookup pour CRC-32."""
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ self.polynome
                else:
                    crc >>= 1
            table.append(crc)
        return table

    def calculer(self, donnees: bytes) -> int:
        """Calcule le CRC-32 d'une séquence de bytes."""
        crc = 0xFFFFFFFF
        for octet in donnees:
            crc = (crc >> 8) ^ self.table[(crc ^ octet) & 0xFF]
        return crc ^ 0xFFFFFFFF

    def verifier(self, donnees: bytes, crc_attendu: int) -> bool:
        """Vérifie l'intégrité des données avec le CRC."""
        return self.calculer(donnees) == crc_attendu

    def encoder_avec_crc(self, donnees: bytes) -> bytes:
        """Retourne les données avec le CRC-32 ajouté à la fin (4 bytes big-endian)."""
        crc = self.calculer(donnees)
        return donnees + struct.pack('>I', crc)

    def decoder_avec_crc(self, donnees_avec_crc: bytes):
        """
        Sépare les données du CRC et vérifie l'intégrité.
        CORRECTION : retourne (données, False, 0, 0) si moins de 4 bytes,
        évitant un struct.error au lieu d'un crash silencieux.

        Retourne : (données, valide: bool, crc_calculé: int, crc_reçu: int)
        """
        if len(donnees_avec_crc) < 4:
            return donnees_avec_crc, False, 0, 0

        donnees   = donnees_avec_crc[:-4]
        crc_recu  = struct.unpack('>I', donnees_avec_crc[-4:])[0]
        crc_calc  = self.calculer(donnees)
        valide    = (crc_calc == crc_recu)
        return donnees, valide, crc_calc, crc_recu

    def demo_division_polynomiale(self, message_bits: str, generateur: str) -> dict:
        """
        Démontre la division polynomiale modulo 2 (comme dans le cours).
        message_bits : str de '0' et '1'
        generateur   : str de '0' et '1' (polynôme générateur)
        Retourne le reste (CRC) et les étapes.
        """
        deg      = len(generateur) - 1
        dividend = list(message_bits + '0' * deg)
        gen      = list(generateur)
        etapes   = []

        i = 0
        while i <= len(dividend) - len(gen):
            if dividend[i] == '1':
                etape = {
                    'position': i,
                    'avant':    ''.join(dividend),
                    'diviseur': ' ' * i + generateur
                }
                for j in range(len(gen)):
                    dividend[i + j] = str(int(dividend[i + j]) ^ int(gen[j]))
                etape['apres'] = ''.join(dividend)
                etapes.append(etape)
            i += 1

        reste = ''.join(dividend[-deg:]) if deg > 0 else ''
        return {
            'message_original': message_bits,
            'message_padde':    message_bits + '0' * deg,
            'generateur':       generateur,
            'crc':              reste,
            'message_final':    message_bits + reste,
            'etapes':           etapes
        }


# ════════════════════════════════════════════════════════════════════
# AES-256
# ════════════════════════════════════════════════════════════════════

class ChiffreurAES:
    """
    Chiffrement AES-256 en mode CBC.
    Clé dérivée via SHA-256 depuis un mot de passe.
    """

    TAILLE_BLOC = 16   # bytes (128 bits)
    TAILLE_CLE  = 32   # bytes (256 bits)

    def __init__(self):
        self.taille_bloc = self.TAILLE_BLOC
        self.taille_cle  = self.TAILLE_CLE

    def _deriver_cle(self, mot_de_passe: str) -> bytes:
        """Dérive une clé AES-256 depuis un mot de passe via SHA-256."""
        return hashlib.sha256(mot_de_passe.encode('utf-8')).digest()

    # ── Chiffrement / déchiffrement texte ─────────────────────────

    def chiffrer(self, texte_clair: str, mot_de_passe: str) -> dict:
        """
        Chiffre un texte avec AES-256-CBC.
        Retourne un dict avec IV, données chiffrées, et métadonnées.
        """
        cle    = self._deriver_cle(mot_de_passe)
        iv     = os.urandom(self.taille_bloc)
        cipher = AES.new(cle, AES.MODE_CBC, iv)

        donnees          = texte_clair.encode('utf-8')
        donnees_paddees  = pad(donnees, self.taille_bloc)
        donnees_chiffrees = cipher.encrypt(donnees_paddees)

        return {
            'iv':               iv,
            'donnees_chiffrees': donnees_chiffrees,
            'taille_originale': len(donnees),
            'taille_chiffree':  len(donnees_chiffrees),
            # CORRECTION : affichage cohérent sur 16 octets (32 chars hex)
            'cle_hex':          cle.hex()[:32] + '...'
        }

    def dechiffrer(self, iv: bytes, donnees_chiffrees: bytes,
                   mot_de_passe: str, taille_originale: int) -> str:
        """Déchiffre des données AES-256-CBC vers texte."""
        cle            = self._deriver_cle(mot_de_passe)
        cipher         = AES.new(cle, AES.MODE_CBC, iv)
        donnees_paddees = cipher.decrypt(donnees_chiffrees)
        donnees        = unpad(donnees_paddees, self.taille_bloc)
        return donnees.decode('utf-8')

    # ── Chiffrement / déchiffrement bytes bruts ───────────────────

    def chiffrer_bytes(self, donnees: bytes, mot_de_passe: str) -> tuple:
        """
        Chiffre des bytes bruts (pour données binaires compressées).
        Retourne (iv, données_chiffrées).
        """
        cle    = self._deriver_cle(mot_de_passe)
        iv     = os.urandom(self.taille_bloc)
        cipher = AES.new(cle, AES.MODE_CBC, iv)
        return iv, cipher.encrypt(pad(donnees, self.taille_bloc))

    def dechiffrer_bytes(self, iv: bytes, donnees_chiffrees: bytes,
                         mot_de_passe: str) -> bytes:
        """
        Déchiffre vers bytes bruts.
        CORRECTION : lève ValueError avec message clair si padding corrompu,
        ce qui permet à pipeline.py de capturer l'exception proprement.
        """
        if len(donnees_chiffrees) == 0:
            raise ValueError("Données chiffrées vides — déchiffrement impossible.")
        if len(donnees_chiffrees) % self.taille_bloc != 0:
            raise ValueError(
                f"Longueur invalide ({len(donnees_chiffrees)} bytes) — "
                f"doit être un multiple de {self.taille_bloc}."
            )
        cle    = self._deriver_cle(mot_de_passe)
        cipher = AES.new(cle, AES.MODE_CBC, iv)
        try:
            return unpad(cipher.decrypt(donnees_chiffrees), self.taille_bloc)
        except ValueError as e:
            raise ValueError(f"Padding AES corrompu (données altérées par le canal) : {e}")

    def dechiffrer_bytes_safe(self, iv: bytes, donnees_chiffrees: bytes,
                              mot_de_passe: str) -> tuple:
        """
        Version sécurisée de dechiffrer_bytes().
        Retourne (données_bytes, succès: bool) sans lever d'exception.
        Utile pour pipeline.py afin d'éviter les try/except imbriqués.
        """
        try:
            donnees = self.dechiffrer_bytes(iv, donnees_chiffrees, mot_de_passe)
            return donnees, True
        except Exception:
            return b'', False


# ── Test standalone ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("MODULE AES + CRC - TEST")
    print("=" * 60)

    # ── Test CRC division polynomiale (exemple cours) ─────────────
    print("\n--- TEST CRC division polynomiale ---")
    crc_calc = CalculateurCRC()
    res = crc_calc.demo_division_polynomiale("1101", "1011")
    print(f"Message paddé  : {res['message_padde']}")
    print(f"CRC calculé    : {res['crc']}")
    print(f"Message final  : {res['message_final']}")
    print(f"(Attendu selon cours : CRC=001, message final=1101001)")

    # ── Test CRC-32 sur données réelles ───────────────────────────
    print("\n--- TEST CRC-32 ---")
    donnees    = b"TRANSMISSION SECURISEE CI2CYBER"
    avec_crc   = crc_calc.encoder_avec_crc(donnees)
    d, valide, cv, cr = crc_calc.decoder_avec_crc(avec_crc)
    print(f"CRC calculé  : 0x{cv:08X}")
    print(f"Intégrité OK : {valide}")

    # Simulation erreur
    corrompues = bytearray(avec_crc)
    corrompues[5] ^= 0xFF
    _, valide2, _, _ = crc_calc.decoder_avec_crc(bytes(corrompues))
    print(f"Après corruption : Intégrité OK = {valide2}  (doit être False)")

    # CORRECTION : test avec données trop courtes
    _, valide3, _, _ = crc_calc.decoder_avec_crc(b'\x00\x01')
    print(f"Données < 4 bytes : Intégrité OK = {valide3}  (doit être False)")

    # ── Test AES-256 texte ────────────────────────────────────────
    print("\n--- TEST AES-256 (texte) ---")
    aes     = ChiffreurAES()
    message = "Message secret CI2CYBER 2025"
    mdp     = "motdepasse_securise_123"

    res_c = aes.chiffrer(message, mdp)
    print(f"Message original : '{message}'")
    print(f"Taille originale : {res_c['taille_originale']} bytes")
    print(f"Taille chiffrée  : {res_c['taille_chiffree']} bytes")
    print(f"Clé (partielle)  : {res_c['cle_hex']}")

    decode = aes.dechiffrer(res_c['iv'], res_c['donnees_chiffrees'],
                             mdp, res_c['taille_originale'])
    print(f"Déchiffré OK     : {'✅' if decode == message else '❌'} → '{decode}'")

    # ── Test AES-256 bytes bruts ──────────────────────────────────
    print("\n--- TEST AES-256 (bytes bruts) ---")
    donnees_brutes = b'\x01\x02\x03\xAB\xCD\xEF' * 10
    iv2, chiff2 = aes.chiffrer_bytes(donnees_brutes, mdp)
    dechiff2, ok = aes.dechiffrer_bytes_safe(iv2, chiff2, mdp)
    print(f"Bytes bruts OK : {'✅' if dechiff2 == donnees_brutes else '❌'}")

    # Test déchiffrement avec mauvais mot de passe
    _, ok_bad = aes.dechiffrer_bytes_safe(iv2, chiff2, "mauvais_mdp")
    print(f"Mauvais MDP    : retourne succès={ok_bad}  (doit être False)")

    # ── Test données corrompues ───────────────────────────────────
    # NOTE IMPORTANTE sur AES-CBC :
    # Corrompre un bloc intermédiaire ne plante PAS le déchiffrement AES.
    # En CBC, seul le dernier bloc contient le padding PKCS7 ; si on corrompt
    # un bloc qui ne touche pas ce padding, unpad() réussit quand même —
    # les données déchiffrées sont juste incorrectes (garbage dans ce bloc).
    # C'est NORMAL et ATTENDU : AES garantit la CONFIDENTIALITÉ, pas l'INTÉGRITÉ.
    # Dans notre pipeline, c'est le CRC-32 (étape avant AES) qui détecte
    # toute altération des données. AES + CRC ensemble assurent les deux propriétés.

    # Cas 1 : corruption bloc intermédiaire → AES réussit mais données altérées
    chiff_corrompu_mid = bytearray(chiff2)
    chiff_corrompu_mid[8] ^= 0xFF   # bloc 0, octet 8
    data_mid, ok_mid = aes.dechiffrer_bytes_safe(iv2, bytes(chiff_corrompu_mid), mdp)
    print(f"Corruption bloc intermédiaire : succès={ok_mid}, données_ok={data_mid == donnees_brutes}")
    print(f"  → Normal : AES déchiffre mais les données sont corrompues (rôle du CRC)")

    # Cas 2 : corruption dernier bloc → padding cassé → AES échoue
    chiff_corrompu_last = bytearray(chiff2)
    chiff_corrompu_last[-1] ^= 0xFF  # dernier octet = padding
    _, ok_last = aes.dechiffrer_bytes_safe(iv2, bytes(chiff_corrompu_last), mdp)
    print(f"Corruption dernier bloc (padding) : succès={ok_last}  (doit être False)")

    # Cas 3 : corruption de l'IV → premier bloc corrompu → AES réussit (même note)
    iv_corrompu = bytearray(iv2)
    iv_corrompu[0] ^= 0xFF
    data_iv, ok_iv = aes.dechiffrer_bytes_safe(bytes(iv_corrompu), chiff2, mdp)
    print(f"Corruption IV : succès={ok_iv}, données_ok={data_iv == donnees_brutes}")
    print(f"  → Normal : IV corrompt seulement le 1er bloc (rôle du CRC)")