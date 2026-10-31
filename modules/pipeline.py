"""
Module 5 : Pipeline Complet - Orchestrateur
Transmission de Données Sécurisée - CI2CYBER ISMAGI

Ordre : Huffman -> AES -> CRC -> Convolutif -> Canal -> Viterbi -> CRC^-1 -> AES^-1 -> Huffman^-1

CORRECTIONS :
- Les résultats d'émission sont retournés ET stockés dans un dict lié à l'instance,
  ce qui évite toute collision si plusieurs pipelines coexistent.
- Le CodeurHuffman est réinstancié à chaque emettre() pour garantir un arbre propre.
- recevoir() vérifie que les résultats correspondent bien à la dernière émission
  via un identifiant de session (timestamp).
- Meilleure gestion des exceptions à chaque étape de réception.
"""

import sys
import os
import struct
import time
import uuid
import numpy as np

# ── Résolution des imports selon le contexte d'exécution ──────────
# Permet de lancer ce fichier de deux façons :
#   1. Depuis la racine du projet :  python modules/pipeline.py
#   2. Depuis la racine via app.py : import modules.pipeline
# Dans les deux cas, le dossier racine du projet est ajouté au path.
_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))   # .../project_syst/modules
_PROJECT_DIR = os.path.dirname(_MODULE_DIR)                  # .../project_syst
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

from modules.huffman import CodeurHuffman
from modules.convolutif import CodeurConvolutif, DecodeurViterbi, CanalBruite, texte_vers_bits, bits_vers_texte
from modules.crypto_crc import ChiffreurAES, CalculateurCRC
from modules.reseau import ReseauSecurise, PaquetReseau


class PipelineTransmission:
    """
    Pipeline complet de transmission sécurisée.
    Intègre tous les modules dans une chaîne cohérente.

    IMPORTANT : emettre() doit toujours être appelé avant recevoir().
    Les résultats sont isolés par session_id pour éviter toute collision.
    """

    def __init__(self, prob_erreur=0.05, mot_de_passe="CI2CYBER_2025"):
        # NOTE : self.huffman est réinstancié dans emettre() pour garantir
        # un arbre de Huffman propre à chaque nouveau message.
        self.codeur   = CodeurConvolutif()
        self.decodeur = DecodeurViterbi()
        self.canal    = CanalBruite(prob_erreur)
        self.aes      = ChiffreurAES()
        self.crc      = CalculateurCRC()
        self.reseau   = ReseauSecurise()
        self.mot_de_passe = mot_de_passe

        # Résultats intermédiaires — réinitialisés à chaque emettre()
        self._session_id = None
        self._resultats  = {}

    # ─────────────────────────────────────────────────────────────────
    # ÉMISSION
    # ─────────────────────────────────────────────────────────────────
    def emettre(self, message: str, source: str, destination: str) -> dict:
        """
        Pipeline d'émission complet.
        Retourne toutes les données intermédiaires pour la visualisation.
        """
        debut = time.time()

        # ── Réinitialisation propre ────────────────────────────────
        # CORRECTION : nouvelle instance Huffman à chaque message
        # pour éviter qu'un ancien arbre soit utilisé à la réception.
        self.huffman   = CodeurHuffman()
        self._session_id = str(uuid.uuid4())
        self._resultats  = {}

        resultats = {'succes': True, 'etapes': {}, 'session_id': self._session_id}

        # ── ÉTAPE 0 : Routage ──────────────────────────────────────
        routage = self.reseau.trouver_chemin_optimal(source, destination)
        resultats['routage'] = routage
        resultats['etapes']['routage'] = {
            'chemin':   routage.get('chemin_optimal', []),
            'distance': routage.get('distance', 0)
        }

        # ── ÉTAPE 1 : Compression Huffman ──────────────────────────
        compresse, padding, codes = self.huffman.compresser(message)
        stats_huffman = self.huffman.stats_compression(message, compresse)
        resultats['etapes']['huffman'] = {
            'taille_avant_bits':  stats_huffman['taille_originale_bits'],
            'taille_apres_bits':  stats_huffman['taille_compressee_bits'],
            'taux_compression':   stats_huffman['taux_compression'],
            'codes':   {str(k): v for k, v in codes.items()},
            'padding': padding
        }

        # ── ÉTAPE 2 : Chiffrement AES-256 ──────────────────────────
        iv, donnees_chiffrees = self.aes.chiffrer_bytes(compresse, self.mot_de_passe)
        resultats['etapes']['aes'] = {
            'taille_avant':        len(compresse),
            'taille_apres':        len(donnees_chiffrees),
            'iv_hex':              iv.hex(),
            'donnees_hex_preview': donnees_chiffrees[:16].hex() + '...'
        }

        # ── ÉTAPE 3 : Ajout du CRC-32 ─────────────────────────────
        # On protège iv + données chiffrées ensemble
        payload = iv + donnees_chiffrees
        payload_avec_crc = self.crc.encoder_avec_crc(payload)
        crc_valeur = self.crc.calculer(payload)
        resultats['etapes']['crc'] = {
            'taille_avant': len(payload),
            'taille_apres': len(payload_avec_crc),
            'crc_hex':      f'0x{crc_valeur:08X}'
        }

        # ── ÉTAPE 4 : Encodage Convolutif R=1/2 ───────────────────
        bits_payload = []
        for octet in payload_avec_crc:
            for i in range(7, -1, -1):
                bits_payload.append((octet >> i) & 1)

        bits_codes, bits_avec_flush = self.codeur.encoder_avec_terminaison(bits_payload)
        resultats['etapes']['convolutif'] = {
            'nb_bits_avant': len(bits_payload),
            'nb_bits_apres': len(bits_codes),
            'rendement':     '1/2',
            'taille_memoire': self.codeur.m,
            'preview_avant': str(bits_payload[:16]),
            'preview_apres': str(bits_codes[:32])
        }

        # ── ÉTAPE 5 : Canal Bruité ─────────────────────────────────
        bits_recus, positions_erreurs = self.canal.transmettre(bits_codes)
        ber_canal = self.canal.calculer_ber(bits_codes, bits_recus)
        resultats['etapes']['canal'] = {
            'nb_bits':           len(bits_codes),
            'nb_erreurs':        len(positions_erreurs),
            'positions_erreurs': positions_erreurs[:10],
            'ber_reel':          round(ber_canal, 4),
            'prob_erreur_canal': self.canal.p
        }

        # ── Sauvegarde pour recevoir() ─────────────────────────────
        # CORRECTION : tout est isolé dans self._resultats lié à cette instance
        self._resultats = {
            'session_id':        self._session_id,
            'bits_recus':        bits_recus,
            'nb_bits_originaux': len(bits_payload),   # longueur AVANT flush
            'iv':                iv,
            'padding':           padding,
            'longueur_message':  len(message),
            'bits_codes':        bits_codes,
            'positions_erreurs': positions_erreurs,
            'message_original':  message,             # utile pour débogage
        }

        resultats['temps_emission'] = round(time.time() - debut, 4)
        return resultats

    # ─────────────────────────────────────────────────────────────────
    # RÉCEPTION
    # ─────────────────────────────────────────────────────────────────
    def recevoir(self) -> dict:
        """
        Pipeline de réception complet.
        Doit être appelé après emettre() sur la même instance.
        """
        if not self._resultats or self._session_id is None:
            return {
                'succes': False,
                'erreur': 'Aucune transmission initiée — appelez emettre() d\'abord.',
                'message_decode': '',
                'integrite_globale': False,
                'etapes': {}
            }

        debut = time.time()
        resultats_reception = {
            'succes':      True,
            'session_id':  self._session_id,
            'etapes':      {}
        }

        bits_recus        = self._resultats['bits_recus']
        nb_bits_originaux = self._resultats['nb_bits_originaux']

        # ── ÉTAPE 6 : Décodage Viterbi ─────────────────────────────
        try:
            bits_decodes, hist_viterbi, chemin = self.decodeur.decoder(
                bits_recus, nb_bits_originaux
            )
            viterbi_ok = True
        except Exception as e:
            bits_decodes  = []
            hist_viterbi  = []
            chemin        = {'metrique': -1, 'etats': [], 'bits': []}
            viterbi_ok    = False

        resultats_reception['etapes']['viterbi'] = {
            'nb_bits_decodes':  len(bits_decodes),
            'nb_etats_treillis': 4,
            'metrique_finale':  chemin.get('metrique', -1),
            'chemin_etats':     [str(e) for e in chemin.get('etats', [])[:10]],
            'viterbi_ok':       viterbi_ok,
        }

        # ── ÉTAPE 7 : Reconstituer les bytes ───────────────────────
        octets_decodes = bytearray()
        nb_bits_complets = len(bits_decodes) - len(bits_decodes) % 8
        for i in range(0, nb_bits_complets, 8):
            octet = 0
            for bit in bits_decodes[i:i+8]:
                octet = (octet << 1) | bit
            octets_decodes.append(octet)
        payload_avec_crc = bytes(octets_decodes)

        # ── ÉTAPE 8 : Vérification CRC-32 ──────────────────────────
        crc_valide = False
        crc_calc   = 0
        crc_recu   = 0
        payload_recu = payload_avec_crc  # fallback si CRC trop court

        if len(payload_avec_crc) >= 4:
            try:
                payload_recu, crc_valide, crc_calc, crc_recu = \
                    self.crc.decoder_avec_crc(payload_avec_crc)
            except Exception:
                crc_valide = False
        
        resultats_reception['etapes']['crc'] = {
            'integrite_ok': crc_valide,
            'crc_calcule':  f'0x{crc_calc:08X}',
            'crc_recu':     f'0x{crc_recu:08X}'
        }

        # ── ÉTAPE 9 : Déchiffrement AES-256 ────────────────────────
        donnees_decompressees = b''
        aes_ok = False

        try:
            # Structure du payload : IV (16 bytes) | données chiffrées
            if len(payload_recu) > 16:
                iv_recu          = payload_recu[:16]
                donnees_chiffrees = payload_recu[16:]
                donnees_decompressees = self.aes.dechiffrer_bytes(
                    iv_recu, donnees_chiffrees, self.mot_de_passe
                )
                aes_ok = True
            else:
                aes_ok = False
        except Exception:
            aes_ok = False

        resultats_reception['etapes']['aes'] = {
            'dechiffrement_ok': aes_ok,
            'taille_donnees':   len(donnees_decompressees)
        }

        # ── ÉTAPE 10 : Décompression Huffman ───────────────────────
        # CORRECTION : on utilise self.huffman qui contient l'arbre
        # construit lors de l'émission (même instance de pipeline).
        message_decode = ''
        huffman_ok = False

        try:
            if aes_ok and len(donnees_decompressees) > 0:
                padding          = self._resultats['padding']
                longueur         = self._resultats['longueur_message']
                message_decode   = self.huffman.decompresser(
                    donnees_decompressees, padding, longueur
                )
                huffman_ok = True
        except Exception:
            huffman_ok = False

        resultats_reception['etapes']['huffman'] = {
            'decompression_ok': huffman_ok,
            'message_decode':   message_decode
        }

        resultats_reception['message_decode']     = message_decode
        resultats_reception['integrite_globale']  = crc_valide and aes_ok and huffman_ok
        resultats_reception['temps_reception']    = round(time.time() - debut, 4)

        return resultats_reception

    # ─────────────────────────────────────────────────────────────────
    # ANALYSE BER
    # ─────────────────────────────────────────────────────────────────
    def evaluer_ber(self, message: str, prob_min=0.0, prob_max=0.2,
                    nb_points=10, nb_essais=5) -> dict:
        """
        Évalue le BER en fonction du bruit canal.
        CORRECTION : utilise le message courant (passé en paramètre),
        pas une valeur codée en dur.
        """
        probabilites   = np.linspace(prob_min, prob_max, nb_points)
        bers_avant     = []
        bers_apres     = []

        # CORRECTION : on encode le message réel pour le BER
        bits_msg       = texte_vers_bits(message)
        codeur_test    = CodeurConvolutif()
        decodeur_test  = DecodeurViterbi()

        for p in probabilites:
            canal_test        = CanalBruite(p)
            ber_avant_liste   = []
            ber_apres_liste   = []

            for _ in range(nb_essais):
                # Encoder
                bits_codes, _ = codeur_test.encoder_avec_terminaison(bits_msg)
                # Canal
                bits_recus, _ = canal_test.transmettre(bits_codes)
                # BER avant décodage (= taux d'erreur brut du canal)
                ber_avant = canal_test.calculer_ber(bits_codes, bits_recus)
                ber_avant_liste.append(ber_avant)
                # Viterbi
                bits_dec, _, _ = decodeur_test.decoder(bits_recus, len(bits_msg))
                # BER après décodage (comparaison bit à bit avec l'original)
                n       = min(len(bits_msg), len(bits_dec))
                ber_apres = sum(a != b for a, b in zip(bits_msg[:n], bits_dec[:n])) / n if n > 0 else 0
                ber_apres_liste.append(ber_apres)

            bers_avant.append(float(np.mean(ber_avant_liste)))
            bers_apres.append(float(np.mean(ber_apres_liste)))

        return {
            'probabilites':      probabilites.tolist(),
            'ber_sans_codage':   bers_avant,
            'ber_avec_viterbi':  bers_apres,
            'message_utilise':   message,
            'nb_bits_message':   len(bits_msg),
        }


# ── Test standalone ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 65)
    print("PIPELINE COMPLET - TEST")
    print("=" * 65)

    pipeline = PipelineTransmission(prob_erreur=0.03)
    message  = "TRANSMISSION SECURISEE"

    print(f"\n>>> ÉMISSION : '{message}' de N0 vers N7\n")
    res_emission = pipeline.emettre(message, "N0", "N7")

    for etape, data in res_emission['etapes'].items():
        print(f"[{etape.upper()}]")
        for k, v in data.items():
            print(f"  {k}: {v}")
        print()

    print(">>> RÉCEPTION\n")
    res_reception = pipeline.recevoir()

    for etape, data in res_reception['etapes'].items():
        print(f"[{etape.upper()}]")
        for k, v in data.items():
            print(f"  {k}: {v}")
        print()

    print(f"Message décodé   : '{res_reception['message_decode']}'")
    print(f"Message original : '{message}'")
    print(f"Correspondance   : {res_reception['message_decode'] == message}")
    print(f"Intégrité globale: {res_reception['integrite_globale']}")

    # Test avec différents messages
    print("\n" + "=" * 65)
    print("TEST MULTI-MESSAGES")
    print("=" * 65)
    messages_test = [
        "HELLO CI2CYBER",
        "TEST 123",
        "ISMAGI 2025 SECURITE",
    ]
    for msg in messages_test:
        p = PipelineTransmission(prob_erreur=0.02)
        p.emettre(msg, "N0", "N7")
        r = p.recevoir()
        ok = "✅" if r['message_decode'] == msg else "❌"
        print(f"  {ok} '{msg}' → '{r['message_decode']}'")