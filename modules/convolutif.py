"""
Module 2 : Codage Canal - Code Convolutif R=1/2, K=3 + Décodage Viterbi
Basé sur le cours chap_5_convolutif.pdf - CI2CYBER ISMAGI
Polynômes générateurs : g1 = [1,0,1] = 5 octal, g2 = [1,1,1] = 7 octal

CORRECTIONS :
- CodeurConvolutif.encoder() réinitialise le registre au début de chaque appel,
  évitant qu'un état résiduel d'une transmission précédente fausse le codage.
- DecodeurViterbi.decoder() gère les séquences de longueur impaire (padding auto).
- CanalBruite : probabilite_erreur clampée entre 0 et 1 pour éviter les valeurs
  aberrantes venant d'un slider mal initialisé.
- texte_vers_bits / bits_vers_texte : robustesse sur les entrées vides.
"""

import numpy as np
from itertools import product


class CodeurConvolutif:
    """
    Encodeur convolutif non systématique R=1/2, K=3
    g1(D) = 1 + D²  -> sortie x1
    g2(D) = 1 + D + D²  -> sortie x2
    (Correspond à l'exemple du cours pages 6-23)
    """

    def __init__(self):
        self.g1 = [1, 0, 1]   # 1 + D²
        self.g2 = [1, 1, 1]   # 1 + D + D²
        self.K  = 3            # Longueur de contrainte
        self.m  = 2            # Mémoire (K-1)
        self.registre = [0, 0]

    def encoder(self, bits: list) -> list:
        """
        Encode une séquence de bits.
        CORRECTION : le registre est réinitialisé à [0,0] à chaque appel
        pour garantir un état initial propre, même si l'instance est réutilisée.
        """
        self.registre = [0, 0]   # ← CORRECTION : réinitialisation systématique
        sequence_codee = []

        for bit in bits:
            x1 = (bit * self.g1[0] +
                  self.registre[0] * self.g1[1] +
                  self.registre[1] * self.g1[2]) % 2
            x2 = (bit * self.g2[0] +
                  self.registre[0] * self.g2[1] +
                  self.registre[1] * self.g2[2]) % 2

            sequence_codee.extend([x1, x2])
            self.registre = [bit, self.registre[0]]

        return sequence_codee

    def encoder_avec_terminaison(self, bits: list):
        """
        Encode en ajoutant m=2 bits de terminaison (flush) pour
        ramener le codeur à l'état '00'.
        Retourne (sequence_codee, bits_avec_flush).
        """
        bits_avec_flush = list(bits) + [0] * self.m
        return self.encoder(bits_avec_flush), bits_avec_flush

    def get_sorties_etat(self, etat: tuple, bit_entree: int):
        """
        Calcule les sorties et l'état suivant pour un état et une entrée donnés.
        etat = (e1, e2) = contenu du registre.
        """
        e1, e2 = etat
        x1 = (bit_entree * self.g1[0] + e1 * self.g1[1] + e2 * self.g1[2]) % 2
        x2 = (bit_entree * self.g2[0] + e1 * self.g2[1] + e2 * self.g2[2]) % 2
        etat_suivant = (bit_entree, e1)
        return (x1, x2), etat_suivant


class DecodeurViterbi:
    """
    Décodeur Viterbi pour le code convolutif R=1/2, K=3.
    Implémentation conforme au cours (pages 51-63).
    """

    def __init__(self):
        self.codeur = CodeurConvolutif()
        self.etats  = [(0, 0), (0, 1), (1, 0), (1, 1)]
        self._construire_treillis()

    def _construire_treillis(self):
        """Précalcule toutes les transitions du treillis."""
        self.transitions = {}
        for etat in self.etats:
            self.transitions[etat] = {}
            for bit in [0, 1]:
                sorties, etat_suivant = self.codeur.get_sorties_etat(etat, bit)
                self.transitions[etat][bit] = {
                    'etat_suivant': etat_suivant,
                    'sorties':      sorties
                }

    def distance_hamming(self, seq1, seq2) -> int:
        """Distance de Hamming entre deux séquences."""
        return sum(a != b for a, b in zip(seq1, seq2))

    def decoder(self, sequence_recue: list, longueur_message: int):
        """
        Algorithme de Viterbi complet.
        CORRECTION : si la séquence reçue a une longueur impaire,
        on ajoute un bit 0 de padding pour éviter un IndexError.

        sequence_recue   : liste de bits reçus (éventuellement bruités)
        longueur_message : nombre de bits originaux (sans flush ni codage)
        Retourne : (bits_décodés, historique_métriques, meilleur_chemin)
        """
        # ── Gestion longueur impaire ───────────────────────────────
        if len(sequence_recue) % 2 != 0:
            sequence_recue = list(sequence_recue) + [0]

        # ── Gestion séquence vide ──────────────────────────────────
        if len(sequence_recue) == 0:
            chemin_vide = {'metrique': 0, 'etats': [(0, 0)], 'bits': []}
            return [], [{}], chemin_vide

        n_etapes     = len(sequence_recue) // 2
        metrique_inf = float('inf')

        # Initialisation : seul l'état (0,0) est actif au départ
        metriques = {etat: metrique_inf for etat in self.etats}
        metriques[(0, 0)] = 0

        chemins = {
            etat: {'metrique': metrique_inf, 'etats': [etat], 'bits': []}
            for etat in self.etats
        }
        chemins[(0, 0)] = {'metrique': 0, 'etats': [(0, 0)], 'bits': []}

        historique_metriques = [dict(metriques)]

        for etape in range(n_etapes):
            bits_recus = tuple(sequence_recue[etape*2:(etape+1)*2])

            nouveaux_chemins = {
                etat: {'metrique': metrique_inf, 'etats': [], 'bits': []}
                for etat in self.etats
            }

            for etat_courant in self.etats:
                if metriques[etat_courant] == metrique_inf:
                    continue

                for bit_entree in [0, 1]:
                    trans        = self.transitions[etat_courant][bit_entree]
                    etat_suivant = trans['etat_suivant']
                    sorties      = trans['sorties']

                    metrique_branche  = self.distance_hamming(sorties, bits_recus)
                    nouvelle_metrique = metriques[etat_courant] + metrique_branche

                    if nouvelle_metrique < nouveaux_chemins[etat_suivant]['metrique']:
                        nouveaux_chemins[etat_suivant] = {
                            'metrique': nouvelle_metrique,
                            'etats':    chemins[etat_courant]['etats'] + [etat_suivant],
                            'bits':     chemins[etat_courant]['bits']  + [bit_entree]
                        }

            chemins   = nouveaux_chemins
            metriques = {etat: chemins[etat]['metrique'] for etat in self.etats}
            historique_metriques.append(dict(metriques))

        # ── Sélection du meilleur chemin ──────────────────────────
        # Priorité à l'état final (0,0) (terminaison propre)
        meilleur_chemin = chemins[(0, 0)]
        if meilleur_chemin['metrique'] == metrique_inf:
            # Fallback : chemin global de métrique minimale
            meilleur_chemin = min(
                chemins.values(),
                key=lambda x: x['metrique'] if x['metrique'] != metrique_inf else 1e18
            )

        bits_decodes = meilleur_chemin['bits'][:longueur_message]
        return bits_decodes, historique_metriques, meilleur_chemin


class CanalBruite:
    """
    Simule un canal binaire symétrique (BSC) avec probabilité d'erreur p.
    CORRECTION : p est clampé dans [0, 1] pour éviter des comportements
    indéfinis si le slider Streamlit transmet une valeur hors plage.
    """

    def __init__(self, probabilite_erreur: float = 0.05):
        self.p = max(0.0, min(1.0, float(probabilite_erreur)))  # ← clamp

    def transmettre(self, bits: list):
        """Introduit des erreurs aléatoires selon la probabilité p."""
        bits_recus = []
        erreurs    = []
        for i, bit in enumerate(bits):
            if np.random.random() < self.p:
                bits_recus.append(1 - bit)
                erreurs.append(i)
            else:
                bits_recus.append(bit)
        return bits_recus, erreurs

    def calculer_ber(self, bits_originaux: list, bits_recus: list) -> float:
        """
        Calcule le Bit Error Rate.
        CORRECTION : retourne 0.0 si l'une des listes est vide.
        """
        n = min(len(bits_originaux), len(bits_recus))
        if n == 0:
            return 0.0
        erreurs = sum(a != b for a, b in zip(bits_originaux[:n], bits_recus[:n]))
        return erreurs / n


def texte_vers_bits(texte: str) -> list:
    """
    Convertit du texte en liste de bits (UTF-8, big-endian).
    CORRECTION : retourne [] si texte vide.
    """
    if not texte:
        return []
    bits = []
    for octet in texte.encode('utf-8'):
        for i in range(7, -1, -1):
            bits.append((octet >> i) & 1)
    return bits


def bits_vers_texte(bits: list) -> str:
    """
    Convertit une liste de bits en texte.
    CORRECTION : retourne '' si liste vide.
    """
    if not bits:
        return ''
    # Aligner sur un multiple de 8
    while len(bits) % 8 != 0:
        bits.append(0)
    octets = bytearray()
    for i in range(0, len(bits), 8):
        octet = 0
        for bit in bits[i:i+8]:
            octet = (octet << 1) | bit
        octets.append(octet)
    try:
        return octets.decode('utf-8', errors='ignore')
    except Exception:
        return str(octets)


# ── Test standalone ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("MODULE CODAGE CONVOLUTIF + VITERBI - TEST")
    print("=" * 60)

    codeur  = CodeurConvolutif()
    decodeur = DecodeurViterbi()
    canal   = CanalBruite(probabilite_erreur=0.05)

    # ── Test séquence du cours : '1001' ───────────────────────────
    message_bits = [1, 0, 0, 1]
    print(f"\nMessage original (bits) : {message_bits}")

    code, bits_flush = codeur.encoder_avec_terminaison(message_bits)
    print(f"Bits avec terminaison   : {bits_flush}")
    print(f"Séquence encodée        : {code}")
    print(f"(Attendu selon cours   : 1 1 0 1 1 1 1 1 pour '1001')")

    np.random.seed(42)
    code_recu, positions_erreurs = canal.transmettre(code)
    print(f"\nSéquence reçue (après canal p=0.05) : {code_recu}")
    print(f"Positions des erreurs                : {positions_erreurs}")
    print(f"BER canal                            : {canal.calculer_ber(code, code_recu):.4f}")

    bits_decodes, hist, chemin = decodeur.decoder(code_recu, len(message_bits))
    print(f"\nBits décodés par Viterbi : {bits_decodes}")
    print(f"Message original         : {message_bits}")
    print(f"Décodage correct         : {'✅' if bits_decodes == message_bits else '❌'}")

    # ── Test réutilisation du codeur (registre propre) ────────────
    print("\n--- Test réutilisation codeur ---")
    for msg in [[1, 0, 0, 1], [1, 1, 0, 0], [0, 1, 0, 1]]:
        code1, _ = codeur.encoder_avec_terminaison(msg)
        code2, _ = codeur.encoder_avec_terminaison(msg)
        print(f"  msg={msg} → code1==code2 : {'✅' if code1 == code2 else '❌'}")

    # ── Test avec texte complet ───────────────────────────────────
    # Seed fixe par texte pour résultats déterministes.
    # À p=0.05, Viterbi corrige jusqu'à ~2 erreurs groupées.
    # Pour des messages longs, des erreurs multiples peuvent dépasser
    # la capacité de correction → ❌ possible et NORMAL sur ce test.
    # Dans l'app réelle, c'est le CRC qui détecte ces cas résiduels.
    print("\n--- Test avec texte complet (seed fixe par texte) ---")
    seeds = [("HELLO", 0), ("CI2CYBER 2025", 1), ("TRANSMISSION", 7)]
    for texte, seed in seeds:
        np.random.seed(seed)
        bits_msg = texte_vers_bits(texte)
        code2, _ = codeur.encoder_avec_terminaison(bits_msg)
        code2_recu, erreurs2 = canal.transmettre(code2)
        bits_dec2, _, _ = decodeur.decoder(code2_recu, len(bits_msg))
        texte_decode = bits_vers_texte(list(bits_dec2))
        ok = texte_decode == texte
        note = "" if ok else f"  ← {len(erreurs2)} erreurs canal, capacité correction dépassée (normal)"
        print(f"  {'✅' if ok else '❌'} '{texte}' → '{texte_decode}'{note}")

    # ── Test canal avec p hors plage ──────────────────────────────
    print("\n--- Test canal avec p invalide ---")
    c_neg = CanalBruite(-0.5)
    c_sup = CanalBruite(1.5)
    print(f"  CanalBruite(-0.5).p = {c_neg.p}  (attendu : 0.0)")
    print(f"  CanalBruite(1.5).p  = {c_sup.p}  (attendu : 1.0)")