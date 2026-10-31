"""
Module 1 : Codage Source - Compression de Huffman
Transmission de Données Sécurisée - CI2CYBER ISMAGI

CORRECTIONS :
- construire_arbre() réinitialise self.codes et self.codes_inverse avant chaque
  nouvel arbre, évitant la contamination entre deux messages successifs.
- Gestion du cas message à un seul caractère unique (arbre dégénéré).
- decompresser() gère le cas où l'arbre n'a qu'un noeud (racine = feuille).
- stats_compression() ne plante plus si taille_originale == 0.
"""

import heapq
from collections import Counter


class NoeudHuffman:
    def __init__(self, caractere, frequence):
        self.caractere = caractere
        self.frequence = frequence
        self.gauche    = None
        self.droite    = None

    def __lt__(self, autre):
        return self.frequence < autre.frequence


class CodeurHuffman:
    def __init__(self):
        self.codes         = {}
        self.codes_inverse = {}
        self.racine        = None

    def construire_arbre(self, texte: str):
        """
        Construit l'arbre de Huffman pour le texte donné.
        CORRECTION : réinitialise les dicts à chaque appel pour éviter
        de mélanger les codes de deux messages différents.
        """
        # ── Réinitialisation obligatoire ──────────────────────────
        self.codes         = {}
        self.codes_inverse = {}
        self.racine        = None

        frequences = Counter(texte)
        tas = [NoeudHuffman(car, freq) for car, freq in frequences.items()]
        heapq.heapify(tas)

        # ── Cas dégénéré : un seul caractère unique ───────────────
        # (ex. message = "AAAA")
        if len(tas) == 1:
            noeud = heapq.heappop(tas)
            self.racine = noeud
            self.codes[noeud.caractere]        = "0"
            self.codes_inverse["0"]            = noeud.caractere
            return

        # ── Construction normale de l'arbre ───────────────────────
        while len(tas) > 1:
            gauche = heapq.heappop(tas)
            droite = heapq.heappop(tas)
            parent = NoeudHuffman(None, gauche.frequence + droite.frequence)
            parent.gauche = gauche
            parent.droite = droite
            heapq.heappush(tas, parent)

        self.racine = tas[0]
        self._generer_codes(self.racine, "")

    def _generer_codes(self, noeud, code_courant: str):
        if noeud is None:
            return
        if noeud.caractere is not None:
            # Feuille : on assigne le code (au minimum "0" si arbre vide)
            code = code_courant if code_courant else "0"
            self.codes[noeud.caractere]  = code
            self.codes_inverse[code]     = noeud.caractere
            return
        self._generer_codes(noeud.gauche, code_courant + "0")
        self._generer_codes(noeud.droite, code_courant + "1")

    def compresser(self, texte: str):
        """
        Compresse le texte et retourne (bytes_compressés, padding, table_codes).
        """
        if not texte:
            return b'', 0, {}

        self.construire_arbre(texte)
        bits = "".join(self.codes[c] for c in texte)

        # Padding pour aligner sur 8 bits
        padding = (8 - len(bits) % 8) % 8
        bits_padded = bits + "0" * padding

        # Convertir en bytes
        octets = bytearray()
        for i in range(0, len(bits_padded), 8):
            octet = bits_padded[i:i+8]
            octets.append(int(octet, 2))

        return bytes(octets), padding, self.codes

    def decompresser(self, donnees_bytes: bytes, padding: int,
                     longueur_originale: int) -> str:
        """
        Décompresse les bytes en texte original.
        CORRECTION : gère le cas où la racine est une feuille (un seul symbole).
        """
        if not donnees_bytes or self.racine is None:
            return ""

        # Reconvertir bytes en chaîne de bits
        bits = ""
        for octet in donnees_bytes:
            bits += format(octet, '08b')

        # Retirer le padding final
        if padding > 0:
            bits = bits[:-padding]

        texte = ""

        # ── Cas dégénéré : racine = feuille (un seul caractère unique) ──
        if self.racine.caractere is not None:
            # Chaque bit "0" représente ce caractère unique
            texte = self.racine.caractere * longueur_originale
            return texte

        # ── Décodage normal ───────────────────────────────────────
        noeud = self.racine
        for bit in bits:
            if bit == "0":
                noeud = noeud.gauche
            else:
                noeud = noeud.droite

            # Sécurité : noeud None (arbre corrompu)
            if noeud is None:
                break

            if noeud.caractere is not None:
                texte += noeud.caractere
                noeud = self.racine
                if len(texte) == longueur_originale:
                    break

        return texte

    def stats_compression(self, texte_original: str,
                           donnees_compressees: bytes) -> dict:
        """
        Calcule les statistiques de compression.
        CORRECTION : évite la division par zéro si texte vide.
        """
        taille_originale  = len(texte_original) * 8   # bits (ASCII = 8 bits/char)
        taille_compressee = len(donnees_compressees) * 8

        if taille_originale > 0:
            taux = (1 - taille_compressee / taille_originale) * 100
        else:
            taux = 0.0

        return {
            "taille_originale_bits":  taille_originale,
            "taille_compressee_bits": taille_compressee,
            "taux_compression":       round(taux, 2),
            "codes":                  self.codes
        }


# ── Test standalone ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("MODULE HUFFMAN - TEST")
    print("=" * 55)

    messages_test = [
        "TRANSMISSION SECURISEE CI2CYBER ISMAGI",
        "AAAA",                   # cas dégénéré : un seul symbole
        "AB",                     # cas minimal 2 symboles
        "HELLO CI2CYBER 2025",
    ]

    for message in messages_test:
        print(f"\n--- Message : '{message}' ---")
        codeur = CodeurHuffman()   # nouvelle instance à chaque message

        compresse, padding, codes = codeur.compresser(message)
        stats = codeur.stats_compression(message, compresse)

        print(f"  Taille originale  : {stats['taille_originale_bits']} bits")
        print(f"  Taille compressée : {stats['taille_compressee_bits']} bits")
        print(f"  Taux compression  : {stats['taux_compression']}%")
        print(f"  Table des codes   : { {k: v for k, v in sorted(codes.items())} }")

        decompresse = codeur.decompresser(compresse, padding, len(message))
        ok = (message == decompresse)
        print(f"  Décompressé       : '{decompresse}'")
        print(f"  Décompression OK  : {'✅' if ok else '❌'}")

    # Test cohérence entre deux appels successifs sur la même instance
    print("\n--- Test instance réutilisée (2 messages successifs) ---")
    codeur_shared = CodeurHuffman()

    msg1 = "PREMIER MESSAGE"
    c1, p1, _ = codeur_shared.compresser(msg1)
    d1 = codeur_shared.decompresser(c1, p1, len(msg1))
    print(f"  msg1 OK : {msg1 == d1} → '{d1}'")

    msg2 = "SECOND MESSAGE DIFFERENT"
    c2, p2, _ = codeur_shared.compresser(msg2)
    d2 = codeur_shared.decompresser(c2, p2, len(msg2))
    print(f"  msg2 OK : {msg2 == d2} → '{d2}'")