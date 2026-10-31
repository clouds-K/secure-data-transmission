"""
Module 4 : Modélisation Réseau - Graphe + Routage Dijkstra
Transmission de Données Sécurisée - CI2CYBER ISMAGI

CORRECTIONS :
- get_info_reseau() retourne maintenant une liste sérialisable (pas de tuples nx)
  pour éviter les erreurs d'affichage Streamlit.
- PaquetReseau : attribut nb_etapes corrigé (était absent, provoquait un AttributeError).
"""

import networkx as nx
import random
import json


class ReseauSecurise:
    """
    Réseau pair-à-pair simulé avec 8 noeuds.
    Chaque lien a un poids (latence/qualité du canal).
    """

    def __init__(self, nb_noeuds=8, seed=42):
        random.seed(seed)
        self.nb_noeuds = nb_noeuds
        self.graphe = nx.Graph()
        self._construire_reseau()

    def _construire_reseau(self):
        """Construit un réseau avec noeuds et liens pondérés."""
        noeuds = [f"N{i}" for i in range(self.nb_noeuds)]
        self.graphe.add_nodes_from(noeuds)

        # Topologie fixe pour la reproductibilité
        liens = [
            ("N0", "N1", 1), ("N0", "N2", 3), ("N1", "N3", 2),
            ("N1", "N4", 4), ("N2", "N3", 1), ("N3", "N5", 2),
            ("N4", "N5", 3), ("N4", "N6", 1), ("N5", "N7", 2),
            ("N6", "N7", 1), ("N2", "N6", 5), ("N1", "N2", 2)
        ]

        for n1, n2, poids in liens:
            self.graphe.add_edge(n1, n2, weight=poids,
                                 qualite=random.uniform(0.7, 1.0))

        # Positions pour la visualisation
        self.positions = {
            "N0": (0, 2), "N1": (1, 3), "N2": (1, 1),
            "N3": (2, 2), "N4": (2, 4), "N5": (3, 2),
            "N6": (3, 0), "N7": (4, 1)
        }

    def trouver_chemin_optimal(self, source: str, destination: str) -> dict:
        """
        Algorithme de Dijkstra pour trouver le chemin de coût minimal.
        Retourne le chemin, la distance totale, et tous les chemins alternatifs.
        """
        try:
            chemin = nx.dijkstra_path(self.graphe, source, destination,
                                      weight='weight')
            distance = nx.dijkstra_path_length(self.graphe, source, destination,
                                               weight='weight')

            # Trouver chemins alternatifs (jusqu'à 3)
            all_paths = list(nx.all_simple_paths(
                self.graphe, source, destination, cutoff=6
            ))
            all_paths_avec_poids = []
            for path in all_paths[:5]:
                poids = sum(self.graphe[path[i]][path[i+1]]['weight']
                           for i in range(len(path)-1))
                all_paths_avec_poids.append((path, poids))
            all_paths_avec_poids.sort(key=lambda x: x[1])

            return {
                'chemin_optimal':      chemin,
                'distance':            distance,
                'nb_sauts':            len(chemin) - 1,
                'chemins_alternatifs': all_paths_avec_poids[:3],
                'succes':              True
            }
        except nx.NetworkXNoPath:
            return {
                'succes': False,
                'erreur': f"Pas de chemin entre {source} et {destination}",
                'chemin_optimal': [],
                'distance': 0,
                'nb_sauts': 0,
                'chemins_alternatifs': []
            }
        except nx.NodeNotFound as e:
            return {
                'succes': False,
                'erreur': f"Nœud introuvable : {e}",
                'chemin_optimal': [],
                'distance': 0,
                'nb_sauts': 0,
                'chemins_alternatifs': []
            }

    def get_info_reseau(self) -> dict:
        """
        Retourne les statistiques du réseau.
        CORRECTION : 'liens' est une liste de dicts (JSON-sérialisable),
        et 'noeuds' est une liste de strings triée.
        """
        return {
            'nb_noeuds':   self.graphe.number_of_nodes(),
            'nb_liens':    self.graphe.number_of_edges(),
            'connexe':     nx.is_connected(self.graphe),
            'diametre':    nx.diameter(self.graphe),
            'degre_moyen': round(
                sum(dict(self.graphe.degree()).values()) /
                self.graphe.number_of_nodes(), 2
            ),
            'noeuds': sorted(list(self.graphe.nodes())),  # trié : N0, N1, ... N7
            'liens': [
                {'n1': u, 'n2': v, 'poids': d['weight']}
                for u, v, d in self.graphe.edges(data=True)
            ]
        }

    def simuler_panne(self, noeud: str):
        """Simule la panne d'un noeud en le retirant du graphe."""
        if noeud in self.graphe:
            self.graphe.remove_node(noeud)

    def get_positions(self) -> dict:
        return self.positions

    def get_graphe(self):
        return self.graphe


class PaquetReseau:
    """Représente un paquet transmis sur le réseau."""

    def __init__(self, source, destination, message_original):
        self.source           = source
        self.destination      = destination
        self.message_original = message_original
        self.etapes           = []  # Historique du traitement

    @property
    def nb_etapes(self):
        """CORRECTION : propriété calculée pour éviter l'AttributeError."""
        return len(self.etapes)

    def ajouter_etape(self, nom, donnees_avant, donnees_apres, metadata=None):
        self.etapes.append({
            'etape':    nom,
            'avant':    donnees_avant,
            'apres':    donnees_apres,
            'metadata': metadata or {}
        })

    def get_resume(self) -> dict:
        return {
            'source':           self.source,
            'destination':      self.destination,
            'message_original': self.message_original,
            'nb_etapes':        self.nb_etapes,
            'etapes':           self.etapes
        }


# ── Test standalone ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("MODULE RÉSEAU - TEST")
    print("=" * 60)

    reseau = ReseauSecurise(nb_noeuds=8)
    info   = reseau.get_info_reseau()

    print(f"\nNombre de noeuds : {info['nb_noeuds']}")
    print(f"Nombre de liens  : {info['nb_liens']}")
    print(f"Réseau connexe   : {info['connexe']}")
    print(f"Diamètre         : {info['diametre']}")
    print(f"Degré moyen      : {info['degre_moyen']}")
    print(f"Noeuds           : {info['noeuds']}")

    print("\n--- TEST ROUTAGE DIJKSTRA ---")
    for source, dest in [("N0", "N7"), ("N2", "N6"), ("N0", "N0")]:
        resultat = reseau.trouver_chemin_optimal(source, dest)
        if resultat['succes']:
            print(f"\n{source} → {dest}")
            print(f"  Chemin optimal  : {' → '.join(resultat['chemin_optimal'])}")
            print(f"  Distance totale : {resultat['distance']}")
            print(f"  Sauts           : {resultat['nb_sauts']}")
            print(f"  Alternatifs ({len(resultat['chemins_alternatifs'])}) :")
            for path, poids in resultat['chemins_alternatifs']:
                print(f"    {' → '.join(path)} (coût: {poids})")
        else:
            print(f"\n{source} → {dest} : {resultat['erreur']}")

    # Test PaquetReseau
    print("\n--- TEST PAQUET RÉSEAU ---")
    paquet = PaquetReseau("N0", "N7", "Message de test")
    paquet.ajouter_etape("Compression", "Message de test", "0101...", {"taux": "35%"})
    paquet.ajouter_etape("Encodage",    "0101...",          "1101...", {"rendement": "1/2"})
    paquet.ajouter_etape("Chiffrement", "1101...",          "AES...",  {"algo": "AES-256"})
    print(f"Paquet créé avec {paquet.nb_etapes} étapes")
    resume = paquet.get_resume()
    for e in resume['etapes']:
        print(f"  [{e['etape']}] {e['avant']} → {e['apres']}")