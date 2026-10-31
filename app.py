"""
Dashboard Streamlit - Système de Communication Sécurisée
Transmission de Données Sécurisée - CI2CYBER ISMAGI
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import time

from modules.huffman import CodeurHuffman
from modules.convolutif import CodeurConvolutif, DecodeurViterbi, CanalBruite, texte_vers_bits
from modules.crypto_crc import ChiffreurAES, CalculateurCRC
from modules.reseau import ReseauSecurise
from modules.pipeline import PipelineTransmission

# ── Configuration Streamlit ────────────────────────────────────────
st.set_page_config(
    page_title="Transmission Sécurisée - CI2CYBER",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS personnalisé ────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1e3a5f, #0d7377);
        color: white;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
    }
    .metric-card {
        background: #f0f4f8;
        border-left: 4px solid #0d7377;
        padding: 10px 15px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .success-box {
        background: #d4edda;
        border: 1px solid #28a745;
        border-radius: 8px;
        padding: 15px;
        color: #155724;
    }
    .error-box {
        background: #f8d7da;
        border: 1px solid #dc3545;
        border-radius: 8px;
        padding: 15px;
        color: #721c24;
    }
    .step-header {
        font-size: 1.1em;
        font-weight: bold;
        color: #1e3a5f;
        border-bottom: 2px solid #0d7377;
        padding-bottom: 5px;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🔐 Système de Transmission Sécurisée</h1>
    <p>Codage Convolutif + AES-256 + CRC + Huffman | CI2CYBER - ISMAGI 2025</p>
</div>
""", unsafe_allow_html=True)

# ── Session State (persistance entre reruns) ───────────────────────
# Paramètres de configuration
if "message" not in st.session_state:
    st.session_state.message = "TRANSMISSION SECURISEE CI2CYBER"
if "mot_de_passe" not in st.session_state:
    st.session_state.mot_de_passe = "CI2CYBER_2025"
if "source" not in st.session_state:
    st.session_state.source = "N0"
if "destination" not in st.session_state:
    st.session_state.destination = "N7"
if "prob_erreur" not in st.session_state:
    st.session_state.prob_erreur = 0.05

# ── CORRECTION BUG 2 : Résultats de transmission persistés ──────────
if "res_emission" not in st.session_state:
    st.session_state.res_emission = None
if "res_reception" not in st.session_state:
    st.session_state.res_reception = None
if "transmission_effectuee" not in st.session_state:
    st.session_state.transmission_effectuee = False
# Paramètres utilisés lors de la dernière transmission (pour affichage de cohérence)
if "last_params" not in st.session_state:
    st.session_state.last_params = {}

# ── Sidebar ────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")

    st.subheader("📡 Réseau")
    reseau_obj = ReseauSecurise()
    noeuds = reseau_obj.get_info_reseau()['noeuds']

    # ── CORRECTION BUG 1 : on lit et stocke immédiatement dans session_state ──
    source = st.selectbox(
        "Nœud Source", noeuds,
        index=noeuds.index(st.session_state.source),
        key="source_select"
    )
    st.session_state.source = source

    destination = st.selectbox(
        "Nœud Destination", noeuds,
        index=noeuds.index(st.session_state.destination),
        key="dest_select"
    )
    st.session_state.destination = destination

    st.subheader("📻 Canal")
    prob_erreur = st.slider(
        "Probabilité d'erreur (p)", 0.0, 0.3,
        st.session_state.prob_erreur, 0.01,
        format="%.2f", key="prob_slider"
    )
    st.session_state.prob_erreur = prob_erreur

    st.subheader("🔑 Sécurité")
    mot_de_passe = st.text_input(
        "Clé AES (mot de passe)",
        value=st.session_state.mot_de_passe,
        type="password", key="mdp_input"
    )
    st.session_state.mot_de_passe = mot_de_passe

    st.subheader("✉️ Message")
    message = st.text_area(
        "Message à transmettre",
        value=st.session_state.message,
        height=80, key="msg_input"
    )
    st.session_state.message = message

    transmettre_btn = st.button("🚀 Transmettre", type="primary",
                                 use_container_width=True)

    st.divider()
    st.subheader("📊 Analyse BER")
    analyser_btn = st.button("📈 Courbe BER", use_container_width=True)

# ── CORRECTION BUG 1 & 2 : Traitement de la transmission ──────────
# On exécute le pipeline ICI, en dehors des tabs,
# en lisant TOUJOURS depuis st.session_state (valeurs fraîches du rerun courant)
if transmettre_btn:
    _message   = st.session_state.message.strip()
    _mdp       = st.session_state.mot_de_passe
    _source    = st.session_state.source
    _dest      = st.session_state.destination
    _prob      = st.session_state.prob_erreur

    if _message:
        with st.spinner("⚡ Transmission en cours..."):
            pipeline = PipelineTransmission(_prob, _mdp)
            res_emission  = pipeline.emettre(_message, _source, _dest)
            res_reception = pipeline.recevoir()

        # Persistance des résultats dans session_state
        st.session_state.res_emission           = res_emission
        st.session_state.res_reception          = res_reception
        st.session_state.transmission_effectuee = True
        # Snapshot des paramètres utilisés → affichés dans Tab 2
        st.session_state.last_params = {
            "message":     _message,
            "mot_de_passe": _mdp,
            "source":      _source,
            "destination": _dest,
            "prob_erreur": _prob,
        }
    else:
        st.warning("⚠️ Le message est vide.")

# ── Onglets principaux ─────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🗺️ Réseau", "📡 Pipeline", "🔐 Crypto & CRC",
    "🌀 Convolutif", "📈 BER"
])

# ════════════════════════════════════════════════════════════════════
# TAB 1 : Visualisation du réseau
# ════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🗺️ Topologie du Réseau Pair-à-Pair")

    # ── CORRECTION BUG 3 : on recrée le réseau et lit source/destination
    # depuis session_state pour refléter les sélections courantes ──────
    reseau = ReseauSecurise()
    G = reseau.get_graphe()
    pos = reseau.get_positions()

    _source_tab1 = st.session_state.source
    _dest_tab1   = st.session_state.destination

    routage = reseau.trouver_chemin_optimal(_source_tab1, _dest_tab1)
    chemin_optimal = routage.get('chemin_optimal', [])

    # Construire le graphe Plotly
    edge_x, edge_y, edge_labels_x, edge_labels_y, edge_labels = [], [], [], [], []
    edge_x_path, edge_y_path = [], []

    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]
        edge_labels_x.append((x0 + x1) / 2)
        edge_labels_y.append((y0 + y1) / 2)
        edge_labels.append(f"w={data['weight']}")

        if u in chemin_optimal and v in chemin_optimal:
            idx_u = chemin_optimal.index(u)
            idx_v = chemin_optimal.index(v)
            if abs(idx_u - idx_v) == 1:
                edge_x_path += [x0, x1, None]
                edge_y_path += [y0, y1, None]

    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]
    node_colors = []
    node_sizes = []
    for n in G.nodes():
        if n == _source_tab1:
            node_colors.append('#28a745')
            node_sizes.append(25)
        elif n == _dest_tab1:
            node_colors.append('#dc3545')
            node_sizes.append(25)
        elif n in chemin_optimal:
            node_colors.append('#fd7e14')
            node_sizes.append(20)
        else:
            node_colors.append('#1e3a5f')
            node_sizes.append(15)

    fig_reseau = go.Figure()
    fig_reseau.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines',
                                     line=dict(width=1.5, color='#adb5bd'),
                                     hoverinfo='none'))
    if edge_x_path:
        fig_reseau.add_trace(go.Scatter(x=edge_x_path, y=edge_y_path, mode='lines',
                                         line=dict(width=4, color='#fd7e14', dash='solid'),
                                         name='Chemin optimal'))
    fig_reseau.add_trace(go.Scatter(
        x=node_x, y=node_y, mode='markers+text',
        marker=dict(size=node_sizes, color=node_colors, line=dict(width=2, color='white')),
        text=list(G.nodes()), textposition='top center',
        textfont=dict(size=12, color='black'),
        hovertext=[f"Nœud {n}" for n in G.nodes()],
    ))
    fig_reseau.update_layout(
        height=400, showlegend=False,
        plot_bgcolor='#f8f9fa', paper_bgcolor='white',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(l=10, r=10, t=10, b=10)
    )
    st.plotly_chart(fig_reseau, use_container_width=True)

    info_reseau = reseau.get_info_reseau()
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Nœuds", info_reseau['nb_noeuds'])
    with col2:
        st.metric("Liens", info_reseau['nb_liens'])
    with col3:
        if routage['succes']:
            # Affichage complet du chemin (pas tronqué)
            st.metric("Chemin optimal", " → ".join(chemin_optimal))
    with col4:
        if routage['succes']:
            st.metric("Distance", routage['distance'])

    # Chemins alternatifs
    if routage['succes'] and len(routage.get('chemins_alternatifs', [])) > 1:
        with st.expander("🔀 Chemins alternatifs"):
            for path, poids in routage['chemins_alternatifs']:
                st.write(f"**{' → '.join(path)}** — coût : `{poids}`")

# ════════════════════════════════════════════════════════════════════
# TAB 2 : Pipeline de transmission
# ════════════════════════════════════════════════════════════════════
with tab2:
    # ── CORRECTION BUG 2 : on lit les résultats depuis session_state ──
    if st.session_state.transmission_effectuee and \
       st.session_state.res_emission is not None and \
       st.session_state.res_reception is not None:

        res_emission  = st.session_state.res_emission
        res_reception = st.session_state.res_reception
        lp            = st.session_state.last_params

        # Bandeau récapitulatif des paramètres utilisés
        st.info(
            f"📨 **Message :** `{lp.get('message', '')}` | "
            f"🔗 **Chemin :** {lp.get('source','')} → {lp.get('destination','')} | "
            f"📻 **p =** {lp.get('prob_erreur', 0):.2f}"
        )
        st.success("✅ Transmission terminée !")

        # Indicateurs globaux
        c1, c2, c3, c4 = st.columns(4)
        e = res_emission['etapes']
        c1.metric("Compression",
                  f"{e['huffman']['taux_compression']}%",
                  delta="Réduit la taille")
        c2.metric("Erreurs canal",
                  f"{e['canal']['nb_erreurs']} bits",
                  delta=f"BER={e['canal']['ber_reel']}")
        c3.metric("Intégrité CRC",
                  "✅ OK" if res_reception['etapes']['crc']['integrite_ok'] else "❌ ERREUR")
        c4.metric("Message récupéré",
                  "✅" if res_reception['integrite_globale'] else "❌")

        st.divider()

        # Pipeline visuel
        st.subheader("🔄 Étapes de la Transmission")
        etapes_noms = ["📨 Message", "🗜️ Huffman", "🔒 AES", "🔢 CRC",
                       "🌀 Convolutif", "📻 Canal", "🌀 Viterbi", "✅ CRC", "🔓 AES", "📨 Récupéré"]

        fig_flux = go.Figure()
        couleurs = ['#0d7377'] * 5 + ['#dc3545'] + ['#28a745'] * 4

        for i, (nom, coul) in enumerate(zip(etapes_noms, couleurs)):
            fig_flux.add_trace(go.Scatter(
                x=[i], y=[0], mode='markers+text',
                marker=dict(size=40, color=coul, symbol='square'),
                text=[nom.split(' ', 1)[-1][:8]], textposition='bottom center',
                textfont=dict(size=9), showlegend=False
            ))
            if i < len(etapes_noms) - 1:
                fig_flux.add_annotation(
                    x=i + 0.5, y=0, ax=i, ay=0,
                    xref='x', yref='y', axref='x', ayref='y',
                    showarrow=True, arrowhead=2, arrowsize=1.5,
                    arrowcolor='#6c757d'
                )

        fig_flux.update_layout(
            height=150, showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                       range=[-0.5, len(etapes_noms) - 0.5]),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                       range=[-0.5, 0.5]),
            margin=dict(l=10, r=10, t=10, b=50),
            plot_bgcolor='white'
        )
        st.plotly_chart(fig_flux, use_container_width=True)

        # Détails par étape
        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("**📤 ÉMISSION**")
            with st.expander("🗜️ Huffman (Compression)", expanded=True):
                h = e['huffman']
                st.write(f"Avant : **{h['taille_avant_bits']} bits**")
                st.write(f"Après : **{h['taille_apres_bits']} bits**")
                st.write(f"Taux  : **{h['taux_compression']}%** de réduction")

            with st.expander("🔒 AES-256 (Chiffrement)"):
                a = e['aes']
                st.write(f"Taille avant : {a['taille_avant']} bytes")
                st.write(f"Taille après : {a['taille_apres']} bytes")
                st.code(f"IV : {a['iv_hex'][:32]}...", language=None)
                st.code(f"Chiffré : {a['donnees_hex_preview']}", language=None)

            with st.expander("🔢 CRC-32"):
                c = e['crc']
                st.write(f"CRC calculé : `{c['crc_hex']}`")
                st.write(f"Taille payload + CRC : {c['taille_apres']} bytes")

            with st.expander("🌀 Encodage Convolutif R=1/2"):
                cv = e['convolutif']
                st.write(f"Bits avant : {cv['nb_bits_avant']}")
                st.write(f"Bits après : {cv['nb_bits_apres']} (+100%)")
                st.write(f"Polynômes : g1=1+D², g2=1+D+D²")
                st.code(f"Entrée : {cv['preview_avant']}", language=None)
                st.code(f"Sortie : {cv['preview_apres']}", language=None)

            with st.expander("📻 Canal Bruité"):
                can = e['canal']
                st.write(f"Prob. erreur : **{can['prob_erreur_canal']}**")
                st.write(f"Bits transmis : {can['nb_bits']}")
                st.write(f"Erreurs introduites : **{can['nb_erreurs']}**")
                st.write(f"BER réel : **{can['ber_reel']}**")
                if can['positions_erreurs']:
                    st.write(f"Positions : {can['positions_erreurs']}")

        with col_b:
            st.markdown("**📥 RÉCEPTION**")
            re = res_reception['etapes']

            with st.expander("🌀 Décodage Viterbi", expanded=True):
                v = re['viterbi']
                st.write(f"Bits décodés : {v['nb_bits_decodes']}")
                st.write(f"États du treillis : {v['nb_etats_treillis']}")
                st.write(f"Métrique finale : {v['metrique_finale']}")

            with st.expander("✅ Vérification CRC"):
                crc_r = re['crc']
                if crc_r['integrite_ok']:
                    st.success("Intégrité vérifiée ✅")
                else:
                    st.error("Intégrité compromise ❌")
                st.write(f"CRC calculé : `{crc_r['crc_calcule']}`")
                st.write(f"CRC reçu    : `{crc_r['crc_recu']}`")

            with st.expander("🔓 Déchiffrement AES"):
                aes_r = re['aes']
                if aes_r['dechiffrement_ok']:
                    st.success("Déchiffrement réussi ✅")
                else:
                    st.error("Échec déchiffrement ❌")

            with st.expander("📨 Message final"):
                if res_reception['integrite_globale']:
                    st.markdown(f"""
                    <div class="success-box">
                    <b>Message décodé :</b><br>
                    <code>{res_reception['message_decode']}</code>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="error-box">
                    Message partiellement corrompu.<br>
                    <code>{res_reception['message_decode']}</code>
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.info("👈 Configure les paramètres dans la sidebar et clique sur **🚀 Transmettre**")
        st.markdown("""
        ### 🔗 Architecture de la chaîne de transmission
        ```
        Message texte
            ↓ [1] Compression Huffman     → Réduit la taille
            ↓ [2] Chiffrement AES-256     → Sécurise le contenu
            ↓ [3] CRC-32                  → Calcule la somme de contrôle
            ↓ [4] Encodage Convolutif R=½ → Ajoute la redondance
            ↓ ~~~ Canal Bruité ~~~        → Erreurs aléatoires
            ↓ [5] Décodage Viterbi        → Corrige les erreurs
            ↓ [6] Vérification CRC        → Détecte les erreurs résiduelles
            ↓ [7] Déchiffrement AES       → Récupère les données claires
            ↓ [8] Décompression Huffman   → Récupère le message original
            Message récupéré ✓
        ```
        """)

# ════════════════════════════════════════════════════════════════════
# TAB 3 : Crypto & CRC
# ════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("🔐 Démonstration Cryptographie & CRC")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🔢 CRC - Division Polynomiale")
        st.markdown("*(Exemple interactif basé sur le cours Chap. 4)*")

        msg_crc = st.text_input("Message binaire", value="1101", key="msg_crc")
        gen_crc = st.text_input("Polynôme générateur", value="1011", key="gen_crc")

        if st.button("Calculer CRC"):
            if all(c in '01' for c in msg_crc) and all(c in '01' for c in gen_crc):
                calc = CalculateurCRC()
                res = calc.demo_division_polynomiale(msg_crc, gen_crc)

                st.success(f"**CRC = {res['crc']}**")
                st.info(f"Message final à transmettre : `{res['message_final']}`")

                with st.expander("📋 Étapes de la division"):
                    for i, etape in enumerate(res['etapes']):
                        st.code(
                            f"Étape {i+1}:\n"
                            f"  Avant   : {etape['avant']}\n"
                            f"  Diviseur: {etape['diviseur']}\n"
                            f"  Après   : {etape['apres']}",
                            language=None
                        )

    with col2:
        st.markdown("### 🔒 AES-256 - Chiffrement Symétrique")

        texte_aes = st.text_area("Texte à chiffrer",
                                  value="Message confidentiel CI2CYBER",
                                  height=80, key="texte_aes")
        mdp_aes = st.text_input("Mot de passe", value="cle_secrete_123",
                                  type="password", key="mdp_aes")

        if st.button("Chiffrer / Déchiffrer"):
            aes = ChiffreurAES()
            res_chiffre = aes.chiffrer(texte_aes, mdp_aes)

            st.markdown("**Résultat du chiffrement :**")
            st.code(f"IV          : {res_chiffre['iv'].hex()}", language=None)
            st.code(f"Chiffré(hex): {res_chiffre['donnees_chiffrees'].hex()}", language=None)
            st.code(f"Clé (SHA256): {res_chiffre['cle_hex']}", language=None)

            decode = aes.dechiffrer(
                res_chiffre['iv'],
                res_chiffre['donnees_chiffrees'],
                mdp_aes,
                res_chiffre['taille_originale']
            )
            st.success(f"✅ Déchiffré : `{decode}`")

            fig_tailles = go.Figure(go.Bar(
                x=['Original', 'Chiffré'],
                y=[res_chiffre['taille_originale'], res_chiffre['taille_chiffree']],
                marker_color=['#28a745', '#dc3545'],
                text=[f"{res_chiffre['taille_originale']}B", f"{res_chiffre['taille_chiffree']}B"],
                textposition='auto'
            ))
            fig_tailles.update_layout(height=200, margin=dict(l=10, r=10, t=10, b=10),
                                       yaxis_title="Bytes")
            st.plotly_chart(fig_tailles, use_container_width=True)

# ════════════════════════════════════════════════════════════════════
# TAB 4 : Codage Convolutif
# ════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🌀 Codage Convolutif R=1/2, K=3 + Décodage Viterbi")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### 📊 Encodeur")
        bits_input = st.text_input("Bits d'entrée (ex: 1001)",
                                    value="10011010", key="bits_conv")

        if st.button("Encoder + Canal + Viterbi"):
            try:
                bits = [int(b) for b in bits_input if b in '01']
                if len(bits) < 1:
                    st.error("Entrez des bits valides")
                else:
                    codeur_demo  = CodeurConvolutif()
                    canal_demo   = CanalBruite(st.session_state.prob_erreur)
                    decodeur_demo = DecodeurViterbi()

                    code, flush = codeur_demo.encoder_avec_terminaison(bits)
                    st.success(f"**Entrée** : {bits}")
                    st.success(f"**Sortie encodée** : {code}")
                    st.info(f"Rendement R=1/2 : {len(bits)} bits → {len(code)} bits")

                    recus, erreurs = canal_demo.transmettre(code)
                    st.warning(f"**Après canal** (p={st.session_state.prob_erreur}): {recus}")
                    st.warning(f"Erreurs aux positions : {erreurs if erreurs else 'Aucune'}")

                    decoded, hist, chemin = decodeur_demo.decoder(recus, len(bits))
                    correct = decoded == bits
                    if correct:
                        st.success(f"**Viterbi décodé** : {decoded} ✅")
                    else:
                        st.error(f"**Viterbi décodé** : {decoded} ❌ (original: {bits})")

                    st.markdown("**Évolution des métriques de chemin :**")
                    fig_treillis = go.Figure()
                    etats = ['00', '01', '10', '11']
                    couleurs_etats = ['#0d7377', '#fd7e14', '#dc3545', '#6f42c1']

                    for idx, (etat_tuple, couleur) in enumerate(
                            zip([(0,0),(0,1),(1,0),(1,1)], couleurs_etats)):
                        metriques_etat = []
                        for h in hist:
                            m = h.get(etat_tuple, float('inf'))
                            metriques_etat.append(m if m != float('inf') else None)

                        fig_treillis.add_trace(go.Scatter(
                            y=metriques_etat, x=list(range(len(hist))),
                            mode='lines+markers', name=f"État {etats[idx]}",
                            line=dict(color=couleur, width=2),
                            connectgaps=False
                        ))

                    fig_treillis.update_layout(
                        height=300, xaxis_title="Étape",
                        yaxis_title="Métrique cumulée",
                        legend=dict(orientation='h', yanchor='bottom', y=1),
                        margin=dict(l=10, r=10, t=30, b=30)
                    )
                    st.plotly_chart(fig_treillis, use_container_width=True)

            except Exception as ex:
                st.error(f"Erreur : {ex}")

    with col2:
        st.markdown("### 📐 Polynômes générateurs")
        st.latex(r"g_1(D) = 1 + D^2 \quad \rightarrow \quad [1, 0, 1]")
        st.latex(r"g_2(D) = 1 + D + D^2 \quad \rightarrow \quad [1, 1, 1]")

        st.markdown("### 🔄 Équations du codeur")
        st.latex(r"x_j^1 = s_j + s_{j-2}")
        st.latex(r"x_j^2 = s_j + s_{j-1} + s_{j-2}")

        st.markdown("### 📊 Diagramme d'états")
        st.markdown("""
        | État courant | Entrée | État suivant | Sortie |
        |:---:|:---:|:---:|:---:|
        | 00 | 0 | 00 | **00** |
        | 00 | 1 | 10 | **11** |
        | 10 | 0 | 01 | **10** |
        | 10 | 1 | 11 | **01** |
        | 01 | 0 | 00 | **11** |
        | 01 | 1 | 10 | **00** |
        | 11 | 0 | 01 | **01** |
        | 11 | 1 | 11 | **10** |
        """)

        st.info(f"**Distance minimale** : d_min = 5\n\n"
                f"**Capacité de correction** : jusqu'à ⌊(5-1)/2⌋ = **2 erreurs**")

# ════════════════════════════════════════════════════════════════════
# TAB 5 : Courbe BER
# ════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("📈 Taux d'Erreur Binaire (BER) vs Probabilité d'erreur du canal")

    if analyser_btn:
        with st.spinner("Calcul du BER en cours (plusieurs essais)..."):
            # On lit le message courant depuis session_state
            msg_ber = st.session_state.message.strip() or "TEST BER ANALYSE"
            pipeline_ber = PipelineTransmission(0.0, st.session_state.mot_de_passe)
            ber_data = pipeline_ber.evaluer_ber(msg_ber, 0.0, 0.25, 12, 8)

        fig_ber = go.Figure()

        fig_ber.add_trace(go.Scatter(
            x=ber_data['probabilites'],
            y=ber_data['ber_sans_codage'],
            mode='lines+markers',
            name='Sans codage (canal brut)',
            line=dict(color='#dc3545', width=2, dash='dash'),
            marker=dict(size=8, symbol='circle')
        ))

        fig_ber.add_trace(go.Scatter(
            x=ber_data['probabilites'],
            y=ber_data['ber_avec_viterbi'],
            mode='lines+markers',
            name='Avec Convolutif + Viterbi',
            line=dict(color='#28a745', width=3),
            marker=dict(size=8, symbol='diamond')
        ))

        fig_ber.add_trace(go.Scatter(
            x=ber_data['probabilites'],
            y=ber_data['probabilites'],
            mode='lines',
            name='Référence (BER = p)',
            line=dict(color='#6c757d', width=1, dash='dot')
        ))

        fig_ber.update_layout(
            height=450,
            xaxis_title="Probabilité d'erreur du canal (p)",
            yaxis_title="Taux d'Erreur Binaire (BER)",
            legend=dict(orientation='v', x=0.01, y=0.99),
            plot_bgcolor='#f8f9fa',
            xaxis=dict(gridcolor='#dee2e6'),
            yaxis=dict(gridcolor='#dee2e6')
        )
        st.plotly_chart(fig_ber, use_container_width=True)

        col1, col2, col3 = st.columns(3)
        ber_sans = ber_data['ber_sans_codage']
        ber_avec = ber_data['ber_avec_viterbi']
        idx_mid  = len(ber_sans) // 2

        with col1:
            st.metric("BER sans codage (p≈0.1)", f"{ber_sans[idx_mid]:.4f}")
        with col2:
            st.metric("BER avec Viterbi (p≈0.1)",
                      f"{ber_avec[idx_mid]:.4f}",
                      delta=f"{(ber_avec[idx_mid]-ber_sans[idx_mid]):.4f}")
        with col3:
            if ber_sans[idx_mid] > 0:
                gain = (1 - ber_avec[idx_mid] / ber_sans[idx_mid]) * 100
                st.metric("Gain de codage", f"{gain:.1f}%")

        st.info(f"""
        **Message analysé :** `{msg_ber}`  
        **Interprétation :** Le codage convolutif R=1/2 avec décodage Viterbi 
        réduit significativement le BER pour des probabilités d'erreur canal modérées.
        La distance minimale d_min=5 permet de corriger jusqu'à 2 erreurs par bloc.
        """)
    else:
        st.info("👈 Clique sur **📈 Courbe BER** dans la sidebar pour lancer l'analyse")
        st.markdown("""
        La courbe BER compare :
        - **Rouge (pointillé)** : transmission sans protection (BER ≈ p)
        - **Vert (plein)** : transmission avec codage convolutif R=1/2 + Viterbi
        - **Gris (pointillé)** : référence théorique BER = p
        
        Le gain de codage montre l'efficacité du codage convolutif.
        """)

# Footer
st.divider()
st.markdown("""
<div style='text-align:center; color:#6c757d; font-size:0.85em;'>
    CI2CYBER | ISMAGI 2025 | Transmission de Données Sécurisée<br>
    Huffman + AES-256 + CRC-32 + Codage Convolutif (R=1/2, K=3) + Viterbi + Dijkstra
</div>
""", unsafe_allow_html=True)