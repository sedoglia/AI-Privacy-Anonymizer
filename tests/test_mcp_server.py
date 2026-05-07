"""Test MCP Server stdio — protocollo JSON-RPC 2.0 con dati reali italiani.

Copre:
- handle_request() unit test per ogni metodo JSON-RPC
- Forma della risposta (envelope, id, result/error)
- Tool anonymize_text con PII italiani reali (CF, IBAN, email, tel, IP, P.IVA, targa, TS)
- Trasporto stdio via subprocess (main loop stdin→stdout)
- Casi limite: tool sconosciuto, metodo sconosciuto, id None, testo senza PII, testo vuoto
"""
from __future__ import annotations

import json
import subprocess
import sys

from privacy_anonymizer.mcp_server import handle_request


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _call(text: str) -> dict:
    """Shortcut: invia tools/call anonymize_text con il testo dato."""
    return handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "anonymize_text", "arguments": {"text": text}},
    })


def _extract_text(response: dict) -> str:
    return response["result"]["content"][0]["text"]


def _counts(response: dict) -> dict:
    return response["result"]["structuredContent"]["counts"]


# ===========================================================================
# 1. Metodo: initialize
# ===========================================================================

def test_initialize_returns_protocol_version() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert resp["result"]["protocolVersion"] == "2024-11-05"


def test_initialize_returns_server_info() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    info = resp["result"]["serverInfo"]
    assert info["name"] == "ai-privacy-anonymizer"
    assert "version" in info


def test_initialize_returns_tools_capability() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert "tools" in resp["result"]["capabilities"]


def test_initialize_envelope_is_jsonrpc_2() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 42, "method": "initialize"})
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42
    assert "result" in resp
    assert "error" not in resp


# ===========================================================================
# 2. Metodo: tools/list
# ===========================================================================

def test_tools_list_returns_anonymize_text_tool() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tools = resp["result"]["tools"]
    names = [t["name"] for t in tools]
    assert "anonymize_text" in names


def test_tools_list_tool_has_required_schema_fields() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tool = next(t for t in resp["result"]["tools"] if t["name"] == "anonymize_text")
    assert "description" in tool
    assert "inputSchema" in tool
    schema = tool["inputSchema"]
    assert schema["type"] == "object"
    assert "text" in schema["properties"]
    assert "text" in schema["required"]


def test_tools_list_envelope() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 7
    assert "result" in resp


# ===========================================================================
# 3. Metodo: tools/call — forma della risposta
# ===========================================================================

def test_tools_call_response_has_content_array() -> None:
    resp = _call("CF RSSMRA80A01L219M")
    assert "content" in resp["result"]
    assert isinstance(resp["result"]["content"], list)
    assert len(resp["result"]["content"]) >= 1


def test_tools_call_content_item_has_type_and_text() -> None:
    resp = _call("CF RSSMRA80A01L219M")
    item = resp["result"]["content"][0]
    assert item["type"] == "text"
    assert isinstance(item["text"], str)


def test_tools_call_response_has_structured_content_counts() -> None:
    resp = _call("CF RSSMRA80A01L219M")
    assert "structuredContent" in resp["result"]
    assert "counts" in resp["result"]["structuredContent"]
    assert isinstance(_counts(resp), dict)


def test_tools_call_envelope_id_matches_request() -> None:
    resp = handle_request({
        "jsonrpc": "2.0", "id": 99,
        "method": "tools/call",
        "params": {"name": "anonymize_text", "arguments": {"text": "CF RSSMRA80A01L219M"}},
    })
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 99
    assert "result" in resp
    assert "error" not in resp


# ===========================================================================
# 4. tools/call — dati PII italiani reali
# ===========================================================================

def test_codice_fiscale_rimosso_dal_testo(  ) -> None:
    cf = "RSSMRA80A01L219M"
    resp = _call(f"Dipendente CF {cf}, cedolino aprile 2024")
    assert cf not in _extract_text(resp)
    assert _counts(resp).get("CODICE_FISCALE", 0) >= 1


def test_iban_rimosso_dal_testo() -> None:
    iban = "IT60X0542811101000000123456"
    resp = _call(f"Coordinate bancarie IBAN {iban}")
    assert iban not in _extract_text(resp)
    assert _counts(resp).get("IBAN_IT", 0) >= 1


def test_email_rimossa_dal_testo() -> None:
    email = "mario.rossi@azienda.it"
    resp = _call(f"Contattare {email} per informazioni")
    assert email not in _extract_text(resp)
    assert _counts(resp).get("EMAIL", 0) >= 1


def test_telefono_rimosso_dal_testo() -> None:
    tel = "3401234567"
    resp = _call(f"Chiamare il {tel}")
    assert tel not in _extract_text(resp)
    assert any(_counts(resp).get(k, 0) >= 1 for k in ("TELEFONO_IT", "CELL_IT", "TEL_IT"))


def test_ip_address_rimosso_dal_testo() -> None:
    ip = "192.168.1.10"
    resp = _call(f"Server prod IP {ip} non raggiungibile")
    assert ip not in _extract_text(resp)
    assert _counts(resp).get("IP_ADDRESS", 0) >= 1


def test_partita_iva_rimossa_dal_testo() -> None:
    piva = "01114601006"
    resp = _call(f"Fornitore P.IVA {piva}")
    assert piva not in _extract_text(resp)
    assert _counts(resp).get("PARTITA_IVA", 0) >= 1


def test_targa_rimossa_dal_testo() -> None:
    targa = "AB123CD"
    resp = _call(f"Veicolo targa {targa} intestato al sig. Rossi")
    assert targa not in _extract_text(resp)
    assert _counts(resp).get("TARGA_IT", 0) >= 1


def test_tessera_sanitaria_rimossa_dal_testo() -> None:
    ts = "80380030001234567890"
    resp = _call(f"Tessera sanitaria {ts}")
    assert ts not in _extract_text(resp)
    assert _counts(resp).get("TESSERA_SANITARIA", 0) >= 1


def test_pec_rimossa_dal_testo() -> None:
    pec = "studio.rossi@legalmail.pec.it"
    resp = _call(f"PEC aziendale {pec}")
    assert pec not in _extract_text(resp)
    assert _counts(resp).get("PEC", 0) >= 1


def test_documento_identita_rimosso_dal_testo() -> None:
    ci = "AX1234567"
    resp = _call(f"Carta d'identità {ci} di Anna Bianchi")
    assert ci not in _extract_text(resp)
    assert _counts(resp).get("CARTA_IDENTITA", 0) >= 1


# ===========================================================================
# 5. tools/call — testi multi-entità reali (scenari documento completo)
# ===========================================================================

def test_cedolino_paga_tutte_le_entita_rimosse() -> None:
    testo = (
        "Cedolino aprile 2024 — Mario Rossi CF RSSMRA80A01L219M\n"
        "Stipendio netto 2.450,00 EUR su IBAN IT60X0542811101000000123456\n"
        "Contatto: mario.rossi@azienda.it — tel 3401234567"
    )
    resp = _call(testo)
    anonimizzato = _extract_text(resp)
    c = _counts(resp)

    assert "RSSMRA80A01L219M" not in anonimizzato
    assert "IT60X0542811101000000123456" not in anonimizzato
    assert "mario.rossi@azienda.it" not in anonimizzato
    assert "3401234567" not in anonimizzato
    assert c.get("CODICE_FISCALE", 0) >= 1
    assert c.get("IBAN_IT", 0) >= 1
    assert c.get("EMAIL", 0) >= 1


def test_contratto_fornitura_tutte_le_entita_rimosse() -> None:
    testo = (
        "Contratto n. 2024/CF/0042\n"
        "Fornitore: ACME Srl P.IVA 01114601006, PEC studio@legalmail.pec.it\n"
        "Coordinate: IBAN IT60X0542811101000000123456\n"
        "Referente: +39 011 1234567"
    )
    resp = _call(testo)
    anonimizzato = _extract_text(resp)
    c = _counts(resp)

    assert "01114601006" not in anonimizzato
    assert "IT60X0542811101000000123456" not in anonimizzato
    assert c.get("PARTITA_IVA", 0) >= 1
    assert c.get("IBAN_IT", 0) >= 1


def test_log_it_tutte_le_entita_rimosse() -> None:
    testo = (
        "2024-04-30 12:34:56 — Login fallito per user@acme.it da IP 10.0.0.42\n"
        "Tentativo da 172.16.0.5 bloccato"
    )
    resp = _call(testo)
    anonimizzato = _extract_text(resp)
    c = _counts(resp)

    assert "user@acme.it" not in anonimizzato
    assert "10.0.0.42" not in anonimizzato
    assert "172.16.0.5" not in anonimizzato
    assert c.get("EMAIL", 0) >= 1
    assert c.get("IP_ADDRESS", 0) >= 2


def test_counts_multipli_stessa_categoria() -> None:
    # Due CF distinti nello stesso testo
    testo = (
        "Dipendente 1: CF RSSMRA80A01L219M, "
        "Dipendente 2: CF BNCNNA75T41F205Y"
    )
    resp = _call(testo)
    c = _counts(resp)
    assert c.get("CODICE_FISCALE", 0) >= 2


def test_testo_senza_pii_strutturati_non_produce_pattern_entities() -> None:
    # Verifica che nessun pattern italiano (CF, IBAN, email, tel, IP, P.IVA…) scatti
    # su un testo privo di dati strutturati. GLiNER può comunque rilevare nomi/org.
    resp = _call("Il totale fatture del terzo trimestre ammonta a 142.500 EUR (IVA inclusa).")
    c = _counts(resp)
    pattern_categories = {
        "CODICE_FISCALE", "IBAN_IT", "EMAIL", "TELEFONO_IT", "IP_ADDRESS",
        "PARTITA_IVA", "TARGA_IT", "TESSERA_SANITARIA", "PEC", "MATRICOLA_INPS",
    }
    detected_pattern = {cat for cat in pattern_categories if c.get(cat, 0) > 0}
    assert not detected_pattern, f"Pattern PII inattesi rilevati: {detected_pattern}"


def test_testo_vuoto_non_crasha() -> None:
    resp = _call("")
    assert "result" in resp
    assert _counts(resp) == {}


def test_testo_unicode_italiano_risposta_valida() -> None:
    # Verifica che caratteri unicode italiani (accenti, apostrofi) non
    # corrompano il testo nella risposta JSON-RPC. La email è PII e viene
    # rimossa; parole generiche (non nomi) sopravvivono.
    testo = "L'appuntamento è fissato per venerdì; contattare dott@clinica.it"
    resp = _call(testo)
    anonimizzato = _extract_text(resp)
    # La email deve essere anonimizzata
    assert "dott@clinica.it" not in anonimizzato
    # La risposta deve essere una stringa non vuota con caratteri italiani intatti
    assert isinstance(anonimizzato, str) and len(anonimizzato) > 0
    assert "appuntamento" in anonimizzato


# ===========================================================================
# 6. Gestione errori
# ===========================================================================

def test_unknown_tool_name_returns_error() -> None:
    resp = handle_request({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": "tool_inesistente", "arguments": {"text": "test"}},
    })
    assert "error" in resp
    assert "result" not in resp
    assert resp["error"]["code"] == -32601


def test_unsupported_method_returns_error() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "metodo/inesistente"})
    assert "error" in resp
    assert resp["error"]["code"] == -32601
    assert "metodo/inesistente" in resp["error"]["message"]


def test_none_id_propagated_in_error() -> None:
    resp = handle_request({"jsonrpc": "2.0", "method": "metodo/inesistente"})
    assert resp["id"] is None
    assert "error" in resp


def test_none_id_propagated_in_result() -> None:
    resp = handle_request({"jsonrpc": "2.0", "method": "initialize"})
    assert resp["id"] is None
    assert "result" in resp


def test_error_response_never_has_result_field() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "sconosciuto", "arguments": {}}})
    assert "result" not in resp


def test_success_response_never_has_error_field() -> None:
    resp = _call("CF RSSMRA80A01L219M")
    assert "error" not in resp


# ===========================================================================
# 7. Trasporto stdio — subprocess (main loop)
# ===========================================================================

def _mcp_session(requests: list[dict]) -> list[dict]:
    """Lancia il server MCP come sottoprocesso e invia le richieste via stdin.
    Restituisce la lista di risposte parse."""
    stdin_data = "\n".join(json.dumps(r, ensure_ascii=False) for r in requests) + "\n"
    result = subprocess.run(
        [sys.executable, "-m", "privacy_anonymizer.mcp_server"],
        input=stdin_data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, f"MCP process exited with code {result.returncode}: {result.stderr}"
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    return [json.loads(l) for l in lines]


def test_stdio_initialize_handshake() -> None:
    [resp] = _mcp_session([{"jsonrpc": "2.0", "id": 1, "method": "initialize"}])
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["id"] == 1


def test_stdio_tools_list() -> None:
    [resp] = _mcp_session([{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    names = [t["name"] for t in resp["result"]["tools"]]
    assert "anonymize_text" in names


def test_stdio_anonymize_codice_fiscale() -> None:
    cf = "RSSMRA80A01L219M"
    [resp] = _mcp_session([{
        "jsonrpc": "2.0", "id": 3,
        "method": "tools/call",
        "params": {"name": "anonymize_text", "arguments": {"text": f"CF {cf}"}},
    }])
    assert cf not in resp["result"]["content"][0]["text"]
    assert resp["result"]["structuredContent"]["counts"].get("CODICE_FISCALE", 0) >= 1


def test_stdio_anonymize_iban() -> None:
    iban = "IT60X0542811101000000123456"
    [resp] = _mcp_session([{
        "jsonrpc": "2.0", "id": 4,
        "method": "tools/call",
        "params": {"name": "anonymize_text", "arguments": {"text": f"IBAN {iban}"}},
    }])
    assert iban not in resp["result"]["content"][0]["text"]


def test_stdio_multiple_requests_in_sequence() -> None:
    """Verifica che il loop stdio gestisca più richieste sulla stessa sessione."""
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"name": "anonymize_text", "arguments": {
                "text": "CF RSSMRA80A01L219M email mario@azienda.it"
            }},
        },
    ]
    responses = _mcp_session(requests)

    assert len(responses) == 3
    assert responses[0]["id"] == 1
    assert responses[1]["id"] == 2
    assert responses[2]["id"] == 3

    # Ogni risposta ha il suo id e nessuna ha sia result che error
    for resp in responses:
        assert ("result" in resp) != ("error" in resp)


def test_stdio_blank_lines_are_skipped() -> None:
    """Righe vuote nel flusso stdio non devono produrre risposte."""
    stdin_data = (
        "\n"
        + "   \n"
        + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        + "\n\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "privacy_anonymizer.mcp_server"],
        input=stdin_data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    responses = [json.loads(l) for l in result.stdout.splitlines() if l.strip()]
    # Solo una risposta: le righe vuote non generano output
    assert len(responses) == 1
    assert responses[0]["id"] == 1


def test_stdio_full_workflow_init_list_call() -> None:
    """Workflow completo: initialize → tools/list → tools/call con un cedolino reale."""
    testo_cedolino = (
        "Cedolino Mario Rossi CF RSSMRA80A01L219M "
        "IBAN IT60X0542811101000000123456 "
        "tel 3401234567 email mario@azienda.it"
    )
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"name": "anonymize_text", "arguments": {"text": testo_cedolino}},
        },
    ]
    responses = _mcp_session(requests)

    init_resp, list_resp, call_resp = responses

    # initialize
    assert init_resp["result"]["protocolVersion"] == "2024-11-05"

    # tools/list
    assert any(t["name"] == "anonymize_text" for t in list_resp["result"]["tools"])

    # tools/call
    anonimizzato = call_resp["result"]["content"][0]["text"]
    c = call_resp["result"]["structuredContent"]["counts"]
    assert "RSSMRA80A01L219M" not in anonimizzato
    assert "IT60X0542811101000000123456" not in anonimizzato
    assert "3401234567" not in anonimizzato
    assert "mario@azienda.it" not in anonimizzato
    assert c.get("CODICE_FISCALE", 0) >= 1
    assert c.get("IBAN_IT", 0) >= 1


def test_stdio_response_is_one_json_line_per_request() -> None:
    """Ogni risposta deve stare su una singola riga (requisito del protocollo line-oriented)."""
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    stdin_data = "\n".join(json.dumps(r) for r in requests) + "\n"
    result = subprocess.run(
        [sys.executable, "-m", "privacy_anonymizer.mcp_server"],
        input=stdin_data, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    output_lines = [l for l in result.stdout.splitlines() if l.strip()]
    assert len(output_lines) == 2
    # Ogni riga deve essere JSON valido
    for line in output_lines:
        parsed = json.loads(line)
        assert parsed["jsonrpc"] == "2.0"
