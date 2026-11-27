import re
import pandas as pd

# ============================================================
# CONFIGURAÇÃO
# ============================================================

INPUT_FILE = "inventario.xlsx"
OUTPUT_FILE = "cisco_inventory.csv"

# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def clean_value(value):
    """Remove espaços e trata valores vazios."""
    if pd.isna(value):
        return ""
    return str(value).strip()


def is_cisco(text):
    """
    Verifica se é um equipamento Cisco.
    Ignora HP, Aruba e outros fabricantes.
    """

    text = str(text).upper()

    indicators = [
        "CISCO",
        "CBS",
        "SG",
        "WS-C",
        "CATALYST"
    ]

    return any(i in text for i in indicators)


def normalize_model(raw_model):
    """
    Normaliza os vários formatos de modelos Cisco.
    """

    if not raw_model:
        return ""

    text = str(raw_model).replace("\n", " ").upper()

    patterns = [

        # CBS350-48P-4G
        r"(CBS\d+-[\w\-]+)",

        # SG500-52P
        r"(SG\d+X?-\d+[\w\-]*)",

        # WS-C2960X-48FPS-L
        r"(WS-C[\w\-]+)",

        # C9200L-48P-4G
        r"(C\d{4}[\w\-]*)",

        # C9300-48P
        r"(C\d{4}-[\w\-]+)"
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)

    # Formato:
    # Fabricante: Cisco
    # Modelo: CBS350-48P-4G
    model_match = re.search(
        r"MODELO:\s*([A-Z0-9\-]+)",
        text
    )

    if model_match:
        return model_match.group(1)

    return text


def normalize_firmware(firmware):
    """
    Limpa o firmware.
    """

    if not firmware:
        return ""

    return str(firmware).strip()


def normalize_hostname(hostname):
    """
    Uniformiza hostname.
    """

    if not hostname:
        return ""

    return str(hostname).strip().upper()


# ============================================================
# PROCESSAMENTO PRINCIPAL
# ============================================================

def main():

    print("=" * 80)
    print("CISCO INVENTORY EXTRACTOR")
    print("=" * 80)
    print()

    try:
        excel = pd.ExcelFile(INPUT_FILE)
    except Exception as e:
        print(f"[ERRO] Não foi possível abrir {INPUT_FILE}")
        print(e)
        return

    print(f"[INFO] Ficheiro: {INPUT_FILE}")
    print(f"[INFO] Folhas encontradas: {len(excel.sheet_names)}")
    print()

    results = []

    for sheet in excel.sheet_names:

        print("-" * 80)
        print(f"[PROCESSANDO] {sheet}")

        if not re.fullmatch(r"SW-\d{3}", sheet):
            print("[SKIP] Folha ignorada (não corresponde a SW-XXX)")
            continue

        try:

            df = pd.read_excel(
                INPUT_FILE,
                sheet_name=sheet,
                header=None
            )

            # K3
            hostname = normalize_hostname(
                clean_value(df.iloc[2, 10])
            )

            # K4
            model_raw = clean_value(df.iloc[3, 10])

            # K21
            firmware = normalize_firmware(
                clean_value(df.iloc[20, 10])
            )

            print(f"[INFO] Hostname : {hostname}")
            print(f"[INFO] Modelo RAW : {model_raw}")
            print(f"[INFO] Firmware : {firmware}")

            if not is_cisco(model_raw):
                print("[SKIP] Equipamento não Cisco")
                continue

            model = normalize_model(model_raw)

            print(f"[INFO] Modelo Normalizado : {model}")

            results.append({
                "id": sheet,
                "hostname": hostname,
                "model": model,
                "firmware": firmware
            })

            print("[OK] Equipamento adicionado")

        except Exception as e:
            print(f"[ERRO] Falha ao processar {sheet}")
            print(e)

    print()
    print("=" * 80)
    print("A GERAR CSV...")
    print("=" * 80)

    output = pd.DataFrame(results)

    if output.empty:
        print("[AVISO] Nenhum equipamento Cisco encontrado.")
        return

    output.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig"
    )

    print()
    print("=" * 80)
    print("RESUMO")
    print("=" * 80)
    print(f"Equipamentos Cisco encontrados : {len(output)}")
    print(f"CSV gerado                     : {OUTPUT_FILE}")
    print()

    print(output.to_string(index=False))

    print()
    print("=" * 80)
    print("PROCESSAMENTO CONCLUÍDO")
    print("=" * 80)


if __name__ == "__main__":
    main()