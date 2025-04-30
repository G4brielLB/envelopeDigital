import os

def criar_chave_sessao(tamanho):
    """
    Função para criar uma chave de sessão.
    Recebe o tamanho da chave em bits ou bytes.
    Se o tamanho for fornecido em bytes, deve ser 16, 24 ou 32 bytes (128, 192 ou 256 bits).
    Se o tamanho for fornecido em bits, deve ser 128, 192 ou 256 bits.
    """
    # Converter tamanho para bits se for fornecido em bytes
    if tamanho in [16, 24, 32]:  # 16 bytes = 128 bits, 24 bytes = 192 bits, 32 bytes = 256 bits
        tamanho *= 8

    if tamanho not in [128, 192, 256]:
        raise ValueError("Tamanho da chave deve ser 128, 192 ou 256 bits (ou 16, 24, 32 bytes).")
    
    # Gerar uma chave de sessão aleatória
    chave = os.urandom(tamanho // 8)

    return chave

def main():
    # Exemplo de uso da função
    try:
        tamanho = int(input("Digite o tamanho da chave (em bits ou bytes): "))
        chave = criar_chave_sessao(tamanho)
        print(f"Chave de sessão gerada: {chave.hex()}")
    except ValueError as e:
        print(e)
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    main()
