import os
import base64
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import padding as symmetric_padding

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


def cifrar_mensagem_aes(dados, chave_sessao, modo_operacao='CBC', formato_saida='HEX'):
    """
    Cifra uma mensagem usando AES.
    
    Args:
        dados: Bytes ou string com os dados a serem cifrados
        chave_sessao: Bytes da chave de sessão AES
        modo_operacao: String 'ECB' ou 'CBC'
        formato_saida: String 'HEX' ou 'BASE64'
        
    Returns:
        dict contendo:
        - 'dados_cifrados': Dados cifrados no formato especificado
        - 'iv': Bytes do IV (para CBC) ou None (para ECB)
        - 'erro': Mensagem de erro ou None se sucesso
    """
    resultado = {'dados_cifrados': None, 'iv': None, 'erro': None}
    
    try:
        # Converter string para bytes se necessário
        if isinstance(dados, str):
            dados = dados.encode('utf-8')
        
        # Validar o tamanho da chave AES
        tamanho_chave = len(chave_sessao)
        if tamanho_chave not in [16, 24, 32]:  # 128, 192 ou 256 bits
            raise ValueError(f"Tamanho da chave AES inválido: {tamanho_chave*8} bits. Deve ser 128, 192 ou 256 bits.")
        
        # Validar modo de operação
        modo_operacao = modo_operacao.upper()
        if modo_operacao not in ['ECB', 'CBC']:
            raise ValueError(f"Modo de operação inválido: {modo_operacao}. Deve ser 'ECB' ou 'CBC'.")
        
        # Validar formato de saída
        formato_saida = formato_saida.upper()
        if formato_saida not in ['HEX', 'BASE64']:
            raise ValueError(f"Formato de saída inválido: {formato_saida}. Deve ser 'HEX' ou 'BASE64'.")
        
        # Criar IV para CBC (16 bytes para AES)
        iv = None
        if modo_operacao == 'CBC':
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(chave_sessao), modes.CBC(iv))
            resultado['iv'] = iv
        else:  # ECB
            cipher = Cipher(algorithms.AES(chave_sessao), modes.ECB())
        
        # Aplicar padding PKCS7 (padrão para cifras de bloco)
        padder = symmetric_padding.PKCS7(128).padder()  # 128 bits = 16 bytes (tamanho do bloco AES)
        padded_dados = padder.update(dados) + padder.finalize()
        
        # Cifrar dados
        encryptor = cipher.encryptor()
        dados_cifrados = encryptor.update(padded_dados) + encryptor.finalize()
        
        # Converter para formato de saída especificado
        if formato_saida == 'HEX':
            resultado['dados_cifrados'] = dados_cifrados.hex()
        else:  # BASE64
            resultado['dados_cifrados'] = base64.b64encode(dados_cifrados).decode('ascii')
        
        return resultado
    
    except Exception as e:
        resultado['erro'] = f"Erro ao cifrar mensagem: {str(e)}"
        return resultado
    
def cifrar_arquivo_aes(arquivo_entrada, arquivo_saida, chave_sessao, modo_operacao='CBC', formato_saida='HEX'):
    """
    Cifra um arquivo usando AES com a chave de sessão fornecida.
    
    Args:
        arquivo_entrada: Caminho para o arquivo a ser cifrado
        arquivo_saida: Caminho para salvar o arquivo cifrado
        chave_sessao: Bytes da chave de sessão
        modo_operacao: String 'ECB' ou 'CBC'
        formato_saida: String 'HEX' ou 'BASE64'
        
    Returns:
        dict contendo:
        - 'sucesso': Boolean indicando sucesso ou falha
        - 'mensagem': Mensagem de sucesso ou erro
        - 'iv': Bytes do IV (para CBC) ou None (para ECB)
        - 'arquivo_iv': Nome do arquivo onde o IV foi salvo (para CBC) ou None (para ECB)
    """
    resultado = {'sucesso': False, 'mensagem': '', 'iv': None, 'arquivo_iv': None}
    
    try:
        # Verificar se o arquivo de entrada existe
        if not os.path.isfile(arquivo_entrada):
            resultado['mensagem'] = f"Arquivo de entrada não encontrado: {arquivo_entrada}"
            return resultado
        
        # Verificar se diretório de saída existe, se não, criar
        diretorio_saida = os.path.dirname(arquivo_saida)
        if diretorio_saida and not os.path.exists(diretorio_saida):
            try:
                os.makedirs(diretorio_saida)
            except Exception as e:
                resultado['mensagem'] = f"Não foi possível criar o diretório de saída: {str(e)}"
                return resultado
        
        # Ler conteúdo do arquivo
        try:
            with open(arquivo_entrada, 'rb') as f:
                dados = f.read()
        except Exception as e:
            resultado['mensagem'] = f"Erro ao ler arquivo de entrada: {str(e)}"
            return resultado
        
        # Cifrar dados usando a função de cifragem de mensagem
        res_cifragem = cifrar_mensagem_aes(dados, chave_sessao, modo_operacao, formato_saida)
        
        if res_cifragem['erro']:
            resultado['mensagem'] = res_cifragem['erro']
            return resultado
        
        # Salvar dados cifrados
        try:
            with open(arquivo_saida, 'w') as f:
                f.write(res_cifragem['dados_cifrados'])
        except Exception as e:
            resultado['mensagem'] = f"Erro ao salvar arquivo cifrado: {str(e)}"
            return resultado
        
        # Se modo CBC, salvar IV em arquivo separado
        if res_cifragem['iv']:
            arquivo_iv = f"{arquivo_saida}.iv"
            try:
                with open(arquivo_iv, 'w') as f:
                    f.write(res_cifragem['iv'].hex())
                resultado['arquivo_iv'] = arquivo_iv
            except Exception as e:
                resultado['mensagem'] = f"Arquivo cifrado com sucesso, mas houve erro ao salvar o IV: {str(e)}"
                resultado['sucesso'] = True  # Consideramos sucesso parcial
                return resultado
        
        resultado['sucesso'] = True
        resultado['mensagem'] = f"Arquivo cifrado com sucesso: {arquivo_saida}"
        resultado['iv'] = res_cifragem['iv']
        return resultado
    
    except Exception as e:
        resultado['mensagem'] = f"Erro inesperado ao cifrar arquivo: {str(e)}"
        return resultado

def gerar_par_chaves(tamanho=2048, arquivo_chave_privada="chave_privada.pem", arquivo_chave_publica="chave_publica.pem"):
    """
    Gera um par de chaves RSA e salva em arquivos no formato PEM.
    
    Args:
        tamanho: Tamanho da chave em bits (1024 ou 2048)
        arquivo_chave_privada: Nome do arquivo para salvar a chave privada
        arquivo_chave_publica: Nome do arquivo para salvar a chave pública
    
    Returns:
        Tuple contendo as chaves privada e pública em formato PEM
    """
    try:
        # Validar o tamanho da chave
        if tamanho not in [1024, 2048]:
            raise ValueError("Tamanho da chave deve ser 1024 ou 2048 bits.")
        
        print(f"Gerando par de chaves RSA de {tamanho} bits... Isso pode levar alguns segundos.")
        
        # Gerar chave privada
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Valor padrão usado pelo OpenSSL
            key_size=tamanho
        )
        
        # Obter chave pública correspondente
        public_key = private_key.public_key()
        
        # Serializar chaves para formato PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Verificar se os diretórios de destino existem, se não, criar
        for arquivo in [arquivo_chave_privada, arquivo_chave_publica]:
            diretorio = os.path.dirname(arquivo)
            if diretorio and not os.path.exists(diretorio):
                try:
                    os.makedirs(diretorio)
                    print(f"Diretório criado: {diretorio}")
                except Exception as e:
                    print(f"Aviso: Não foi possível criar o diretório {diretorio}: {e}")
        
        # Salvar chaves em arquivos
        try:
            with open(arquivo_chave_privada, "wb") as f:
                f.write(private_pem)
            print(f"Chave privada salva em: {arquivo_chave_privada}")
        except IOError as e:
            raise IOError(f"Erro ao salvar chave privada em '{arquivo_chave_privada}': {e}")
        
        try:
            with open(arquivo_chave_publica, "wb") as f:
                f.write(public_pem)
            print(f"Chave pública salva em: {arquivo_chave_publica}")
        except IOError as e:
            raise IOError(f"Erro ao salvar chave pública em '{arquivo_chave_publica}': {e}")
        
        print(f"Par de chaves RSA de {tamanho} bits gerado com sucesso!")
        return private_pem, public_pem
    
    except ValueError as e:
        print(f"Erro de valor: {e}")
        return None, None
    except Exception as e:
        print(f"Erro ao gerar par de chaves: {e}")
        return None, None
    

# Para RSA (cifrar a chave de sessão) - Esta função seria implementada em seguida
def cifrar_chave_sessao_rsa(chave_sessao, chave_publica):
    """
    Cifra a chave de sessão usando RSA com PKCS1Padding.
    
    Args:
        chave_sessao: Bytes da chave de sessão
        chave_publica: Objeto de chave pública RSA
        
    Returns:
        Bytes da chave de sessão cifrada
    """
    # Usar explicitamente PKCS1v15Padding (PKCS1Padding) conforme especificado
    chave_cifrada = chave_publica.encrypt(
        chave_sessao,
        asymmetric_padding.PKCS1v15()  # Este é o PKCS1Padding mencionado no trabalho
    )
    
    return chave_cifrada


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
