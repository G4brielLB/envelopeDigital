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
        return private_key, public_key
    
    except ValueError as e:
        print(f"Erro de valor: {e}")
        return None, None
    except Exception as e:
        print(f"Erro ao gerar par de chaves: {e}")
        return None, None

def carregar_chave_publica(arquivo_chave_publica):
    """
    Carrega uma chave pública de um arquivo PEM.
    
    Args:
        arquivo_chave_publica: Caminho para o arquivo de chave pública
        
    Returns:
        Objeto de chave pública RSA
    """
    try:
        with open(arquivo_chave_publica, "rb") as f:
            chave_publica = serialization.load_pem_public_key(f.read())
        return chave_publica
    except Exception as e:
        print(f"Erro ao carregar chave pública: {e}")
        return None

def carregar_chave_privada(arquivo_chave_privada):
    """
    Carrega uma chave privada de um arquivo PEM.
    
    Args:
        arquivo_chave_privada: Caminho para o arquivo de chave privada
        
    Returns:
        Objeto de chave privada RSA
    """
    try:
        with open(arquivo_chave_privada, "rb") as f:
            chave_privada = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        return chave_privada
    except Exception as e:
        print(f"Erro ao carregar chave privada: {e}")
        return None

def cifrar_chave_sessao_rsa(chave_sessao, chave_publica):
    """
    Cifra a chave de sessão usando RSA com PKCS1Padding.
    
    Args:
        chave_sessao: Bytes da chave de sessão
        chave_publica: Objeto de chave pública RSA
        
    Returns:
        Bytes da chave de sessão cifrada
    """
    try:
        # Usar explicitamente PKCS1v15Padding (PKCS1Padding) conforme especificado
        chave_cifrada = chave_publica.encrypt(
            chave_sessao,
            asymmetric_padding.PKCS1v15()  # Este é o PKCS1Padding mencionado no trabalho
        )
        
        return chave_cifrada
    except Exception as e:
        print(f"Erro ao cifrar chave de sessão: {e}")
        return None

def decifrar_chave_sessao_rsa(chave_sessao_cifrada, chave_privada):
    """
    Decifra a chave de sessão usando RSA com PKCS1Padding.
    
    Args:
        chave_sessao_cifrada: Bytes da chave de sessão cifrada
        chave_privada: Objeto de chave privada RSA
        
    Returns:
        Bytes da chave de sessão decifrada
    """
    try:
        # Usar explicitamente PKCS1v15Padding (PKCS1Padding) conforme especificado
        chave_decifrada = chave_privada.decrypt(
            chave_sessao_cifrada,
            asymmetric_padding.PKCS1v15()  # Este é o PKCS1Padding mencionado no trabalho
        )
        
        return chave_decifrada
    except Exception as e:
        print(f"Erro ao decifrar chave de sessão: {e}")
        return None

def decifrar_mensagem_aes(dados_cifrados, chave_sessao, iv=None, modo_operacao='CBC', formato_entrada='HEX'):
    """
    Decifra uma mensagem usando AES.
    
    Args:
        dados_cifrados: String (HEX/BASE64) com os dados cifrados
        chave_sessao: Bytes da chave de sessão AES
        iv: Bytes do IV para CBC (None para ECB)
        modo_operacao: String 'ECB' ou 'CBC'
        formato_entrada: String 'HEX' ou 'BASE64'
        
    Returns:
        dict contendo:
        - 'dados_decifrados': Bytes dos dados decifrados
        - 'erro': Mensagem de erro ou None se sucesso
    """
    resultado = {'dados_decifrados': None, 'erro': None}
    
    try:
        # Validar o tamanho da chave AES
        tamanho_chave = len(chave_sessao)
        if tamanho_chave not in [16, 24, 32]:  # 128, 192 ou 256 bits
            raise ValueError(f"Tamanho da chave AES inválido: {tamanho_chave*8} bits. Deve ser 128, 192 ou 256 bits.")
        
        # Validar modo de operação
        modo_operacao = modo_operacao.upper()
        if modo_operacao not in ['ECB', 'CBC']:
            raise ValueError(f"Modo de operação inválido: {modo_operacao}. Deve ser 'ECB' ou 'CBC'.")
        
        # Validar formato de entrada
        formato_entrada = formato_entrada.upper()
        if formato_entrada not in ['HEX', 'BASE64']:
            raise ValueError(f"Formato de entrada inválido: {formato_entrada}. Deve ser 'HEX' ou 'BASE64'.")
        
        # Converter dados cifrados de acordo com o formato
        if formato_entrada == 'HEX':
            dados_binarios = bytes.fromhex(dados_cifrados)
        else:  # BASE64
            dados_binarios = base64.b64decode(dados_cifrados)
        
        # Configurar o objeto de decifragem
        if modo_operacao == 'CBC':
            if iv is None:
                raise ValueError("IV obrigatório para modo CBC.")
            cipher = Cipher(algorithms.AES(chave_sessao), modes.CBC(iv))
        else:  # ECB
            cipher = Cipher(algorithms.AES(chave_sessao), modes.ECB())
        
        # Decifrar dados
        decryptor = cipher.decryptor()
        dados_padded = decryptor.update(dados_binarios) + decryptor.finalize()
        
        # Remover padding PKCS7
        unpadder = symmetric_padding.PKCS7(128).unpadder()  # 128 bits = 16 bytes (tamanho do bloco AES)
        dados_decifrados = unpadder.update(dados_padded) + unpadder.finalize()
        
        resultado['dados_decifrados'] = dados_decifrados
        return resultado
    
    except Exception as e:
        resultado['erro'] = f"Erro ao decifrar mensagem: {str(e)}"
        return resultado

def decifrar_arquivo_aes(arquivo_cifrado, arquivo_saida, chave_sessao, arquivo_iv=None, modo_operacao='CBC', formato_entrada='HEX'):
    """
    Decifra um arquivo usando AES com a chave de sessão fornecida.
    
    Args:
        arquivo_cifrado: Caminho para o arquivo cifrado
        arquivo_saida: Caminho para salvar o arquivo decifrado
        chave_sessao: Bytes da chave de sessão
        arquivo_iv: Caminho para o arquivo com o IV (para CBC) ou None (para ECB)
        modo_operacao: String 'ECB' ou 'CBC'
        formato_entrada: String 'HEX' ou 'BASE64'
        
    Returns:
        dict contendo:
        - 'sucesso': Boolean indicando sucesso ou falha
        - 'mensagem': Mensagem de sucesso ou erro
    """
    resultado = {'sucesso': False, 'mensagem': ''}
    
    try:
        # Verificar se o arquivo cifrado existe
        if not os.path.isfile(arquivo_cifrado):
            resultado['mensagem'] = f"Arquivo cifrado não encontrado: {arquivo_cifrado}"
            return resultado
        
        # Verificar se diretório de saída existe, se não, criar
        diretorio_saida = os.path.dirname(arquivo_saida)
        if diretorio_saida and not os.path.exists(diretorio_saida):
            try:
                os.makedirs(diretorio_saida)
            except Exception as e:
                resultado['mensagem'] = f"Não foi possível criar o diretório de saída: {str(e)}"
                return resultado
        
        # Ler conteúdo do arquivo cifrado
        try:
            with open(arquivo_cifrado, 'r') as f:
                dados_cifrados = f.read()
        except Exception as e:
            resultado['mensagem'] = f"Erro ao ler arquivo cifrado: {str(e)}"
            return resultado
        
        # Ler IV se modo CBC
        iv = None
        if modo_operacao.upper() == 'CBC':
            if not arquivo_iv:
                # Tentar usar o nome padrão arquivo.iv
                arquivo_iv = f"{arquivo_cifrado}.iv"
            
            if not os.path.isfile(arquivo_iv):
                resultado['mensagem'] = f"Arquivo IV não encontrado: {arquivo_iv}"
                return resultado
            
            try:
                with open(arquivo_iv, 'r') as f:
                    iv_hex = f.read()
                    iv = bytes.fromhex(iv_hex)
            except Exception as e:
                resultado['mensagem'] = f"Erro ao ler arquivo IV: {str(e)}"
                return resultado
        
        # Decifrar dados
        res_decifragem = decifrar_mensagem_aes(
            dados_cifrados, 
            chave_sessao, 
            iv=iv, 
            modo_operacao=modo_operacao, 
            formato_entrada=formato_entrada
        )
        
        if res_decifragem['erro']:
            resultado['mensagem'] = res_decifragem['erro']
            return resultado
        
        # Salvar dados decifrados
        try:
            with open(arquivo_saida, 'wb') as f:
                f.write(res_decifragem['dados_decifrados'])
        except Exception as e:
            resultado['mensagem'] = f"Erro ao salvar arquivo decifrado: {str(e)}"
            return resultado
        
        resultado['sucesso'] = True
        resultado['mensagem'] = f"Arquivo decifrado com sucesso: {arquivo_saida}"
        return resultado
    
    except Exception as e:
        resultado['mensagem'] = f"Erro inesperado ao decifrar arquivo: {str(e)}"
        return resultado

def criar_envelope_digital(arquivo_entrada, pasta_saida, arquivo_chave_publica, 
                          tamanho_chave_aes=256, modo_operacao='CBC', formato_saida='HEX'):
    """
    Cria um envelope digital, cifrando um arquivo com AES e a chave de sessão com RSA.
    
    Args:
        arquivo_entrada: Caminho para o arquivo em claro
        pasta_saida: Pasta para salvar os arquivos de saída
        arquivo_chave_publica: Caminho para o arquivo da chave pública
        tamanho_chave_aes: Tamanho da chave AES em bits (128, 192 ou 256)
        modo_operacao: String 'ECB' ou 'CBC'
        formato_saida: String 'HEX' ou 'BASE64'
        
    Returns:
        dict contendo:
        - 'sucesso': Boolean indicando sucesso ou falha
        - 'mensagem': Mensagem de sucesso ou erro
        - 'arquivo_mensagem_cifrada': Caminho para o arquivo da mensagem cifrada
        - 'arquivo_chave_cifrada': Caminho para o arquivo da chave cifrada
        - 'arquivo_iv': Caminho para o arquivo do IV (para CBC) ou None (para ECB)
    """
    resultado = {
        'sucesso': False, 
        'mensagem': '', 
        'arquivo_mensagem_cifrada': None, 
        'arquivo_chave_cifrada': None, 
        'arquivo_iv': None
    }
    
    try:
        # Verificar se o arquivo de entrada existe
        if not os.path.isfile(arquivo_entrada):
            resultado['mensagem'] = f"Arquivo de entrada não encontrado: {arquivo_entrada}"
            return resultado
        
        # Verificar se a pasta de saída existe, se não, criar
        if not os.path.exists(pasta_saida):
            try:
                os.makedirs(pasta_saida)
            except Exception as e:
                resultado['mensagem'] = f"Não foi possível criar a pasta de saída: {str(e)}"
                return resultado
        
        # Carregar a chave pública
        chave_publica = carregar_chave_publica(arquivo_chave_publica)
        if not chave_publica:
            resultado['mensagem'] = f"Não foi possível carregar a chave pública: {arquivo_chave_publica}"
            return resultado
        
        # Gerar chave de sessão AES
        print(f"Gerando chave de sessão AES de {tamanho_chave_aes} bits...")
        try:
            chave_sessao = criar_chave_sessao(tamanho_chave_aes)
        except ValueError as e:
            resultado['mensagem'] = f"Erro ao gerar chave de sessão: {e}"
            return resultado
        
        # Cifrar a chave de sessão com RSA
        print("Cifrando chave de sessão com RSA...")
        chave_sessao_cifrada = cifrar_chave_sessao_rsa(chave_sessao, chave_publica)
        if not chave_sessao_cifrada:
            resultado['mensagem'] = "Falha ao cifrar a chave de sessão."
            return resultado
        
        # Definir nomes de arquivos de saída
        nome_arquivo = os.path.basename(arquivo_entrada)
        arquivo_mensagem_cifrada = os.path.join(pasta_saida, f"{nome_arquivo}.enc")
        arquivo_chave_cifrada = os.path.join(pasta_saida, f"{nome_arquivo}.key")
        
        # Cifrar o arquivo com AES
        print(f"Cifrando arquivo com AES ({modo_operacao}, saída em {formato_saida})...")
        res_cifragem = cifrar_arquivo_aes(
            arquivo_entrada, 
            arquivo_mensagem_cifrada, 
            chave_sessao, 
            modo_operacao=modo_operacao, 
            formato_saida=formato_saida
        )
        
        if not res_cifragem['sucesso']:
            resultado['mensagem'] = f"Falha ao cifrar o arquivo: {res_cifragem['mensagem']}"
            return resultado
        
        # Salvar a chave de sessão cifrada
        try:
            with open(arquivo_chave_cifrada, 'wb') as f:
                f.write(chave_sessao_cifrada)
            print(f"Chave de sessão cifrada salva em: {arquivo_chave_cifrada}")
        except Exception as e:
            resultado['mensagem'] = f"Erro ao salvar a chave de sessão cifrada: {e}"
            return resultado
        
        # Resultado
        resultado['sucesso'] = True
        resultado['mensagem'] = "Envelope digital criado com sucesso!"
        resultado['arquivo_mensagem_cifrada'] = arquivo_mensagem_cifrada
        resultado['arquivo_chave_cifrada'] = arquivo_chave_cifrada
        resultado['arquivo_iv'] = res_cifragem['arquivo_iv']
        
        print("-" * 50)
        print("Envelope Digital criado com sucesso!")
        print(f"- Arquivo de mensagem cifrada: {arquivo_mensagem_cifrada}")
        print(f"- Arquivo de chave cifrada: {arquivo_chave_cifrada}")
        if res_cifragem['arquivo_iv']:
            print(f"- Arquivo IV: {res_cifragem['arquivo_iv']}")
        print("-" * 50)
        
        return resultado
    
    except Exception as e:
        resultado['mensagem'] = f"Erro inesperado ao criar envelope digital: {str(e)}"
        return resultado

def abrir_envelope_digital(arquivo_mensagem_cifrada, arquivo_chave_cifrada, arquivo_chave_privada, 
                          arquivo_saida, arquivo_iv=None, modo_operacao='CBC', formato_entrada='HEX'):
    """
    Abre um envelope digital, decifrando a chave de sessão com RSA e o arquivo com AES.
    
    Args:
        arquivo_mensagem_cifrada: Caminho para o arquivo da mensagem cifrada
        arquivo_chave_cifrada: Caminho para o arquivo da chave cifrada
        arquivo_chave_privada: Caminho para o arquivo da chave privada
        arquivo_saida: Caminho para salvar o arquivo decifrado
        arquivo_iv: Caminho para o arquivo do IV (para CBC) ou None (para ECB)
        modo_operacao: String 'ECB' ou 'CBC'
        formato_entrada: String 'HEX' ou 'BASE64'
        
    Returns:
        dict contendo:
        - 'sucesso': Boolean indicando sucesso ou falha
        - 'mensagem': Mensagem de sucesso ou erro
    """
    resultado = {'sucesso': False, 'mensagem': ''}
    
    try:
        # Verificar se os arquivos existem
        for arquivo, nome in [
            (arquivo_mensagem_cifrada, "mensagem cifrada"),
            (arquivo_chave_cifrada, "chave cifrada"),
            (arquivo_chave_privada, "chave privada")
        ]:
            if not os.path.isfile(arquivo):
                resultado['mensagem'] = f"Arquivo de {nome} não encontrado: {arquivo}"
                return resultado
        
        # Verificar se diretório de saída existe, se não, criar
        diretorio_saida = os.path.dirname(arquivo_saida)
        if diretorio_saida and not os.path.exists(diretorio_saida):
            try:
                os.makedirs(diretorio_saida)
            except Exception as e:
                resultado['mensagem'] = f"Não foi possível criar o diretório de saída: {str(e)}"
                return resultado
        
        # Carregar chave privada
        print("Carregando chave privada...")
        chave_privada = carregar_chave_privada(arquivo_chave_privada)
        if not chave_privada:
            resultado['mensagem'] = f"Falha ao carregar a chave privada: {arquivo_chave_privada}"
            return resultado
        
        # Ler chave de sessão cifrada
        print("Lendo chave de sessão cifrada...")
        try:
            with open(arquivo_chave_cifrada, 'rb') as f:
                chave_sessao_cifrada = f.read()
        except Exception as e:
            resultado['mensagem'] = f"Erro ao ler arquivo da chave cifrada: {str(e)}"
            return resultado
        
        # Decifrar a chave de sessão com RSA
        print("Decifrando chave de sessão com RSA...")
        chave_sessao = decifrar_chave_sessao_rsa(chave_sessao_cifrada, chave_privada)
        if not chave_sessao:
            resultado['mensagem'] = "Falha ao decifrar a chave de sessão."
            return resultado
        
        print(f"Chave de sessão AES recuperada: {len(chave_sessao)*8} bits")
        
        # Decifrar o arquivo
        print(f"Decifrando arquivo com AES ({modo_operacao}, entrada em {formato_entrada})...")
        res_decifragem = decifrar_arquivo_aes(
            arquivo_cifrado=arquivo_mensagem_cifrada,
            arquivo_saida=arquivo_saida,
            chave_sessao=chave_sessao,
            arquivo_iv=arquivo_iv,
            modo_operacao=modo_operacao,
            formato_entrada=formato_entrada
        )
        
        if not res_decifragem['sucesso']:
            resultado['mensagem'] = f"Falha ao decifrar o arquivo: {res_decifragem['mensagem']}"
            return resultado
        
        # Resultado
        resultado['sucesso'] = True
        resultado['mensagem'] = f"Envelope digital aberto com sucesso! Arquivo decifrado salvo em: {arquivo_saida}"
        
        print("-" * 50)
        print("Envelope Digital aberto com sucesso!")
        print(f"- Arquivo decifrado: {arquivo_saida}")
        print(f"- Tamanho da chave de sessão: {len(chave_sessao)*8} bits")
        print("-" * 50)
        
        return resultado
    
    except Exception as e:
        resultado['mensagem'] = f"Erro inesperado ao abrir envelope digital: {str(e)}"
        return resultado

def main():
    """
    Função principal que processa os argumentos de linha de comando.
    """
    parser = argparse.ArgumentParser(description="Envelope Digital - Programa para operações criptográficas")
    subparsers = parser.add_subparsers(dest="comando", help="Comandos disponíveis")
    
    # Parser para o comando de geração de chaves
    gerar_parser = subparsers.add_parser("gerar-chaves", help="Gerar um par de chaves RSA")
    gerar_parser.add_argument("--tamanho", type=int, default=2048, choices=[1024, 2048],
                             help="Tamanho da chave em bits (1024 ou 2048)")
    gerar_parser.add_argument("--privada", type=str, default="chave_privada.pem",
                             help="Nome do arquivo para a chave privada")
    gerar_parser.add_argument("--publica", type=str, default="chave_publica.pem",
                             help="Nome do arquivo para a chave pública")
    
    # Parser para o comando de criação de envelope
    criar_parser = subparsers.add_parser("criar", help="Criar um envelope digital")
    criar_parser.add_argument("arquivo", type=str, help="Arquivo a ser cifrado")
    criar_parser.add_argument("--saida", type=str, default="./saida",
                             help="Pasta para salvar os arquivos de saída")
    criar_parser.add_argument("--chave-publica", type=str, required=True,
                             help="Arquivo da chave pública do destinatário")
    criar_parser.add_argument("--tamanho-chave-aes", type=int, default=256, choices=[128, 192, 256],
                             help="Tamanho da chave AES em bits (128, 192 ou 256)")
    criar_parser.add_argument("--modo", type=str, default="CBC", choices=["ECB", "CBC"],
                             help="Modo de operação AES (ECB ou CBC)")
    criar_parser.add_argument("--formato", type=str, default="HEX", choices=["HEX", "BASE64"],
                             help="Formato de saída (HEX ou BASE64)")
    
    # Parser para o comando de abertura de envelope
    abrir_parser = subparsers.add_parser("abrir", help="Abrir um envelope digital")
    abrir_parser.add_argument("--mensagem", type=str, required=True,
                             help="Arquivo da mensagem cifrada")
    abrir_parser.add_argument("--chave-cifrada", type=str, required=True,
                             help="Arquivo da chave de sessão cifrada")
    abrir_parser.add_argument("--chave-privada", type=str, required=True,
                             help="Arquivo da chave privada do destinatário")
    abrir_parser.add_argument("--saida", type=str, required=True,
                             help="Arquivo de saída para a mensagem decifrada")
    abrir_parser.add_argument("--iv", type=str, default=None,
                             help="Arquivo do IV (para CBC)")
    abrir_parser.add_argument("--modo", type=str, default="CBC", choices=["ECB", "CBC"],
                             help="Modo de operação AES (ECB ou CBC)")
    abrir_parser.add_argument("--formato", type=str, default="HEX", choices=["HEX", "BASE64"],
                             help="Formato de entrada (HEX ou BASE64)")
    
    # Processar argumentos
    args = parser.parse_args()
    
    # Executar o comando apropriado
    if args.comando == "gerar-chaves":
        gerar_par_chaves(args.tamanho, args.privada, args.publica)
    
    elif args.comando == "criar":
        resultado = criar_envelope_digital(
            args.arquivo,
            args.saida,
            args.chave_publica,
            args.tamanho_chave_aes,
            args.modo,
            args.formato
        )
        
        if not resultado['sucesso']:
            print(f"ERRO: {resultado['mensagem']}")
            return 1
    
    elif args.comando == "abrir":
        resultado = abrir_envelope_digital(
            args.mensagem,
            args.chave_cifrada,
            args.chave_privada,
            args.saida,
            args.iv,
            args.modo,
            args.formato
        )
        
        if not resultado['sucesso']:
            print(f"ERRO: {resultado['mensagem']}")
            return 1
    
    else:
        parser.print_help()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())