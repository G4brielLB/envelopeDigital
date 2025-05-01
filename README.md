# envelopeDigital
Desenvolvimento de um envelope digital com ferramentas de segurança como RSA e AES

## Autores
- Gabriel Lopes Bastos (G4brielLB)
- José Victor Vieira de Oliveira (@vickminari)
- Pedro Emanuel Moreira Carvalho (@PedroEmanuelMoreiraCarvalho)

## Instalação
Para instalar as dependências, utilize um dos seguintes comandos:

```bash
pip install cryptography
```

ou, caso exista um arquivo `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Utilização
Para utilizar o programa, você pode executar os seguintes comandos:

Para gerar um par de chaves RSA:
python claude.py gerar-chaves --tamanho 2048 --privada chave_privada.pem --publica chave_publica.pem

Para criar um envelope digital:
python claude.py criar arquivo.txt --chave-publica chave_publica.pem --saida ./saida --modo CBC --formato HEX

Para abrir um envelope digital:
python claude.py abrir --mensagem ./saida/arquivo.txt.enc --chave-cifrada ./saida/arquivo.txt.key --chave-privada chave_privada.pem --saida arquivo_decifrado.txt --modo CBC --formato HEX
