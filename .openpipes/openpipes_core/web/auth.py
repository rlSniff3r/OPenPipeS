import os
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic()

def ler_credenciais():
    """Lê o usuário e senha do arquivo secrets.conf."""
    caminho_secrets = os.path.expanduser("~/.openpipes/secrets.conf")
    credenciais = {"username": "", "password": ""}
    
    try:
        with open(caminho_secrets, "r") as f:
            for linha in f:
                linha = linha.strip()
                if not linha or linha.startswith("#") or "=" not in linha:
                    continue
                
                chave, valor = linha.split("=", 1)
                
                # Remove o "export " da chave, se existir, e limpa os espaços
                chave = chave.replace("export", "").strip()
                
                # Limpa espaços e possíveis aspas duplas/simples do valor
                valor = valor.strip().strip('"').strip("'")
                
                if chave == "WEB_USER":
                    credenciais["username"] = valor
                elif chave == "WEB_PASS":
                    credenciais["password"] = valor

    except FileNotFoundError:
        pass # Falhará na autenticação mais abaixo
        
    return credenciais

def verificar_autenticacao(credentials: HTTPBasicCredentials = Depends(security)):
    """Valida as credenciais inseridas."""
    creds_config = ler_credenciais()
    
    user_config = creds_config.get("username", "").encode("utf8")
    pass_config = creds_config.get("password", "").encode("utf8")
    
    user_request = credentials.username.encode("utf8")
    pass_request = credentials.password.encode("utf8")
    
    # Se não houver credencial no arquivo, nega acesso por padrão de segurança
    if not user_config or not pass_config:
         raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Credenciais não configuradas em ~/.openpipes/secrets.conf (WEB_USER e WEB_PASS).",
        )

    is_user_ok = secrets.compare_digest(user_request, user_config)
    is_pass_ok = secrets.compare_digest(pass_request, pass_config)
    
    if not (is_user_ok and is_pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return credentials.username