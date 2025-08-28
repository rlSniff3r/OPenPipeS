import os
import json
from pathlib import Path

# Diretório de cache
cache_dir = Path.home() / ".openpipes_cache"
cache_dir.mkdir(parents=True, exist_ok=True)

# Descrições técnicas e diretas baseadas na OWASP Top 10 (versão atual)
owasp_top_10 = {
    "broken_access_control": {
        "tipo": "Broken Access Control",
        "cwe": "CWE-284",
        "wstg_id": "WSTG-ATHZ-01",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Authorization_Testing/01-Testing_for_Path_Traversal",
        "owasp_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
        "descricao": "O produto não restringe ou falha em restringir que agentes não autorizados acessem recursos ou funcionalidades fora de seu escopo pretendido."
    },
    "cryptographic_failures": {
        "tipo": "Cryptographic Failures",
        "cwe": "CWE-311",
        "wstg_id": "WSTG-CRYP-02",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-Testing_for_Weak_Encryption/",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        "descricao": "A aplicação falha em proteger dados sensíveis em repouso ou em trânsito, resultando em possíveis exposições de informações confidenciais como credenciais, números de cartão ou informações pessoais."
    },
    "injection": {
        "tipo": "SQL Injection",
        "cwe": "CWE-89",
        "wstg_id": "WSTG-INPV-05",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
        "owasp_url": "https://owasp.org/www-community/attacks/SQL_Injection",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "descricao": "A aplicação falha em tratar inputs de usuário de maneira suficientemente adequada. É possível injetar comandos SQL que são executados pelo banco de dados, comprometendo a integridade das informações."
    },
    "insecure_design": {
        "tipo": "Insecure Design",
        "cwe": "CWE-1008",
        "wstg_id": "WSTG-INFO-02",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Information_Gathering/02-Fingerprint_Web_Server",
        "owasp_url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
        "descricao": "A arquitetura da aplicação permite fluxos inseguros ou falha em prever abusos de funcionalidades, resultando em riscos evitáveis devido à ausência de modelagem de ameaças ou validações antecipadas."
    },
    "security_misconfiguration": {
        "tipo": "Security Misconfiguration",
        "cwe": "CWE-933",
        "wstg_id": "WSTG-CONF-01",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Configuration_and_Deployment_Management_Testing/01-Testing_for_Misconfiguration",
        "owasp_url": "https://owasp.org/www-community/attacks/Misconfiguration",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Guidelines.html",
        "descricao": "O ambiente de execução da aplicação está configurado de forma insegura, expondo interfaces de administração, mensagens de erro detalhadas ou módulos desnecessários."
    },
    "vulnerable_and_outdated_components": {
        "tipo": "Vulnerable and Outdated Components",
        "cwe": "CWE-1104",
        "wstg_id": "WSTG-CONF-06",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Configuration_and_Deployment_Management_Testing/06-Testing_for_Vulnerable_Components",
        "owasp_url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
        "descricao": "A aplicação utiliza bibliotecas, dependências ou frameworks desatualizados, que contêm vulnerabilidades conhecidas e passíveis de exploração."
    },
    "identification_and_authentication_failures": {
        "tipo": "Identification and Authentication Failures",
        "cwe": "CWE-287",
        "wstg_id": "WSTG-ATHN-01",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Authentication_Testing/01-Testing_for_Credentials_Transported_in_Cleartext",
        "owasp_url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "descricao": "A aplicação não implementa corretamente controles de autenticação, permitindo acesso não autorizado, reutilização de sessões, ou transporte inseguro de credenciais."
    },
    "software_and_data_integrity_failures": {
        "tipo": "Software and Data Integrity Failures",
        "cwe": "CWE-494",
        "wstg_id": "WSTG-CONF-05",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Configuration_and_Deployment_Management_Testing/05-Testing_for_File_Integrity",
        "owasp_url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Software_Integrity_Cheat_Sheet.html",
        "descricao": "A aplicação executa atualizações, bibliotecas ou plugins não verificados, expondo o ambiente à manipulação maliciosa ou injeção de código durante o ciclo de vida."
    },
    "security_logging_and_monitoring_failures": {
        "tipo": "Security Logging and Monitoring Failures",
        "cwe": "CWE-778",
        "wstg_id": "WSTG-LOGN-01",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Testing_for_Error_Handling/01-Testing_for_Error_Handling",
        "owasp_url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
        "descricao": "A ausência ou a má configuração de mecanismos de registro e monitoramento dificulta a detecção e resposta a atividades maliciosas ou incidentes de segurança."
    },
    "server_side_request_forgery": {
        "tipo": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "wstg_id": "WSTG-INPV-09",
        "wstg_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_SSRF",
        "owasp_url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
        "cheatsheet_url": "https://cheatsheetseries.owasp.org/cheatsheets/SSRF_Prevention_Cheat_Sheet.html",
        "descricao": "A aplicação permite que requisições sejam feitas para destinos internos ou externos sem validação adequada, possibilitando escaneamento interno ou exfiltração de dados via SSRF."
    }
}

# Gravar os arquivos JSON
for key, data in owasp_top_10.items():
    filename = cache_dir / f"{key}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

cache_dir.exists(), len(os.listdir(cache_dir))
