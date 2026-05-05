<div align="center">
  <h1>🛡️ SentinelYara NGAV</h1>
  <p><b>Next-Generation Anti-Virus Engine powered by Python & YARA</b></p>

  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/YARA-4.3+-red.svg" alt="YARA Version">
  <img src="https://img.shields.io/badge/Architecture-Multithreaded-orange.svg" alt="Architecture">
  <img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status">
</div>

<br>

O **SentinelYara** é um motor avançado de caça a ameaças (*Threat Hunting*) e varredura estática. Desenvolvido para equipes de *Blue Team* e resposta a incidentes, ele combina o poder de detecção de assinaturas do YARA com o processamento assíncrono do Python, criando uma barreira de defesa robusta e de alta velocidade.

---

## ⚡ Core Features

* **🛡️ Escudo Ativo (Real-Time Watchdog):** Monitoramento contínuo de diretórios em tempo real. Intercepta e analisa eventos de I/O (criação/modificação) no nível do sistema operacional.
* **🚀 Motor Multithread Turbo:** Utiliza `concurrent.futures` para distribuir a carga de varredura por todos os núcleos disponíveis do processador, processando múltiplos arquivos simultaneamente.
* **🔒 Isolamento Automático (Quarentena):** Ação de resposta a incidentes automatizada. Arquivos maliciosos são imediatamente movidos para um diretório seguro, quebrando a cadeia de execução (*kill chain*).
* **📊 Auditoria e Relatórios:** Geração de *logs* em formato JSON contendo *Hashes* SHA256 criptográficos e regras acionadas, facilitando a ingestão de dados em sistemas SIEM.

---

## ⚙️ Pré-requisitos e Instalação

Certifique-se de ter o Python 3.8 ou superior instalado.

```bash
# 1. Clone o repositório
git clone [https://github.com/SEU_USUARIO/SentinelYara.git](https://github.com/SEU_USUARIO/SentinelYara.git)
cd SentinelYara

# 2. Instale as dependências requeridas
pip install -r requirements.txt
