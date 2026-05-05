# SentinelYara 🛡️

O **SentinelYara** é um motor avançado de caça a malwares (Scanner Estático) baseado em Python e YARA. Desenvolvido para atuar na defesa cibernética, ele permite varrer arquivos em massa com altíssima velocidade, monitorar diretórios em tempo real, isolar ameaças automaticamente e gerar relatórios de auditoria.

## 🌟 Funcionalidades Premium
* **Escudo Ativo (Monitoramento em Tempo Real):** Vigia diretórios continuamente, interceptando e neutralizando malwares no exato momento em que são criados ou baixados no disco.
* **Motor Turbo (Multithreading):** Utiliza todos os núcleos do processador para escanear dezenas de arquivos simultaneamente, reduzindo drasticamente o tempo de varredura.
* **Motor Multi-Regras:** Capacidade de carregar e compilar dinamicamente uma pasta inteira de regras `.yar`.
* **Ação Defensiva (Quarentena):** Move automaticamente arquivos maliciosos detectados para uma zona segura e isolada, quebrando o ciclo de infecção.
* **Geração de Relatórios:** Exportação dos resultados da varredura para um arquivo `JSON`, incluindo o Hash SHA256 das ameaças para fácil integração com ferramentas de *Blue Team*.
* **Interface Visual:** Saída colorida no terminal e barras de progresso dinâmicas para rápida triagem visual.

## 🚀 Como instalar

1. Clone este repositório:
\`\`\`bash
git clone https://github.com/SEU_USUARIO/SentinelYara.git
cd SentinelYara
\`\`\`

2. Instale as dependências:
\`\`\`bash
pip install -r requirements.txt
\`\`\`
*(Nota para usuários de Windows: Caso ocorra erro na compilação do `yara-python`, instale o "Microsoft C++ Build Tools" primeiro).*

## 🎯 Como usar (CLI)

O SentinelYara é operado via linha de comando.

**Parâmetros Básicos:**
* `-r` ou `--rules` (Obrigatório): Caminho para o arquivo `.yar` ou pasta contendo as regras.
* `-t` ou `--target` (Obrigatório): Arquivo ou diretório alvo da varredura/monitoramento.

**Modificadores Avançados:**
* `-w` ou `--watch`: Liga o **Escudo Ativo**, mantendo o script em execução contínua para vigiar a pasta alvo.
* `-q` ou `--quarantine`: Habilita a movimentação de ameaças para a pasta `Quarentena`.
* `--report`: Gera um arquivo `relatorio_sentinel.json` ao final de varreduras padrão.

**Exemplo 1 - Escudo Ativo com Quarentena Automática:**
\`\`\`bash
python sorcerer.py -r rules.yar -t . -w -q
\`\`\`

**Exemplo 2 - Varredura Turbo com Relatório:**
\`\`\`bash
python sorcerer.py -r rules.yar -t . --quarantine --report
\`\`\`

## 📦 Compilando para Executável (.exe)
Para rodar o SentinelYara em máquinas sem Python instalado, você pode empacotá-lo:
\`\`\`bash
pyinstaller --onefile sorcerer.py
\`\`\`
O executável final será gerado dentro da pasta `dist/`.